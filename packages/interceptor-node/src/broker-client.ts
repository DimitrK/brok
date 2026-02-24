/**
 * Broker client for executing requests through the broker.
 *
 * This module handles the communication protocol with the broker's /execute endpoint.
 * The same protocol will be used by the eBPF implementation.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as https from 'node:https';
import * as http from 'node:http';
import {randomUUID} from 'node:crypto';

import {
  OpenApiErrorSchema,
  OpenApiExecuteRequestSchema,
  OpenApiExecuteResponseApprovalRequiredSchema,
  OpenApiExecuteResponseExecutedSchema
} from '@broker-interceptor/schemas/dist/generated/schemas.js';

import type {
  ExecuteRequest,
  ExecuteResponseApprovalRequired,
  ExecuteResponseExecuted,
  Logger,
  ParsedManifest,
  ResolvedInterceptorConfig,
  SessionTokenProvider
} from './types.js';

/** Headers that should not be forwarded to upstream */
const BLOCKED_HEADERS = new Set(['host', 'connection', 'content-length']);

/**
 * Options for an execute request.
 */
export interface ExecuteOptions {
  integrationId: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body?: Buffer;
  requestId?: string;
  idempotencyKey?: string;
}

/**
 * Result of executing a request through the broker.
 */
export type ExecuteResult =
  | {ok: true; response: ExecuteResponseExecuted}
  | {ok: false; error: string; approvalRequired?: ExecuteResponseApprovalRequired; denied?: {reason: string; correlationId: string}};

/**
 * Convert headers object to array format expected by broker.
 * Uses explicit iteration to avoid object injection vulnerabilities.
 */
function headersToArray(headers: Record<string, string | string[] | undefined>): Array<{name: string; value: string}> {
  const result: Array<{name: string; value: string}> = [];

  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;

    // Skip headers that shouldn't be forwarded
    if (BLOCKED_HEADERS.has(name.toLowerCase())) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const v of value) {
        result.push({name, value: v});
      }
    } else {
      result.push({name, value});
    }
  }

  return result;
}

/**
 * Make a raw HTTPS request to the broker.
 */
async function rawBrokerRequest(
  url: string,
  options: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    mtlsCert?: Buffer;
    mtlsKey?: Buffer;
    mtlsCa?: Buffer;
  }
): Promise<{status: number; body: string}> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    const requestOptions: https.RequestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method,
      headers: options.headers
    };

    // Add mTLS options
    if (isHttps && options.mtlsCert && options.mtlsKey) {
      requestOptions.cert = options.mtlsCert;
      requestOptions.key = options.mtlsKey;
      if (options.mtlsCa) {
        requestOptions.ca = options.mtlsCa;
      }
    }

    const req = transport.request(requestOptions, res => {
      let body = '';
      res.on('data', (chunk: Buffer) => {
        body += chunk.toString();
      });
      res.on('end', () => {
        resolve({status: res.statusCode || 0, body});
      });
    });

    req.on('error', err => {
      reject(err);
    });

    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Safely read a file, validating that the path is absolute.
 * This prevents path traversal attacks when config comes from untrusted sources.
 */
function safeReadFile(filePath: string): Buffer {
  // Validate path is absolute to prevent traversal
  const normalizedPath = path.normalize(filePath);
  if (!path.isAbsolute(normalizedPath)) {
    throw new Error(`File path must be absolute: ${filePath}`);
  }
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  return fs.readFileSync(normalizedPath);
}

/**
 * Load mTLS credentials from file paths.
 * Paths are validated to be absolute before reading.
 */
function loadMtlsCredentials(config: ResolvedInterceptorConfig): {
  cert?: Buffer;
  key?: Buffer;
  ca?: Buffer;
} {
  const result: {cert?: Buffer; key?: Buffer; ca?: Buffer} = {};

  if (config.mtlsCertPath) {
    result.cert = safeReadFile(config.mtlsCertPath);
  }
  if (config.mtlsKeyPath) {
    result.key = safeReadFile(config.mtlsKeyPath);
  }
  if (config.mtlsCaPath) {
    result.ca = safeReadFile(config.mtlsCaPath);
  }

  return result;
}

/**
 * Execute a request through the broker.
 * If sessionTokenProvider is given and config.sessionToken is not set,
 * it will be used to get a fresh token.
 */
export async function executeRequest(
  options: ExecuteOptions,
  manifest: ParsedManifest,
  config: ResolvedInterceptorConfig,
  logger: Logger,
  sessionTokenProvider?: SessionTokenProvider,
  requestImpl: typeof rawBrokerRequest = rawBrokerRequest
): Promise<ExecuteResult> {
  let mtls: {cert?: Buffer; key?: Buffer; ca?: Buffer};
  try {
    mtls = loadMtlsCredentials(config);
  } catch (err) {
    return {
      ok: false,
      error: `Failed to load mTLS credentials: ${err instanceof Error ? err.message : String(err)}`
    };
  }
  const executeUrl = manifest.broker_execute_url;

  // Get session token - either from config or from provider
  let sessionToken = config.sessionToken;
  if (!sessionToken && sessionTokenProvider) {
    try {
      sessionToken = await sessionTokenProvider.getToken();
    } catch (err) {
      return {ok: false, error: `Failed to get session token: ${err instanceof Error ? err.message : String(err)}`};
    }
  }
  if (!sessionToken) {
    return {ok: false, error: 'No session token available for execute'};
  }

  // Build the execute request payload
  const payload: ExecuteRequest = {
    integration_id: options.integrationId,
    request: {
      method: options.method,
      url: options.url,
      headers: headersToArray(options.headers),
      body_base64: options.body ? options.body.toString('base64') : undefined
    },
    client_context: {
      request_id: options.requestId || randomUUID(),
      idempotency_key: options.idempotencyKey,
      source: 'interceptor-node'
    }
  };
  const parsedPayload = OpenApiExecuteRequestSchema.safeParse(payload);
  if (!parsedPayload.success) {
    return {ok: false, error: `Execute request failed schema validation: ${parsedPayload.error.message}`};
  }

  logger.debug(`Executing request to ${options.url} via broker`);

  try {
    const response = await requestImpl(executeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionToken}`
      },
      body: JSON.stringify(payload),
      mtlsCert: mtls.cert,
      mtlsKey: mtls.key,
      mtlsCa: mtls.ca
    });

    if (response.status === 200) {
      let parsedBody: unknown;
      try {
        parsedBody = JSON.parse(response.body);
      } catch {
        return {ok: false, error: 'Broker returned invalid JSON for execute success response'};
      }

      const executeResponse = OpenApiExecuteResponseExecutedSchema.safeParse(parsedBody);
      if (!executeResponse.success) {
        return {ok: false, error: `Broker execute success response failed schema validation: ${executeResponse.error.message}`};
      }

      logger.debug(`Request executed successfully, correlation_id: ${executeResponse.data.correlation_id}`);
      return {ok: true, response: executeResponse.data};
    }

    if (response.status === 202) {
      let parsedBody: unknown;
      try {
        parsedBody = JSON.parse(response.body);
      } catch {
        return {ok: false, error: 'Broker returned invalid JSON for approval-required response'};
      }

      const approvalResponse = OpenApiExecuteResponseApprovalRequiredSchema.safeParse(parsedBody);
      if (!approvalResponse.success) {
        return {ok: false, error: `Broker approval-required response failed schema validation: ${approvalResponse.error.message}`};
      }

      logger.warn(
        `Request requires approval: ${approvalResponse.data.approval_id} ` +
          `(${approvalResponse.data.summary.risk_tier} risk, action: ${approvalResponse.data.summary.action_group})`
      );
      return {
        ok: false,
        error: `Approval required: ${approvalResponse.data.approval_id}`,
        approvalRequired: approvalResponse.data
      };
    }

    // Handle error responses
    let parsedErrorBody: unknown;
    try {
      parsedErrorBody = JSON.parse(response.body);
    } catch {
      if (response.status === 401) {
        return {ok: false, error: 'Authentication failed: HTTP 401'};
      }
      if (response.status === 429) {
        return {ok: false, error: 'Rate limited by broker'};
      }
      return {ok: false, error: `Broker request failed: HTTP ${response.status}`};
    }

    const parsedError = OpenApiErrorSchema.safeParse(parsedErrorBody);
    if (!parsedError.success) {
      return {ok: false, error: `Broker request failed: HTTP ${response.status}`};
    }

    if (response.status === 401) {
      return {ok: false, error: `Authentication failed: ${parsedError.data.message}`};
    }

    if (response.status === 429) {
      return {ok: false, error: 'Rate limited by broker'};
    }

    const errorCode = parsedError.data.error.toLowerCase();
    const isPolicyDenied =
      response.status === 403 ||
      errorCode.includes('deny') ||
      errorCode.includes('policy') ||
      errorCode.includes('approval');

    if (isPolicyDenied) {
      return {
        ok: false,
        error: `Request denied: ${parsedError.data.message}`,
        denied: {
          reason: parsedError.data.message,
          correlationId: parsedError.data.correlation_id
        }
      };
    }

    return {ok: false, error: `Broker returned ${parsedError.data.error}: ${parsedError.data.message}`};
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Broker request error: ${message}`);
    return {ok: false, error: `Broker request error: ${message}`};
  }
}

/**
 * Custom error class for approval-required responses.
 */
export class ApprovalRequiredError extends Error {
  constructor(
    public readonly approvalId: string,
    public readonly expiresAt: string,
    public readonly summary: ExecuteResponseApprovalRequired['summary']
  ) {
    super(`Approval required: ${approvalId} (${summary.action_group}, ${summary.risk_tier} risk)`);
    this.name = 'ApprovalRequiredError';
  }
}

/**
 * Custom error class for denied responses.
 */
export class RequestDeniedError extends Error {
  constructor(
    public readonly reason: string,
    public readonly correlationId: string
  ) {
    super(`Request denied: ${reason}`);
    this.name = 'RequestDeniedError';
  }
}

export class ManifestUnavailableError extends Error {
  constructor(public readonly reason: string) {
    super(`Manifest unavailable: ${reason}`);
    this.name = 'ManifestUnavailableError';
  }
}
