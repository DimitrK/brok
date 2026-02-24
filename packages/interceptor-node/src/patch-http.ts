/**
 * HTTP/HTTPS module patching for request interception.
 *
 * This module patches Node's http and https modules to intercept outgoing
 * requests and route them through the broker when they match the manifest rules.
 *
 * Key insight: We intercept BEFORE TLS encryption, so we see plaintext
 * and don't need to MITM or inject custom CAs.
 *
 * Note: Module patching in Node requires careful handling due to TypeScript
 * readonly modifiers. We use Object.defineProperty to override.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import {createRequire, syncBuiltinESMExports} from 'node:module';
import * as net from 'node:net';
import {PassThrough} from 'node:stream';

import {matchUrl} from './matcher.js';
import {executeRequest, ApprovalRequiredError, ManifestUnavailableError, RequestDeniedError} from './broker-client.js';
import type {InterceptorState, ExecuteResponseExecuted, ParsedManifest} from './types.js';

const require = createRequire(import.meta.url);
const mutableHttp = require('node:http') as typeof import('node:http');
const mutableHttps = require('node:https') as typeof import('node:https');

// Store original implementations
let originalHttpRequest: typeof http.request | null = null;
let originalHttpsRequest: typeof https.request | null = null;
let originalHttpGet: typeof http.get | null = null;
let originalHttpsGet: typeof https.get | null = null;

// Global state reference (set during initialization)
let interceptorState: InterceptorState | null = null;

function normalizeExecuteMethod(method: string | undefined): 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | null {
  const normalized = (method ?? 'GET').toUpperCase();
  switch (normalized) {
    case 'GET':
    case 'POST':
    case 'PUT':
    case 'PATCH':
    case 'DELETE':
      return normalized;
    default:
      return null;
  }
}

function resolveManifestForInterception(
  state: InterceptorState
): {mode: 'use'; manifest: ParsedManifest} | {mode: 'passthrough'} | {mode: 'block'; reason: string} {
  const manifest = state.manifest;
  if (!manifest) {
    if (state.config.manifestFailurePolicy === 'fail_open') {
      return {mode: 'passthrough'};
    }
    return {mode: 'block', reason: 'no verified manifest is available'};
  }

  const manifestExpired = new Date(manifest.expires_at).getTime() <= Date.now();
  if (manifestExpired && state.config.manifestFailurePolicy !== 'fail_open') {
    return {mode: 'block', reason: 'last verified manifest is expired'};
  }
  if (manifestExpired) {
    return {mode: 'passthrough'};
  }

  return {mode: 'use', manifest};
}

function normalizedPort(url: URL): string {
  if (url.port) {
    return url.port;
  }
  if (url.protocol === 'https:') {
    return '443';
  }
  if (url.protocol === 'http:') {
    return '80';
  }
  return '';
}

function isBrokerOriginRequest(url: URL, brokerUrl: string): boolean {
  try {
    const broker = new URL(brokerUrl);
    return (
      url.protocol === broker.protocol &&
      url.hostname === broker.hostname &&
      normalizedPort(url) === normalizedPort(broker)
    );
  } catch {
    return false;
  }
}

/**
 * Check if patching has been applied.
 */
export function isPatched(): boolean {
  return originalHttpRequest !== null;
}

function createSyntheticClientRequest(): http.ClientRequest {
  const request = new PassThrough() as unknown as http.ClientRequest;

  request.abort = () => request;
  request.destroy = () => request;
  request.setNoDelay = () => request;
  request.setSocketKeepAlive = () => request;
  request.setTimeout = (() => request) as http.ClientRequest['setTimeout'];
  request.flushHeaders = () => {};
  request.setHeader = (() => request) as http.ClientRequest['setHeader'];
  request.removeHeader = (() => request) as http.ClientRequest['removeHeader'];
  request.getHeader = () => undefined;
  request.getHeaderNames = () => [];
  request.getHeaders = () => ({});
  request.hasHeader = () => false;

  return request;
}

/**
 * Create a fake response from broker execute result.
 */
function createFakeResponse(executeResponse: ExecuteResponseExecuted): http.IncomingMessage {
  const upstream = executeResponse.upstream;

  // Create a readable stream for the body
  const bodyBuffer = Buffer.from(upstream.body_base64, 'base64');
  const bodyStream = new PassThrough();

  // Create a real socket for IncomingMessage constructor (required by Node's type)
  const fakeSocket = new net.Socket();

  // Create fake IncomingMessage
  const response = new http.IncomingMessage(fakeSocket);

  response.statusCode = upstream.status_code;
  response.statusMessage = http.STATUS_CODES[upstream.status_code] || '';

  // Set headers using a Map to avoid object injection
  const headersMap = new Map<string, string | string[]>();
  for (const {name, value} of upstream.headers) {
    const lowerName = name.toLowerCase();
    const existing = headersMap.get(lowerName);
    if (existing !== undefined) {
      if (Array.isArray(existing)) {
        existing.push(value);
      } else {
        headersMap.set(lowerName, [existing, value]);
      }
    } else {
      headersMap.set(lowerName, value);
    }
  }

  // Apply headers to response - key is from Map entries, validated as lowercase header name
  for (const [key, val] of headersMap) {
    // eslint-disable-next-line security/detect-object-injection
    response.headers[key] = val;
  }

  // Schedule body data delivery
  setImmediate(() => {
    bodyStream.push(bodyBuffer);
    bodyStream.push(null);

    // Forward events from bodyStream to response
    bodyStream.on('data', (chunk: Buffer) => response.emit('data', chunk));
    bodyStream.on('end', () => response.emit('end'));
  });

  return response;
}

/**
 * Normalize headers from various Node.js formats to a simple record.
 * Handles OutgoingHttpHeaders and raw header arrays.
 */
function normalizeHeaders(
  headers: http.OutgoingHttpHeaders | readonly string[] | undefined
): Record<string, string | string[] | undefined> {
  if (!headers) return {};

  // Handle raw string array format [key1, val1, key2, val2, ...]
  if (Array.isArray(headers)) {
    const result: Record<string, string | string[] | undefined> = {};
    for (let i = 0; i < headers.length; i += 2) {
      // Access array by computed index - safe because we're iterating within bounds
      // eslint-disable-next-line security/detect-object-injection
      const key = headers[i] as string;
      const value = headers[i + 1] as string;
      // eslint-disable-next-line security/detect-object-injection
      result[key] = value;
    }
    return result;
  }

  const result: Record<string, string | string[] | undefined> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    // Convert numbers to strings (e.g., content-length)
    if (typeof value === 'number') {
      // eslint-disable-next-line security/detect-object-injection
      result[key] = String(value);
    } else {
      // eslint-disable-next-line security/detect-object-injection
      result[key] = value;
    }
  }
  return result;
}

/**
 * Create an intercepted ClientRequest that buffers the body and forwards to broker.
 */
function createInterceptedRequest(
  targetUrl: URL,
  integrationId: string,
  manifest: ParsedManifest,
  options: http.RequestOptions | https.RequestOptions,
  callback?: (res: http.IncomingMessage) => void
): http.ClientRequest {
  const state = interceptorState!;
  const logger = state.logger;

  const chunks: Buffer[] = [];

  // Create an in-memory request object to avoid unintended network side effects.
  const request = createSyntheticClientRequest();

  // Override write to buffer body
  request.write = function (
    chunk: string | Buffer,
    encodingOrCallback?: BufferEncoding | ((error?: Error) => void),
    cb?: (error?: Error) => void
  ): boolean {
    const encoding = typeof encodingOrCallback === 'string' ? encodingOrCallback : 'utf8';
    const finalCb = typeof encodingOrCallback === 'function' ? encodingOrCallback : cb;

    if (typeof chunk === 'string') {
      chunks.push(Buffer.from(chunk, encoding));
    } else {
      chunks.push(chunk);
    }

    if (finalCb) {
      setImmediate(finalCb);
    }

    return true;
  };

  // Override end to trigger the actual request to broker
  request.end = function (
    chunkOrCallback?: string | Buffer | (() => void),
    encodingOrCallback?: BufferEncoding | (() => void),
    cb?: () => void
  ): typeof request {
    // Handle the final chunk if provided
    if (chunkOrCallback && typeof chunkOrCallback !== 'function') {
      const encoding = typeof encodingOrCallback === 'string' ? encodingOrCallback : 'utf8';
      if (typeof chunkOrCallback === 'string') {
        chunks.push(Buffer.from(chunkOrCallback, encoding));
      } else {
        chunks.push(chunkOrCallback);
      }
    }

    const finalCallback =
      typeof chunkOrCallback === 'function'
        ? chunkOrCallback
        : typeof encodingOrCallback === 'function'
          ? encodingOrCallback
          : cb;

    // Execute the request through broker
    const body = Buffer.concat(chunks);
    const headers = normalizeHeaders(options.headers);

    // Determine method
    const method = normalizeExecuteMethod(options.method);
    if (!method) {
      request.emit('error', new Error(`Unsupported HTTP method for interception: ${options.method ?? 'unknown'}`));
      if (finalCallback) {
        finalCallback();
      }
      return request;
    }

    logger.debug(`Intercepting ${method} ${targetUrl.href}`);

    executeRequest(
      {
        integrationId,
        method,
        url: targetUrl.href,
        headers,
        body: body.length > 0 ? body : undefined
      },
      manifest,
      state.config,
      logger,
      state.sessionManager ?? undefined
    )
      .then(result => {
        if (result.ok) {
          // Create fake response and emit
          const fakeResponse = createFakeResponse(result.response);

          if (callback) {
            callback(fakeResponse);
          }

          request.emit('response', fakeResponse);
        } else if (result.approvalRequired) {
          const err = new ApprovalRequiredError(
            result.approvalRequired.approval_id,
            result.approvalRequired.expires_at,
            result.approvalRequired.summary
          );
          request.emit('error', err);
        } else if (result.denied) {
          const err = new RequestDeniedError(result.denied.reason, result.denied.correlationId);
          request.emit('error', err);
        } else {
          request.emit('error', new Error(result.error));
        }

        if (finalCallback) {
          finalCallback();
        }
      })
      .catch((err: unknown) => {
        request.emit('error', err);
        if (finalCallback) {
          finalCallback();
        }
      });

    return request;
  };

  return request;
}

function createBlockedRequest(reason: string): http.ClientRequest {
  const request = createSyntheticClientRequest();
  request.write = function (
    _chunk: string | Buffer,
    encodingOrCallback?: BufferEncoding | ((error?: Error) => void),
    cb?: (error?: Error) => void
  ): boolean {
    const finalCb = typeof encodingOrCallback === 'function' ? encodingOrCallback : cb;
    if (finalCb) {
      setImmediate(finalCb);
    }
    return true;
  };
  request.end = function (
    chunkOrCallback?: string | Buffer | (() => void),
    encodingOrCallback?: BufferEncoding | (() => void),
    cb?: () => void
  ): typeof request {
    const finalCallback =
      typeof chunkOrCallback === 'function'
        ? chunkOrCallback
        : typeof encodingOrCallback === 'function'
          ? encodingOrCallback
          : cb;
    if (finalCallback) {
      setImmediate(finalCallback);
    }
    setImmediate(() => {
      request.emit('error', new ManifestUnavailableError(reason));
    });
    return request;
  };
  return request;
}

/**
 * Create a patched request function.
 */
function createPatchedRequest(
  originalFn: typeof http.request | typeof https.request,
  defaultScheme: 'http' | 'https'
): typeof http.request {
  return function patchedRequest(
    urlOrOptions: string | URL | http.RequestOptions | https.RequestOptions,
    optionsOrCallback?: http.RequestOptions | https.RequestOptions | ((res: http.IncomingMessage) => void),
    maybeCallback?: (res: http.IncomingMessage) => void
  ): http.ClientRequest {
    // Parse arguments (Node's request() has complex overloading)
    let url: URL;
    let options: http.RequestOptions | https.RequestOptions;
    let callback: ((res: http.IncomingMessage) => void) | undefined;

    if (typeof urlOrOptions === 'string') {
      url = new URL(urlOrOptions);
      options = typeof optionsOrCallback === 'object' ? optionsOrCallback : {};
      callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
    } else if (urlOrOptions instanceof URL) {
      url = urlOrOptions;
      options = typeof optionsOrCallback === 'object' ? optionsOrCallback : {};
      callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
    } else {
      // Options object
      options = urlOrOptions;
      const scheme = (options as https.RequestOptions).protocol?.replace(':', '') || defaultScheme;
      const host = options.hostname || options.host || 'localhost';
      const port = options.port ? `:${options.port}` : '';
      const pathPart = options.path || '/';
      url = new URL(`${scheme}://${host}${port}${pathPart}`);
      callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
    }

    // Check if we should intercept this request
    const state = interceptorState;
    if (!state || !state.initialized) {
      // Not initialized, pass through
      return originalFn.call(null, urlOrOptions as string, optionsOrCallback as http.RequestOptions, maybeCallback);
    }

    if (isBrokerOriginRequest(url, state.config.brokerUrl)) {
      state.logger.debug(`Skipping interception for broker-origin request: ${url.href}`);
      return originalFn.call(null, urlOrOptions as string, optionsOrCallback as http.RequestOptions, maybeCallback);
    }

    const manifestDecision = resolveManifestForInterception(state);
    if (manifestDecision.mode === 'passthrough') {
      return originalFn.call(null, urlOrOptions as string, optionsOrCallback as http.RequestOptions, maybeCallback);
    }

    if (manifestDecision.mode === 'block') {
      state.logger.warn(`Blocking request because manifest is unavailable: ${manifestDecision.reason}`);
      return createBlockedRequest(manifestDecision.reason);
    }

    const matchResult = matchUrl(url, manifestDecision.manifest);
    if (!matchResult.matched) {
      // No match, pass through to original
      if (matchResult.details && matchResult.details.length > 0) {
        state.logger.debug(`Not intercepting: ${url.href} - no matching rules:`);
        for (const detail of matchResult.details) {
          state.logger.debug(`  Rule ${detail.ruleIndex} (${detail.integrationId}): ${detail.mismatches.join('; ')}`);
        }
      } else {
        state.logger.debug(`Not intercepting: ${url.href} (no rules in manifest)`);
      }
      return originalFn.call(null, urlOrOptions as string, optionsOrCallback as http.RequestOptions, maybeCallback);
    }

    // Intercept this request
    state.logger.debug(`Intercepting: ${url.href} (integration: ${matchResult.integrationId})`);
    return createInterceptedRequest(url, matchResult.integrationId, manifestDecision.manifest, options, callback);
  };
}

/**
 * Apply patches to http and https modules.
 * Uses Object.defineProperty to override readonly module exports.
 */
export function applyPatches(state: InterceptorState): void {
  if (isPatched()) {
    state.logger.warn('HTTP patches already applied, skipping');
    return;
  }

  interceptorState = state;

  // Store originals
  originalHttpRequest = mutableHttp.request;
  originalHttpsRequest = mutableHttps.request;
  originalHttpGet = mutableHttp.get;
  originalHttpsGet = mutableHttps.get;

  // Apply patches using Object.defineProperty to handle readonly
  const patchedHttpRequest = createPatchedRequest(originalHttpRequest, 'http');
  const patchedHttpsRequest = createPatchedRequest(originalHttpsRequest, 'https');

  // Helper to safely define property with fallback
  const safeDefineProperty = (target: object, prop: string, value: unknown, moduleName: string): boolean => {
    try {
      Object.defineProperty(target, prop, {
        value,
        writable: true,
        configurable: true
      });
      return true;
    } catch (err) {
      // Property might be non-configurable, try direct assignment as fallback
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, security/detect-object-injection
        (target as any)[prop] = value;
        return true;
      } catch {
        state.logger.warn(`Cannot patch ${moduleName}.${prop}: ${err instanceof Error ? err.message : String(err)}`);
        return false;
      }
    }
  };

  safeDefineProperty(mutableHttp, 'request', patchedHttpRequest, 'http');
  safeDefineProperty(mutableHttps, 'request', patchedHttpsRequest, 'https');

  // Patch get methods (they just call request with method and end())
  const patchedHttpGet = function (
    url: string | URL | http.RequestOptions,
    options?: http.RequestOptions | ((res: http.IncomingMessage) => void),
    callback?: (res: http.IncomingMessage) => void
  ) {
    // Determine actual callback - options might be the callback
    const actualCallback = typeof options === 'function' ? options : callback;
    const actualOptions = typeof options === 'function' ? undefined : options;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-call
    const req = (patchedHttpRequest as any)(url, actualOptions, actualCallback) as http.ClientRequest;
    req.end();
    return req;
  };

  const patchedHttpsGet = function (
    url: string | URL | https.RequestOptions,
    options?: https.RequestOptions | ((res: http.IncomingMessage) => void),
    callback?: (res: http.IncomingMessage) => void
  ) {
    // Determine actual callback - options might be the callback
    const actualCallback = typeof options === 'function' ? options : callback;
    const actualOptions = typeof options === 'function' ? undefined : options;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-call
    const req = (patchedHttpsRequest as any)(url, actualOptions, actualCallback) as http.ClientRequest;
    req.end();
    return req;
  };

  safeDefineProperty(mutableHttp, 'get', patchedHttpGet, 'http');
  safeDefineProperty(mutableHttps, 'get', patchedHttpsGet, 'https');
  syncBuiltinESMExports();

  state.logger.info('HTTP/HTTPS module patches applied');
}

/**
 * Remove patches and restore original functions.
 */
export function removePatches(): void {
  if (!isPatched()) {
    return;
  }

  // Helper to safely restore property
  const safeRestoreProperty = (target: object, prop: string, value: unknown): void => {
    try {
      Object.defineProperty(target, prop, {
        value,
        writable: true,
        configurable: true
      });
    } catch {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, security/detect-object-injection
        (target as any)[prop] = value;
      } catch {
        // Ignore - we can't restore
      }
    }
  };

  if (originalHttpRequest) {
    safeRestoreProperty(mutableHttp, 'request', originalHttpRequest);
  }
  if (originalHttpsRequest) {
    safeRestoreProperty(mutableHttps, 'request', originalHttpsRequest);
  }
  if (originalHttpGet) {
    safeRestoreProperty(mutableHttp, 'get', originalHttpGet);
  }
  if (originalHttpsGet) {
    safeRestoreProperty(mutableHttps, 'get', originalHttpsGet);
  }
  syncBuiltinESMExports();

  originalHttpRequest = null;
  originalHttpsRequest = null;
  originalHttpGet = null;
  originalHttpsGet = null;
  interceptorState = null;
}

/**
 * Update the state (called when manifest is refreshed).
 */
export function updateState(state: InterceptorState): void {
  interceptorState = state;
}
