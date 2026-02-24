/**
 * Fetch API patching for request interception.
 *
 * This module patches the global fetch() function (available in Node 18+)
 * to intercept outgoing requests and route them through the broker.
 */

import {matchUrl} from './matcher.js';
import {executeRequest, ApprovalRequiredError, ManifestUnavailableError, RequestDeniedError} from './broker-client.js';
import type {InterceptorState} from './types.js';

// Store original fetch
let originalFetch: typeof globalThis.fetch | null = null;

// Global state reference
let interceptorState: InterceptorState | null = null;

function normalizeExecuteMethod(method: string): 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | null {
  const normalized = method.toUpperCase();
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
): {mode: 'use'} | {mode: 'passthrough'} | {mode: 'block'; reason: string} {
  if (!state.manifest) {
    if (state.config.manifestFailurePolicy === 'fail_open') {
      return {mode: 'passthrough'};
    }
    return {mode: 'block', reason: 'no verified manifest is available'};
  }

  const manifestExpired = new Date(state.manifest.expires_at).getTime() <= Date.now();
  if (manifestExpired && state.config.manifestFailurePolicy !== 'fail_open') {
    return {mode: 'block', reason: 'last verified manifest is expired'};
  }
  if (manifestExpired) {
    return {mode: 'passthrough'};
  }

  return {mode: 'use'};
}

/** HTTP status text lookup */
const HTTP_STATUS_TEXT = new Map<number, string>([
  [200, 'OK'],
  [201, 'Created'],
  [204, 'No Content'],
  [301, 'Moved Permanently'],
  [302, 'Found'],
  [304, 'Not Modified'],
  [400, 'Bad Request'],
  [401, 'Unauthorized'],
  [403, 'Forbidden'],
  [404, 'Not Found'],
  [405, 'Method Not Allowed'],
  [429, 'Too Many Requests'],
  [500, 'Internal Server Error'],
  [502, 'Bad Gateway'],
  [503, 'Service Unavailable']
]);

/**
 * Check if fetch patching has been applied.
 */
export function isFetchPatched(): boolean {
  return originalFetch !== null;
}

/**
 * Create a Response object from broker execute result.
 */
function createResponseFromBroker(upstream: {
  status_code: number;
  headers: Array<{name: string; value: string}>;
  body_base64: string;
}): Response {
  const body = Buffer.from(upstream.body_base64, 'base64');

  const headers = new Headers();
  for (const {name, value} of upstream.headers) {
    headers.append(name, value);
  }

  return new Response(body, {
    status: upstream.status_code,
    statusText: HTTP_STATUS_TEXT.get(upstream.status_code) || '',
    headers
  });
}

/**
 * Convert Headers to a plain object using safe iteration.
 */
function headersToObject(
  headers: Headers | [string, string][] | Record<string, string> | undefined
): Record<string, string | string[]> {
  const result = new Map<string, string | string[]>();

  if (!headers) {
    return Object.fromEntries(result);
  }

  if (headers instanceof Headers) {
    headers.forEach((value, key) => {
      const existing = result.get(key);
      if (existing !== undefined) {
        if (Array.isArray(existing)) {
          existing.push(value);
        } else {
          result.set(key, [existing, value]);
        }
      } else {
        result.set(key, value);
      }
    });
  } else if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      result.set(key, value);
    }
  } else {
    for (const [key, value] of Object.entries(headers)) {
      result.set(key, value);
    }
  }

  return Object.fromEntries(result);
}

function normalizeChunkToBuffer(chunk: unknown): Buffer {
  if (typeof chunk === 'string') {
    return Buffer.from(chunk);
  }

  if (chunk instanceof ArrayBuffer) {
    return Buffer.from(chunk);
  }

  if (ArrayBuffer.isView(chunk)) {
    return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }

  throw new Error('Unsupported async iterable body chunk type for interception');
}

async function bodyInitToBuffer(body: RequestInit['body'] | null | undefined): Promise<Buffer | undefined> {
  if (body === undefined || body === null) {
    return undefined;
  }

  if (typeof body === 'string') {
    return Buffer.from(body);
  }

  if (body instanceof URLSearchParams) {
    return Buffer.from(body.toString());
  }

  if (body instanceof Blob) {
    return Buffer.from(await body.arrayBuffer());
  }

  if (body instanceof ArrayBuffer) {
    return Buffer.from(body);
  }

  if (ArrayBuffer.isView(body)) {
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }

  if (body instanceof ReadableStream) {
    const reader = body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    const chunks: Uint8Array[] = [];
    let done = false;
    while (!done) {
      const readResult = await reader.read();
      if (readResult.value) {
        chunks.push(readResult.value);
      }
      done = readResult.done;
    }
    return chunks.length > 0 ? Buffer.concat(chunks) : undefined;
  }

  if (typeof body === 'object' && body !== null && Symbol.asyncIterator in body) {
    const chunks: Buffer[] = [];
    for await (const chunk of body as AsyncIterable<unknown>) {
      chunks.push(normalizeChunkToBuffer(chunk));
    }
    return chunks.length > 0 ? Buffer.concat(chunks) : undefined;
  }

  throw new Error('Unsupported request body type for interception');
}

async function requestBodyToBuffer(request: Request): Promise<Buffer | undefined> {
  if (!request.body) {
    return undefined;
  }

  const clonedRequest = request.clone();
  const body = Buffer.from(await clonedRequest.arrayBuffer());
  return body.length > 0 ? body : undefined;
}

/**
 * Patched fetch function.
 * Uses explicit type handling to avoid TypeScript issues with global types.
 */
async function patchedFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const state = interceptorState;

  // If not initialized, pass through
  if (!state || !state.initialized) {
    return originalFetch!(input, init);
  }

  const manifestDecision = resolveManifestForInterception(state);
  if (manifestDecision.mode === 'passthrough') {
    return originalFetch!(input, init);
  }
  if (manifestDecision.mode === 'block') {
    throw new ManifestUnavailableError(manifestDecision.reason);
  }

  // Parse the URL and request metadata without consuming any request body.
  let url: URL;
  let requestInput: Request | null = null;

  if (typeof input === 'string') {
    url = new URL(input);
  } else if (input instanceof URL) {
    url = input;
  } else if (input instanceof Request) {
    requestInput = input;
    url = new URL(input.url);
  } else {
    // Unknown input type, pass through
    return originalFetch!(input as string, init);
  }

  const method = init?.method ?? requestInput?.method ?? 'GET';
  const headers =
    init?.headers !== undefined
      ? headersToObject(init.headers as Headers | [string, string][] | Record<string, string>)
      : requestInput
        ? headersToObject(requestInput.headers)
        : {};

  // Check if we should intercept
  const manifest = state.manifest;
  if (!manifest) {
    throw new ManifestUnavailableError('no verified manifest is available');
  }

  const matchResult = matchUrl(url, manifest);

  if (!matchResult.matched) {
    if (matchResult.details && matchResult.details.length > 0) {
      state.logger.debug(`fetch: Not intercepting ${url.href} - no matching rules:`);
      for (const detail of matchResult.details) {
        state.logger.debug(`  Rule ${detail.ruleIndex} (${detail.integrationId}): ${detail.mismatches.join('; ')}`);
      }
    } else {
      state.logger.debug(`fetch: Not intercepting ${url.href} (no rules in manifest)`);
    }
    return originalFetch!(input, init);
  }

  state.logger.debug(`fetch: Intercepting ${method} ${url.href} (integration: ${matchResult.integrationId})`);

  // Convert method to expected format
  const normalizedMethod = normalizeExecuteMethod(method);
  if (!normalizedMethod) {
    throw new Error(`Unsupported HTTP method for interception: ${method}`);
  }

  const bodyBuffer =
    init?.body !== undefined ? await bodyInitToBuffer(init.body) : requestInput ? await requestBodyToBuffer(requestInput) : undefined;

  // Execute through broker
  const executeResult = await executeRequest(
    {
      integrationId: matchResult.integrationId,
      method: normalizedMethod,
      url: url.href,
      headers: headers as Record<string, string | string[] | undefined>,
      body: bodyBuffer
    },
    manifest,
    state.config,
    state.logger,
    state.sessionManager ?? undefined
  );

  if (executeResult.ok) {
    return createResponseFromBroker(executeResult.response.upstream);
  }

  if (executeResult.approvalRequired) {
    throw new ApprovalRequiredError(
      executeResult.approvalRequired.approval_id,
      executeResult.approvalRequired.expires_at,
      executeResult.approvalRequired.summary
    );
  }

  if (executeResult.denied) {
    throw new RequestDeniedError(executeResult.denied.reason, executeResult.denied.correlationId);
  }

  throw new Error(executeResult.error);
}

/**
 * Apply fetch patch.
 */
export function applyFetchPatch(state: InterceptorState): void {
  if (isFetchPatched()) {
    state.logger.warn('fetch already patched, skipping');
    return;
  }

  // Check if global fetch exists (Node 18+)
  if (typeof globalThis.fetch !== 'function') {
    state.logger.warn('global fetch not available, skipping fetch patch');
    return;
  }

  interceptorState = state;
  originalFetch = globalThis.fetch;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
  globalThis.fetch = patchedFetch as any;

  state.logger.info('fetch patch applied');
}

/**
 * Remove fetch patch.
 */
export function removeFetchPatch(): void {
  if (!isFetchPatched()) {
    return;
  }

  if (originalFetch) {
    globalThis.fetch = originalFetch;
  }

  originalFetch = null;
  interceptorState = null;
}

/**
 * Update state (called when manifest is refreshed).
 */
export function updateFetchState(state: InterceptorState): void {
  interceptorState = state;
}
