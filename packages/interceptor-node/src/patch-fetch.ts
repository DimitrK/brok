/**
 * Fetch API patching for request interception.
 *
 * This module patches the global fetch() function (available in Node 18+)
 * to intercept outgoing requests and route them through the broker.
 */

import {matchUrl} from './matcher.js';
import {executeRequest, ApprovalRequiredError, RequestDeniedError} from './broker-client.js';
import type {InterceptorState} from './types.js';

// Store original fetch
let originalFetch: typeof globalThis.fetch | null = null;

// Global state reference
let interceptorState: InterceptorState | null = null;

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

/**
 * Patched fetch function.
 * Uses explicit type handling to avoid TypeScript issues with global types.
 */
async function patchedFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const state = interceptorState;

  // If not initialized or no manifest, pass through
  if (!state || !state.initialized || !state.manifest) {
    return originalFetch!(input, init);
  }

  // Parse the URL
  let url: URL;
  let method: string = init?.method || 'GET';
  let headers: Record<string, string | string[]> = {};
  let bodyBuffer: Buffer | undefined;

  if (typeof input === 'string') {
    url = new URL(input);
    headers = headersToObject(init?.headers as Headers | [string, string][] | Record<string, string> | undefined);
  } else if (input instanceof URL) {
    url = input;
    headers = headersToObject(init?.headers as Headers | [string, string][] | Record<string, string> | undefined);
  } else if (input instanceof Request) {
    url = new URL(input.url);
    method = input.method;
    headers = headersToObject(input.headers);
    if (input.body) {
      // Read the body - explicitly type the reader for proper chunk handling
      const reader = input.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
      const chunks: Uint8Array[] = [];
      let done = false;
      while (!done) {
        const readResult = await reader.read();
        if (readResult.value) {
          chunks.push(readResult.value);
        }
        done = readResult.done;
      }
      bodyBuffer = Buffer.concat(chunks);
    }
  } else {
    // Unknown input type, pass through
    return originalFetch!(input as string, init);
  }

  // Handle body from init
  if (!bodyBuffer && init?.body) {
    if (typeof init.body === 'string') {
      bodyBuffer = Buffer.from(init.body);
    } else if (init.body instanceof ArrayBuffer) {
      bodyBuffer = Buffer.from(init.body);
    } else if (init.body instanceof Uint8Array) {
      bodyBuffer = Buffer.from(init.body);
    } else if (init.body instanceof Blob) {
      bodyBuffer = Buffer.from(await init.body.arrayBuffer());
    } else if (init.body instanceof ReadableStream) {
      const reader = (init.body as ReadableStream<Uint8Array>).getReader();
      const chunks: Uint8Array[] = [];
      let done = false;
      while (!done) {
        const readResult = await reader.read();
        if (readResult.value) {
          chunks.push(readResult.value);
        }
        done = readResult.done;
      }
      bodyBuffer = Buffer.concat(chunks);
    }
  }

  // Check if we should intercept
  const matchResult = matchUrl(url, state.manifest);

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
  const normalizedMethod = method.toUpperCase() as 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

  // Execute through broker
  const executeResult = await executeRequest(
    {
      integrationId: matchResult.integrationId,
      method: normalizedMethod,
      url: url.href,
      headers: headers as Record<string, string | string[] | undefined>,
      body: bodyBuffer
    },
    state.manifest,
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
    throw new RequestDeniedError(executeResult.denied.reason, executeResult.denied.correlation_id);
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
