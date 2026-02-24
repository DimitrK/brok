import {afterEach, describe, expect, it, vi} from 'vitest';

vi.mock('../broker-client.js', async () => {
  const actual = await vi.importActual<typeof import('../broker-client.js')>('../broker-client.js');
  return {
    ...actual,
    executeRequest: vi.fn()
  };
});

import {ManifestUnavailableError, executeRequest} from '../broker-client.js';
import {applyFetchPatch, removeFetchPatch, updateFetchState} from '../patch-fetch.js';
import type {InterceptorState, ParsedManifest, ResolvedInterceptorConfig} from '../types.js';

function createManifest(overrides?: Partial<ParsedManifest>): ParsedManifest {
  return {
    manifest_version: 1,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    broker_execute_url: 'https://broker.example.com/v1/execute',
    match_rules: [
      {
        integration_id: 'int_openai',
        provider: 'openai',
        match: {
          hosts: ['api.openai.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/v1/*']
        },
        rewrite: {
          mode: 'execute',
          send_intended_url: true
        }
      }
    ],
    signature: {
      alg: 'EdDSA',
      kid: 'k1',
      jws: 'stub'
    },
    ...overrides
  };
}

function createConfig(overrides?: Partial<ResolvedInterceptorConfig>): ResolvedInterceptorConfig {
  return {
    brokerUrl: 'https://broker.example.com',
    workloadId: 'w_test',
    sessionToken: 'tok_test',
    sessionTtlSeconds: 3600,
    manifestRefreshIntervalMs: 300000,
    failOnManifestError: true,
    manifestFailurePolicy: 'use_last_valid',
    ...overrides
  };
}

function createState(options?: {
  manifest?: ParsedManifest | null;
  config?: Partial<ResolvedInterceptorConfig>;
  manifestState?: InterceptorState['manifestRuntime']['manifestState'];
}): InterceptorState {
  const manifest = options && 'manifest' in options ? (options.manifest ?? null) : createManifest();
  return {
    config: createConfig(options?.config),
    manifest,
    manifestRuntime: {
      currentManifest: manifest,
      currentManifestExpiresAt: manifest ? new Date(manifest.expires_at) : null,
      lastRefreshAttemptAt: null,
      manifestState: options?.manifestState ?? (manifest ? 'valid' : 'missing')
    },
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {}
    },
    refreshTimer: null,
    initialized: true,
    sessionManager: null
  };
}

describe('patch-fetch', () => {
  const nativeFetch = globalThis.fetch;
  const mockedExecuteRequest = vi.mocked(executeRequest);

  afterEach(() => {
    removeFetchPatch();
    globalThis.fetch = nativeFetch;
    vi.clearAllMocks();
  });

  it('intercepts matching fetch requests', async () => {
    const passthroughFetch = vi.fn(() => Promise.resolve(new Response('passthrough', {status: 200})));
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;
    mockedExecuteRequest.mockResolvedValue({
      ok: true,
      response: {
        status: 'executed',
        correlation_id: 'corr_1',
        upstream: {
          status_code: 201,
          headers: [{name: 'content-type', value: 'text/plain'}],
          body_base64: Buffer.from('intercepted').toString('base64')
        }
      }
    });

    applyFetchPatch(createState());

    const response = await fetch('https://api.openai.com/v1/chat/completions', {method: 'POST', body: '{"x":1}'});
    expect(response.status).toBe(201);
    expect(await response.text()).toBe('intercepted');
    expect(mockedExecuteRequest).toHaveBeenCalled();
    expect(passthroughFetch).not.toHaveBeenCalled();
  });

  it('passes through non-matching fetch requests', async () => {
    const passthroughFetch = vi.fn(() => Promise.resolve(new Response('passthrough', {status: 200})));
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;
    mockedExecuteRequest.mockResolvedValue({
      ok: true,
      response: {
        status: 'executed',
        correlation_id: 'corr_1',
        upstream: {
          status_code: 200,
          headers: [{name: 'content-type', value: 'text/plain'}],
          body_base64: Buffer.from('should-not-be-used').toString('base64')
        }
      }
    });

    applyFetchPatch(createState());

    const response = await fetch('https://example.com/healthz');
    expect(await response.text()).toBe('passthrough');
    expect(passthroughFetch).toHaveBeenCalled();
    expect(mockedExecuteRequest).not.toHaveBeenCalled();
  });

  it('does not consume Request body before passthrough when URL does not match manifest', async () => {
    let bodyUsedAtPassthroughEntry: boolean | null = null;
    const passthroughFetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (input instanceof Request) {
        bodyUsedAtPassthroughEntry = input.bodyUsed;
        const bodyText = await input.text();
        return new Response(bodyText, {status: 200});
      }

      const request = new Request(input, init);
      bodyUsedAtPassthroughEntry = request.bodyUsed;
      const bodyText = await request.text();
      return new Response(bodyText, {status: 200});
    });
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;

    applyFetchPatch(createState());

    const request = new Request('https://example.com/healthz', {
      method: 'POST',
      body: 'passthrough-body'
    });
    const response = await fetch(request);

    expect(await response.text()).toBe('passthrough-body');
    expect(bodyUsedAtPassthroughEntry).toBe(false);
    expect(passthroughFetch).toHaveBeenCalled();
    expect(mockedExecuteRequest).not.toHaveBeenCalled();
  });

  it('uses init overrides for Request input when intercepting', async () => {
    const passthroughFetch = vi.fn(() => Promise.resolve(new Response('passthrough', {status: 200})));
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;

    mockedExecuteRequest.mockResolvedValue({
      ok: true,
      response: {
        status: 'executed',
        correlation_id: 'corr_override',
        upstream: {
          status_code: 200,
          headers: [{name: 'content-type', value: 'text/plain'}],
          body_base64: Buffer.from('override-ok').toString('base64')
        }
      }
    });

    applyFetchPatch(createState());

    const request = new Request('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'x-original': 'request'
      },
      body: 'request-body'
    });

    const response = await fetch(request, {
      method: 'PATCH',
      headers: {
        'x-override': 'init'
      },
      body: 'init-body'
    });

    expect(await response.text()).toBe('override-ok');
    expect(mockedExecuteRequest).toHaveBeenCalledTimes(1);
    const executeCall = mockedExecuteRequest.mock.calls[0];
    expect(executeCall?.[0].method).toBe('PATCH');
    expect(executeCall?.[0].headers).toEqual({
      'x-override': 'init'
    });
    expect(executeCall?.[0].body).toEqual(Buffer.from('init-body'));
    expect(passthroughFetch).not.toHaveBeenCalled();
  });

  it('keeps routing with stale runtime state while manifest is still unexpired', async () => {
    const passthroughFetch = vi.fn(() => Promise.resolve(new Response('passthrough', {status: 200})));
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;
    mockedExecuteRequest.mockResolvedValue({
      ok: true,
      response: {
        status: 'executed',
        correlation_id: 'corr_2',
        upstream: {
          status_code: 200,
          headers: [{name: 'content-type', value: 'text/plain'}],
          body_base64: Buffer.from('stale-manifest-routed').toString('base64')
        }
      }
    });

    const state = createState({
      manifest: createManifest({expires_at: new Date(Date.now() + 30_000).toISOString()}),
      manifestState: 'stale'
    });
    applyFetchPatch(state);
    updateFetchState(state);

    const response = await fetch('https://api.openai.com/v1/chat/completions');
    expect(await response.text()).toBe('stale-manifest-routed');
    expect(mockedExecuteRequest).toHaveBeenCalled();
    expect(passthroughFetch).not.toHaveBeenCalled();
  });

  it('blocks matching requests when manifest is expired', async () => {
    const passthroughFetch = vi.fn(() => Promise.resolve(new Response('passthrough', {status: 200})));
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;

    applyFetchPatch(
      createState({
        manifest: createManifest({expires_at: new Date(Date.now() - 30_000).toISOString()}),
        config: {manifestFailurePolicy: 'use_last_valid'}
      })
    );

    await expect(fetch('https://api.openai.com/v1/chat/completions')).rejects.toBeInstanceOf(ManifestUnavailableError);
    expect(mockedExecuteRequest).not.toHaveBeenCalled();
    expect(passthroughFetch).not.toHaveBeenCalled();
  });

  it('does not block broker-origin fetch requests when manifest is expired', async () => {
    const passthroughFetch = vi.fn(() => Promise.resolve(new Response('broker-refresh', {status: 200})));
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;

    applyFetchPatch(
      createState({
        manifest: createManifest({expires_at: new Date(Date.now() - 30_000).toISOString()}),
        config: {manifestFailurePolicy: 'use_last_valid'}
      })
    );

    const response = await fetch('https://broker.example.com/v1/workloads/w_test/manifest');
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('broker-refresh');
    expect(passthroughFetch).toHaveBeenCalled();
    expect(mockedExecuteRequest).not.toHaveBeenCalled();
  });

  it('passes through when manifest is missing and policy is fail_open', async () => {
    const passthroughFetch = vi.fn(() => Promise.resolve(new Response('fail-open', {status: 200})));
    globalThis.fetch = passthroughFetch as typeof globalThis.fetch;

    applyFetchPatch(
      createState({
        manifest: null,
        config: {manifestFailurePolicy: 'fail_open'}
      })
    );

    const response = await fetch('https://api.openai.com/v1/chat/completions');
    expect(await response.text()).toBe('fail-open');
    expect(passthroughFetch).toHaveBeenCalled();
    expect(mockedExecuteRequest).not.toHaveBeenCalled();
  });
});
