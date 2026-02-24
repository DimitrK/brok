import * as http from 'node:http';
import * as https from 'node:https';

import {afterEach, describe, expect, it, vi} from 'vitest';

vi.mock('../broker-client.js', async () => {
  const actual = await vi.importActual<typeof import('../broker-client.js')>('../broker-client.js');
  return {
    ...actual,
    executeRequest: vi.fn()
  };
});

import {ManifestUnavailableError, executeRequest} from '../broker-client.js';
import {applyPatches, removePatches} from '../patch-http.js';
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

function createState(options?: {manifest?: ParsedManifest | null; config?: Partial<ResolvedInterceptorConfig>}): InterceptorState {
  const manifest = options && 'manifest' in options ? (options.manifest ?? null) : createManifest();
  return {
    config: createConfig(options?.config),
    manifest,
    manifestRuntime: {
      currentManifest: manifest,
      currentManifestExpiresAt: manifest ? new Date(manifest.expires_at) : null,
      lastRefreshAttemptAt: null,
      manifestState: manifest ? 'valid' : 'missing'
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

describe('patch-http', () => {
  const mockedExecuteRequest = vi.mocked(executeRequest);

  afterEach(() => {
    removePatches();
    vi.clearAllMocks();
  });

  it('intercepts matching http.request traffic', async () => {
    mockedExecuteRequest.mockResolvedValue({
      ok: true,
      response: {
        status: 'executed',
        correlation_id: 'corr_1',
        upstream: {
          status_code: 200,
          headers: [{name: 'content-type', value: 'text/plain'}],
          body_base64: Buffer.from('http-intercepted').toString('base64')
        }
      }
    });

    applyPatches(createState());

    const body = await new Promise<string>((resolve, reject) => {
      const req = http.request('https://api.openai.com/v1/chat/completions', {method: 'POST'}, res => {
        let responseBody = '';
        res.on('data', (chunk: Buffer) => {
          responseBody += chunk.toString();
        });
        res.on('end', () => resolve(responseBody));
      });
      req.on('error', reject);
      req.end();
    });

    expect(body).toBe('http-intercepted');
    expect(mockedExecuteRequest).toHaveBeenCalled();
  });

  it('intercepts matching https.request and preserves deterministic callback/event ordering', async () => {
    mockedExecuteRequest.mockResolvedValue({
      ok: true,
      response: {
        status: 'executed',
        correlation_id: 'corr_2',
        upstream: {
          status_code: 200,
          headers: [{name: 'content-type', value: 'text/plain'}],
          body_base64: Buffer.from('https-intercepted').toString('base64')
        }
      }
    });

    applyPatches(createState());

    const order: string[] = [];
    const result = await new Promise<string>((resolve, reject) => {
      const req = https.request('https://api.openai.com/v1/chat/completions', {method: 'POST'}, res => {
        order.push('callback');
        let body = '';
        res.on('data', (chunk: Buffer) => {
          body += chunk.toString();
        });
        res.on('end', () => resolve(body));
      });

      req.on('response', () => order.push('response'));
      req.on('error', reject);
      req.end(() => order.push('endcb'));
    });

    expect(result).toBe('https-intercepted');
    expect(order).toEqual(['callback', 'response', 'endcb']);
    expect(mockedExecuteRequest).toHaveBeenCalled();
  });

  it('passes through non-matching https.request traffic (no execute call)', () => {
    mockedExecuteRequest.mockResolvedValue({
      ok: true,
      response: {
        status: 'executed',
        correlation_id: 'corr_unused',
        upstream: {
          status_code: 200,
          headers: [],
          body_base64: ''
        }
      }
    });

    applyPatches(createState());

    const req = https.request('https://non-matching.example.com/path');
    req.on('error', () => {});
    req.destroy();

    expect(mockedExecuteRequest).not.toHaveBeenCalled();
  });

  it('blocks matching requests when manifest is expired and refresh is unavailable', async () => {
    applyPatches(
      createState({
        manifest: createManifest({expires_at: new Date(Date.now() - 60_000).toISOString()}),
        config: {manifestFailurePolicy: 'use_last_valid'}
      })
    );

    const err = await new Promise<unknown>(resolve => {
      const req = https.request('https://api.openai.com/v1/chat/completions');
      req.on('error', resolve);
      req.end();
    });

    expect(err).toBeInstanceOf(ManifestUnavailableError);
    expect(mockedExecuteRequest).not.toHaveBeenCalled();
  });

  it('does not block broker-origin requests when manifest is expired', async () => {
    applyPatches(
      createState({
        manifest: createManifest({expires_at: new Date(Date.now() - 60_000).toISOString()}),
        config: {
          manifestFailurePolicy: 'use_last_valid',
          brokerUrl: 'https://127.0.0.1:1'
        }
      })
    );

    const err = await new Promise<unknown>(resolve => {
      const req = https.request('https://127.0.0.1:1/v1/workloads/w_test/manifest');
      const timer = setTimeout(() => {
        req.destroy(new Error('timeout'));
      }, 2_000);

      req.on('error', error => {
        clearTimeout(timer);
        resolve(error);
      });
      req.end();
    });

    expect(err).not.toBeInstanceOf(ManifestUnavailableError);
    expect(mockedExecuteRequest).not.toHaveBeenCalled();
  });
});
