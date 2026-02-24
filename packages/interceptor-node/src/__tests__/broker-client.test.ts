/**
 * Unit tests for the broker client module.
 */

import {describe, expect, it, vi} from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {ApprovalRequiredError, ManifestUnavailableError, RequestDeniedError} from '../broker-client.js';
import {executeRequest} from '../broker-client.js';
import type {ExecuteResponseApprovalRequired, ParsedManifest, ResolvedInterceptorConfig} from '../types.js';

/**
 * Helper to create a valid summary object.
 */
function createSummary(
  overrides?: Partial<ExecuteResponseApprovalRequired['summary']>
): ExecuteResponseApprovalRequired['summary'] {
  return {
    integration_id: 'test-integration',
    action_group: 'READ',
    risk_tier: 'low',
    destination_host: 'api.example.com',
    method: 'GET',
    path: '/v1/test',
    ...overrides
  };
}

function createMtlsFiles(): {certPath: string; keyPath: string; caPath: string; cleanup: () => void} {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-client-mtls-'));
  const certPath = path.join(dir, 'workload.crt');
  const keyPath = path.join(dir, 'workload.key');
  const caPath = path.join(dir, 'ca.pem');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.writeFileSync(certPath, 'cert');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.writeFileSync(keyPath, 'key');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.writeFileSync(caPath, 'ca');

  return {
    certPath,
    keyPath,
    caPath,
    cleanup: () => {
      fs.rmSync(dir, {recursive: true, force: true});
    }
  };
}

describe('ApprovalRequiredError', () => {
  it('creates error with correct properties', () => {
    const summary = createSummary({
      risk_tier: 'high',
      action_group: 'DELETE'
    });

    const error = new ApprovalRequiredError('apr_123', '2024-12-31T23:59:59Z', summary);

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('ApprovalRequiredError');
    expect(error.approvalId).toBe('apr_123');
    expect(error.expiresAt).toBe('2024-12-31T23:59:59Z');
    expect(error.summary).toEqual(summary);
  });

  it('includes approval info in message', () => {
    const summary = createSummary({
      risk_tier: 'high',
      action_group: 'DELETE'
    });

    const error = new ApprovalRequiredError('apr_abc', '2024-12-31T23:59:59Z', summary);

    expect(error.message).toContain('apr_abc');
    expect(error.message).toContain('DELETE');
    expect(error.message).toContain('high');
  });

  it('can be caught as Error', () => {
    const summary = createSummary({
      risk_tier: 'medium',
      action_group: 'UPDATE'
    });

    const error = new ApprovalRequiredError('apr_test', '2024-12-31T23:59:59Z', summary);

    expect(() => {
      throw error;
    }).toThrow(Error);

    try {
      throw error;
    } catch (e) {
      expect(e).toBeInstanceOf(ApprovalRequiredError);
    }
  });
});

describe('RequestDeniedError', () => {
  it('creates error with correct properties', () => {
    const error = new RequestDeniedError('Insufficient permissions', 'corr_123abc');

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('RequestDeniedError');
    expect(error.reason).toBe('Insufficient permissions');
    expect(error.correlationId).toBe('corr_123abc');
  });

  it('includes reason in message', () => {
    const error = new RequestDeniedError('Policy violation: resource deletion blocked', 'corr_xyz');

    expect(error.message).toContain('Policy violation');
    expect(error.message).toContain('resource deletion blocked');
  });

  it('can be caught as Error', () => {
    const error = new RequestDeniedError('Access denied', 'corr_test');

    expect(() => {
      throw error;
    }).toThrow(Error);

    try {
      throw error;
    } catch (e) {
      expect(e).toBeInstanceOf(RequestDeniedError);
    }
  });
});

describe('Error inheritance', () => {
  it('ApprovalRequiredError is instanceof Error', () => {
    const error = new ApprovalRequiredError('apr_1', '2024-01-01T00:00:00Z', createSummary());

    expect(error instanceof Error).toBe(true);
  });

  it('RequestDeniedError is instanceof Error', () => {
    const error = new RequestDeniedError('denied', 'corr_1');

    expect(error instanceof Error).toBe(true);
  });

  it('errors have stack traces', () => {
    const approvalError = new ApprovalRequiredError('apr_1', '2024-01-01T00:00:00Z', createSummary());
    const deniedError = new RequestDeniedError('denied', 'corr_1');

    expect(approvalError.stack).toBeDefined();
    expect(deniedError.stack).toBeDefined();
    expect(approvalError.stack).toContain('ApprovalRequiredError');
    expect(deniedError.stack).toContain('RequestDeniedError');
  });

  it('ManifestUnavailableError is instanceof Error', () => {
    const error = new ManifestUnavailableError('manifest expired');

    expect(error instanceof Error).toBe(true);
    expect(error.message).toContain('manifest expired');
  });
});

describe('executeRequest', () => {
  const logger = {
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {}
  };

  const manifest: ParsedManifest = {
    manifest_version: 1,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    broker_execute_url: 'https://broker.example.com/v1/execute',
    match_rules: [
      {
        integration_id: 'int_test',
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
    }
  };

  const config: ResolvedInterceptorConfig = {
    brokerUrl: 'https://broker.example.com',
    workloadId: 'w_test',
    sessionToken: 'tok_test',
    sessionTtlSeconds: 3600,
    manifestRefreshIntervalMs: 300000,
    failOnManifestError: true,
    manifestFailurePolicy: 'use_last_valid'
  };

  const executeOptions = {
    integrationId: 'int_test',
    method: 'POST' as const,
    url: 'https://api.openai.com/v1/chat/completions',
    headers: {'content-type': 'application/json'},
    body: Buffer.from('{"hello":"world"}')
  };

  it('parses 200 executed responses', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({
        status: 200,
        body: JSON.stringify({
          status: 'executed',
          correlation_id: 'corr_1',
          upstream: {
            status_code: 200,
            headers: [{name: 'content-type', value: 'application/json'}],
            body_base64: Buffer.from('{"ok":true}').toString('base64')
          }
        })
      })
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.response.status).toBe('executed');
      expect(result.response.correlation_id).toBe('corr_1');
    }
  });

  it('parses 202 approval required responses', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({
        status: 202,
        body: JSON.stringify({
          status: 'approval_required',
          approval_id: 'appr_1',
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          correlation_id: 'corr_2',
          summary: {
            integration_id: 'int_test',
            action_group: 'openai_write',
            risk_tier: 'high',
            destination_host: 'api.openai.com',
            method: 'POST',
            path: '/v1/chat/completions'
          }
        })
      })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.approvalRequired?.approval_id).toBe('appr_1');
    }
  });

  it('maps 403 OpenAPI errors to RequestDeniedError-compatible result', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({
        status: 403,
        body: JSON.stringify({
          error: 'policy_denied',
          message: 'Blocked by policy',
          correlation_id: 'corr_3'
        })
      })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.denied?.reason).toBe('Blocked by policy');
      expect(result.denied?.correlationId).toBe('corr_3');
    }
  });

  it('returns deterministic error for malformed error payload', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({
        status: 403,
        body: '{"error":"missing-fields"}'
      })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Broker request failed: HTTP 403');
    }
  });

  it('fails when no session token is available', async () => {
    const configWithoutToken: ResolvedInterceptorConfig = {
      ...config,
      sessionToken: undefined
    };

    const result = await executeRequest(executeOptions, manifest, configWithoutToken, logger);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('No session token available for execute');
    }
  });

  it('fails when session token provider throws', async () => {
    const configWithoutToken: ResolvedInterceptorConfig = {
      ...config,
      sessionToken: undefined
    };

    const result = await executeRequest(
      executeOptions,
      manifest,
      configWithoutToken,
      logger,
      {
        getToken: () => Promise.reject(new Error('provider down')),
        getMtlsCredentials: () => ({cert: Buffer.from('c'), key: Buffer.from('k')})
      },
      () => Promise.resolve({status: 200, body: '{}'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Failed to get session token');
    }
  });

  it('rejects invalid execute request payloads before broker call', async () => {
    const requestImpl = vi.fn().mockResolvedValue({status: 200, body: '{}'});

    const result = await executeRequest(
      {
        ...executeOptions,
        method: 'TRACE' as unknown as 'POST'
      },
      manifest,
      config,
      logger,
      undefined,
      requestImpl
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Execute request failed schema validation');
    }
    expect(requestImpl).not.toHaveBeenCalled();
  });

  it('returns deterministic error when execute success response is invalid JSON', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({status: 200, body: '{"bad"'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Broker returned invalid JSON for execute success response');
    }
  });

  it('returns deterministic error when execute success response fails schema validation', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () =>
        Promise.resolve({
          status: 200,
          body: JSON.stringify({status: 'executed'})
        })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Broker execute success response failed schema validation');
    }
  });

  it('returns deterministic error when approval response is invalid JSON', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({status: 202, body: '{"broken"'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Broker returned invalid JSON for approval-required response');
    }
  });

  it('returns deterministic error when approval response fails schema validation', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () =>
        Promise.resolve({
          status: 202,
          body: JSON.stringify({status: 'approval_required'})
        })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Broker approval-required response failed schema validation');
    }
  });

  it('maps non-JSON 401 to authentication failure', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({status: 401, body: 'unauthorized'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Authentication failed: HTTP 401');
    }
  });

  it('maps non-JSON 429 to rate limited error', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({status: 429, body: 'rate limited'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Rate limited by broker');
    }
  });

  it('maps non-JSON non-special statuses to generic broker failure', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.resolve({status: 500, body: 'internal'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Broker request failed: HTTP 500');
    }
  });

  it('maps JSON 401 payload to authentication failure with message', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () =>
        Promise.resolve({
          status: 401,
          body: JSON.stringify({
            error: 'unauthorized',
            message: 'invalid token',
            correlation_id: 'corr_auth'
          })
        })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Authentication failed: invalid token');
    }
  });

  it('maps JSON 429 payload to rate-limited error', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () =>
        Promise.resolve({
          status: 429,
          body: JSON.stringify({
            error: 'rate_limited',
            message: 'try later',
            correlation_id: 'corr_rate'
          })
        })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Rate limited by broker');
    }
  });

  it('maps policy-like 400 payloads to denied result', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () =>
        Promise.resolve({
          status: 400,
          body: JSON.stringify({
            error: 'policy_violation',
            message: 'blocked by policy',
            correlation_id: 'corr_policy'
          })
        })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.denied).toEqual({
        reason: 'blocked by policy',
        correlationId: 'corr_policy'
      });
    }
  });

  it('maps non-policy JSON errors to broker returned message', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () =>
        Promise.resolve({
          status: 400,
          body: JSON.stringify({
            error: 'bad_request',
            message: 'invalid input',
            correlation_id: 'corr_bad'
          })
        })
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('Broker returned bad_request: invalid input');
    }
  });

  it('returns deterministic credential loading error for invalid mTLS path', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      {
        ...config,
        mtlsCertPath: 'relative/cert.pem'
      },
      logger,
      undefined,
      () => Promise.resolve({status: 200, body: '{}'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Failed to load mTLS credentials');
    }
  });

  it('returns deterministic broker request error when network call throws', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      () => Promise.reject(new Error('socket hang up'))
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Broker request error: socket hang up');
    }
  });

  it('handles non-Error token provider failures deterministically', async () => {
    const configWithoutToken: ResolvedInterceptorConfig = {
      ...config,
      sessionToken: undefined
    };

    const result = await executeRequest(
      executeOptions,
      manifest,
      configWithoutToken,
      logger,
      {
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
        getToken: () => Promise.reject('provider-down'),
        getMtlsCredentials: () => ({cert: Buffer.from('c'), key: Buffer.from('k')})
      },
      () => Promise.resolve({status: 200, body: '{}'})
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('provider-down');
    }
  });

  it('uses session token provider success path when static token is absent', async () => {
    const configWithoutToken: ResolvedInterceptorConfig = {
      ...config,
      sessionToken: undefined
    };
    const result = await executeRequest(
      {
        ...executeOptions,
        headers: {
          'content-type': 'application/json',
          host: 'should-be-stripped',
          connection: 'keep-alive',
          'x-multi': ['a', 'b'],
          'x-undefined': undefined
        }
      },
      manifest,
      configWithoutToken,
      logger,
      {
        getToken: () => Promise.resolve('provider-token'),
        getMtlsCredentials: () => ({cert: Buffer.from('c'), key: Buffer.from('k')})
      },
      (_url, options) => {
        const parsed = JSON.parse(options.body ?? '{}') as {
          request?: {headers?: Array<{name: string; value: string}>};
        };
        expect(parsed.request?.headers).toContainEqual({name: 'x-multi', value: 'a'});
        expect(parsed.request?.headers).toContainEqual({name: 'x-multi', value: 'b'});
        expect(parsed.request?.headers?.some(header => header.name.toLowerCase() === 'host')).toBe(false);
        expect(parsed.request?.headers?.some(header => header.name.toLowerCase() === 'connection')).toBe(false);
        return Promise.resolve({
          status: 200,
          body: JSON.stringify({
            status: 'executed',
            correlation_id: 'corr_provider',
            upstream: {
              status_code: 200,
              headers: [{name: 'content-type', value: 'application/json'}],
              body_base64: Buffer.from('{}').toString('base64')
            }
          })
        });
      }
    );

    expect(result.ok).toBe(true);
  });

  it('loads absolute mTLS cert/key/ca paths successfully', async () => {
    const files = createMtlsFiles();
    try {
      const result = await executeRequest(
        executeOptions,
        manifest,
        {
          ...config,
          mtlsCertPath: files.certPath,
          mtlsKeyPath: files.keyPath,
          mtlsCaPath: files.caPath
        },
        logger,
        undefined,
        () =>
          Promise.resolve({
            status: 200,
            body: JSON.stringify({
              status: 'executed',
              correlation_id: 'corr_mtls',
              upstream: {
                status_code: 200,
                headers: [{name: 'content-type', value: 'application/json'}],
                body_base64: Buffer.from('{}').toString('base64')
              }
            })
          })
      );

      expect(result.ok).toBe(true);
    } finally {
      files.cleanup();
    }
  });

  it('handles non-Error throw values from request implementation', async () => {
    const result = await executeRequest(
      executeOptions,
      manifest,
      config,
      logger,
      undefined,
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
      () => Promise.reject('boom-string')
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Broker request error: boom-string');
    }
  });
});
