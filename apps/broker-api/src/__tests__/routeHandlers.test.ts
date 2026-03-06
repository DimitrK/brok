import {describe, expect, it, vi} from 'vitest';

import type {ServiceConfig} from '../config';
import {handleFallbackRoute} from '../http/routes/fallbackRoute';
import {handleHealthRoute} from '../http/routes/healthRoute';
import {handleManifestKeysRoute} from '../http/routes/manifestKeysRoute';
import {handleWorkloadManifestRoute, isWorkloadManifestPath} from '../http/routes/workloadManifestRoute';
import type {RouteHandlerContext, RouteRuntime} from '../http/routes/types';

const makeConfig = (): ServiceConfig => ({
  nodeEnv: 'test',
  host: '127.0.0.1',
  port: 0,
  publicBaseUrl: 'https://broker.example',
  maxBodyBytes: 1024 * 1024,
  logging: {
    level: 'silent',
    redactExtraKeys: []
  },
  sessionDefaultTtlSeconds: 900,
  approvalTtlSeconds: 300,
  manifestTtlSeconds: 300,
  dpopMaxSkewSeconds: 300,
  forwarder: {
    total_timeout_ms: 15_000,
    max_request_body_bytes: 2 * 1024 * 1024,
    max_response_bytes: 2 * 1024 * 1024
  },
  dns_timeout_ms: 2_000,
  infrastructure: {
    enabled: false,
    redisConnectTimeoutMs: 2_000,
    redisKeyPrefix: 'broker-api:test'
  },
  corsAllowedOrigins: ['http://localhost:4173'],
  expectedSanUriPrefix: 'spiffe://broker/tenants/',
  initialState: {
    version: 1,
    workloads: [],
    integrations: [],
    templates: [],
    policies: [],
    approvals: [],
    sessions: [],
    integration_secret_headers: {},
    dpop_required_workload_ids: []
  },
  secretKey: Buffer.alloc(32, 'a'),
  secretKeyId: 'v1'
});

const makeResponse = () => {
  let statusCode = 0;
  let headers: Record<string, string> = {};
  let body = '';

  return {
    response: {
      writeHead: (status: number, nextHeaders: Record<string, string>) => {
        statusCode = status;
        headers = nextHeaders;
      },
      end: (value?: string) => {
        body = value ?? '';
      }
    } as RouteHandlerContext['response'],
    read: (): {
      statusCode: number;
      headers: Record<string, string>;
      body: string;
      json: unknown;
    } => ({
      statusCode,
      headers,
      body,
      json: body.length > 0 ? (JSON.parse(body) as unknown) : null
    })
  };
};

const makeRuntime = (): RouteRuntime & {
  manifestKeysSpy: ReturnType<typeof vi.fn>;
} => {
  const getManifestVerificationKeysShared = vi.fn(() =>
    Promise.resolve({
      keys: [
        {
          kid: 'manifest_test_key',
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'bs53BdmjW2it_uMCMgH2kk8_FdOKFOyojwDO91jTrBs',
          alg: 'EdDSA',
          use: 'sig'
        }
      ]
    })
  );
  const repository = {
    getManifestVerificationKeysShared,
    listManifestTemplateRulesForTenantShared: vi.fn(() => Promise.resolve([])),
    getManifestTtlSeconds: vi.fn(() => 300),
    getManifestSigningPrivateKeyShared: vi.fn()
  } as unknown as RouteRuntime['repository'];

  return {
    config: makeConfig(),
    repository,
    auditService: {} as RouteRuntime['auditService'],
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
      fatal: vi.fn(),
      child: vi.fn()
    } as unknown as RouteRuntime['logger'],
    baseDnsResolver: {} as RouteRuntime['baseDnsResolver'],
    now: () => new Date('2026-02-28T12:00:00.000Z'),
    requireMtlsContextWithLogging: vi.fn(() =>
      Promise.resolve({
      tenant_id: 't_1',
      workload_id: 'w_1',
      cert_fingerprint256: 'fp-1',
      san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1'
      })
    ),
    requireSessionContextWithLogging: vi.fn(),
    buildPublicRouteUrl: vi.fn(({pathname}: {pathname: string}) => `https://broker.example${pathname}`),
    getSingleHeaderValue: vi.fn(),
    isDpopRequiredForIdentity: vi.fn(() => false),
    isDpopFailureReasonCode: vi.fn(() => false),
    buildAuditEvent: vi.fn(),
    appendAuditEvent: vi.fn(() => Promise.resolve(undefined)),
    appendDpopFailureAuditEvent: vi.fn(() => Promise.resolve(undefined)),
    parseDestinationFromRequestUrl: vi.fn(),
    appendSsrfDecisionProjectionBestEffort: vi.fn(() => Promise.resolve(undefined)),
    reportPersistenceWarning: vi.fn(),
    normalizeResolvedIps: vi.fn(),
    ipSetsEqual: vi.fn(),
    clamp: vi.fn(),
    toForwarderIdempotencyFingerprint: vi.fn(),
    decodedBase64ByteLength: vi.fn(),
    manifestKeysSpy: getManifestVerificationKeysShared
  };
};

const makeContext = ({
  pathname = '/healthz',
  method = 'GET',
  runtime = makeRuntime(),
  response = makeResponse().response
}: {
  pathname?: string;
  method?: string;
  runtime?: RouteRuntime;
  response?: RouteHandlerContext['response'];
} = {}): RouteHandlerContext => ({
  request: {headers: {}} as RouteHandlerContext['request'],
  response,
  correlationId: 'corr_123',
  method,
  pathname,
  state: {
    mtlsContext: null,
    executeAuditRecorded: false
  },
  runtime
});

describe('broker-api route handlers', () => {
  it('returns the health payload with the correlation header', () => {
    const sink = makeResponse();

    void handleHealthRoute(
      makeContext({
        response: sink.response
      })
    );

    const result = sink.read();
    expect(result.statusCode).toBe(200);
    expect(result.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(result.headers['x-correlation-id']).toBe('corr_123');
    expect(result.json).toEqual({status: 'ok'});
  });

  it('returns signed manifest keys with cache headers after mTLS verification', async () => {
    const sink = makeResponse();
    const runtime = makeRuntime();

    await handleManifestKeysRoute(
      makeContext({
        pathname: '/v1/keys/manifest',
        runtime,
        response: sink.response
      })
    );

    expect(runtime.requireMtlsContextWithLogging).toHaveBeenCalledTimes(1);
    expect(runtime.manifestKeysSpy).toHaveBeenCalledTimes(1);
    const result = sink.read();
    expect(result.statusCode).toBe(200);
    expect(result.headers['cache-control']).toBe('public, max-age=60, must-revalidate');
    expect(result.headers['x-correlation-id']).toBe('corr_123');
    expect(result.json).toEqual({
      keys: [
        {
          kid: 'manifest_test_key',
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'bs53BdmjW2it_uMCMgH2kk8_FdOKFOyojwDO91jTrBs',
          alg: 'EdDSA',
          use: 'sig'
        }
      ]
    });
  });

  it('rejects unsupported routes through the fallback handler', () => {
    try {
      void handleFallbackRoute(
        makeContext({
          pathname: '/unsupported',
          method: 'DELETE'
        })
      );
      throw new Error('expected fallback route to reject unsupported requests');
    } catch (error) {
      expect(error).toMatchObject({
        code: 'route_not_found',
        status: 400,
        message: 'Unsupported route DELETE /unsupported'
      });
    }
  });

  it('matches only workload manifest routes with a workload identifier segment', () => {
    expect(isWorkloadManifestPath('/v1/workloads/w_1/manifest')).toBe(true);
    expect(isWorkloadManifestPath('/v1/workloads/w_1')).toBe(false);
  });

  it('fails closed when the manifest path workload does not match the mTLS workload', async () => {
    const runtime = makeRuntime();

    await expect(
      handleWorkloadManifestRoute(
        makeContext({
          pathname: '/v1/workloads/w_other/manifest',
          runtime
        })
      )
    ).rejects.toMatchObject({
      code: 'manifest_workload_mismatch',
      status: 401
    });
  });
});
