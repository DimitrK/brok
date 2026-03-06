import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';

import type {ServiceConfig} from '../config';

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

beforeEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
});

describe('createBrokerApiApp unit wiring', () => {
  it('passes HTTPS options into Nest and shuts down cleanly when TLS is configured', async () => {
    const expressDisable = vi.fn();
    const expressUse = vi.fn();
    const enableCors = vi.fn();
    const init = vi.fn(() => Promise.resolve(undefined));
    const listen = vi.fn(() => Promise.resolve(undefined));
    const close = vi.fn(() => Promise.resolve(undefined));
    const getHttpServer = vi.fn(() => ({address: () => ({port: 8443})}));
    const destroy = vi.fn();
    const infrastructureClose = vi.fn(() => Promise.resolve(undefined));
    const readFile = vi
      .fn()
      .mockResolvedValueOnce(Buffer.from('key-pem'))
      .mockResolvedValueOnce(Buffer.from('cert-pem'))
      .mockResolvedValueOnce(Buffer.from('ca-pem'));
    const create = vi.fn(() =>
      Promise.resolve({
      enableCors,
      init,
      getHttpServer,
      listen,
      close
      })
    );

    vi.doMock('node:fs', () => ({
      promises: {
        readFile
      }
    }));
    vi.doMock('express', () => ({
      default: vi.fn(() => ({
        disable: expressDisable,
        use: expressUse
      }))
    }));
    vi.doMock('helmet', () => ({
      default: vi.fn(() => 'helmet-middleware')
    }));
    vi.doMock('@nestjs/core', () => ({
      NestFactory: {
        create
      }
    }));
    vi.doMock('@nestjs/platform-express', () => ({
      ExpressAdapter: vi.fn(function ExpressAdapter(app: unknown) {
        return {app};
      })
    }));
    vi.doMock('../infrastructure', () => ({
      createProcessInfrastructure: vi.fn(() => Promise.resolve({
        enabled: false,
        close: infrastructureClose
      }))
    }));
    vi.doMock('../repository', () => ({
      DataPlaneRepository: {
        create: vi.fn(() => Promise.resolve({
          destroy
        }))
      }
    }));
    vi.doMock('@broker-interceptor/logging', () => ({
      createStructuredLogger: vi.fn(() => ({
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        debug: vi.fn(),
        fatal: vi.fn(),
        child: vi.fn()
      }))
    }));
    vi.doMock('@broker-interceptor/audit', () => ({
      createAuditService: vi.fn(() => ({append: vi.fn()})),
      createInMemoryAuditStore: vi.fn(() => ({kind: 'memory'})),
      createPersistentAuditStore_INCOMPLETE: vi.fn()
    }));
    vi.doMock('@broker-interceptor/db', () => ({
      createAuditRedisCacheAdapter: vi.fn()
    }));

    const {createBrokerApiApp} = await import('../app');

    const configWithTls = makeConfig();
    configWithTls.tls = {
      enabled: true,
      keyPath: '/tmp/broker-api-test.key',
      certPath: '/tmp/broker-api-test.crt',
      clientCaPath: '/tmp/broker-api-test-ca.crt',
      requireClientCert: true,
      rejectUnauthorizedClientCert: true
    };

    const app = await createBrokerApiApp({config: configWithTls});
    await app.start();
    await app.stop();

    expect(readFile).toHaveBeenCalledTimes(3);
    expect(expressDisable).toHaveBeenCalledWith('x-powered-by');
    expect(expressUse).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        bodyParser: false,
        logger: false,
        httpsOptions: {
          key: Buffer.from('key-pem'),
          cert: Buffer.from('cert-pem'),
          ca: Buffer.from('ca-pem'),
          requestCert: true,
          rejectUnauthorized: true
        }
      })
    );
    expect(enableCors).toHaveBeenCalledWith({
      origin: ['http://localhost:4173']
    });
    expect(listen).toHaveBeenCalledWith(0, '127.0.0.1');
    expect(destroy).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(infrastructureClose).toHaveBeenCalledTimes(1);
  }, 15_000);

  it('closes infrastructure when repository creation fails during bootstrap', async () => {
    const infrastructureClose = vi.fn(() => Promise.resolve(undefined));
    const startupError = new Error('repository init failed');

    vi.doMock('express', () => ({
      default: vi.fn(() => ({
        disable: vi.fn(),
        use: vi.fn()
      }))
    }));
    vi.doMock('helmet', () => ({
      default: vi.fn(() => 'helmet-middleware')
    }));
    vi.doMock('../infrastructure', () => ({
      createProcessInfrastructure: vi.fn(() => Promise.resolve({
        enabled: false,
        close: infrastructureClose
      }))
    }));
    vi.doMock('../repository', () => ({
      DataPlaneRepository: {
        create: vi.fn(() => {
          throw startupError;
        })
      }
    }));
    vi.doMock('@broker-interceptor/logging', () => ({
      createStructuredLogger: vi.fn(() => ({
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        debug: vi.fn(),
        fatal: vi.fn(),
        child: vi.fn()
      }))
    }));
    vi.doMock('@broker-interceptor/audit', () => ({
      createAuditService: vi.fn(),
      createInMemoryAuditStore: vi.fn(),
      createPersistentAuditStore_INCOMPLETE: vi.fn()
    }));
    vi.doMock('@broker-interceptor/db', () => ({
      createAuditRedisCacheAdapter: vi.fn()
    }));

    const {createBrokerApiApp} = await import('../app');

    await expect(createBrokerApiApp({config: makeConfig()})).rejects.toThrow('repository init failed');
    expect(infrastructureClose).toHaveBeenCalledTimes(1);
  });
});
