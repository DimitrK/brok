import {createHash, randomUUID} from 'node:crypto';
import type {IncomingMessage, ServerResponse} from 'node:http';
import {Readable} from 'node:stream';
import type {TLSSocket} from 'node:tls';

import {createAuditService, createInMemoryAuditStore} from '@broker-interceptor/audit';
import {
  buildEnvelopeAad,
  createAesGcmKeyManagementService,
  encryptSecretMaterial
} from '@broker-interceptor/crypto';
import type {StructuredLogger} from '@broker-interceptor/logging';
import {OpenApiManifestSchema} from '@broker-interceptor/schemas';
import {calculateJwkThumbprint} from '@broker-interceptor/auth';
import {exportJWK, generateKeyPair, SignJWT, type JWK} from 'jose';
import {afterEach, describe, expect, it, vi} from 'vitest';

import {appName} from '../index';
import type {ServiceConfig} from '../config';
import type {ProcessInfrastructure} from '../infrastructure';
import {DataPlaneRepository} from '../repository';
import {createBrokerApiRequestHandler} from '../server';

type RequestOptions = {
  method: 'GET' | 'POST';
  path: string;
  token?: string;
  dpop?: string;
  body?: unknown;
  rawBody?: string;
  headers?: Record<string, string>;
  tls?: {
    authorized?: boolean;
    sanUri?: string;
    fingerprint256?: string;
    remoteAddress?: string;
    extKeyUsage?: string[];
  };
};

type ResponseShape = {
  status: number;
  body: unknown;
  text: string;
  headers: Record<string, string>;
};

type ServerContext = {
  request: (options: RequestOptions) => Promise<ResponseShape>;
  repository: DataPlaneRepository;
  auditService: ReturnType<typeof createAuditService>;
};

const createMockSecretRepository = () => {
  type ManifestSigningKeyRecordMock = {
    kid: string;
    alg: string;
    public_jwk: unknown;
    private_key_ref: string;
    status: 'active';
    created_at: string;
  };
  type ManifestSigningKeyCreateInput = {
    kid?: string;
    alg?: string;
    public_jwk?: unknown;
    private_key_ref?: string;
  };

  let activeKey: ManifestSigningKeyRecordMock | null = null;
  return {
    getActiveSecretEnvelope: vi.fn(() => Promise.resolve(null)),
    getActiveManifestSigningKeyRecord: vi.fn(() => Promise.resolve(activeKey)),
    createManifestSigningKeyRecord: vi.fn((input: ManifestSigningKeyCreateInput) => {
      activeKey = {
        kid: input.kid || 'test-key',
        alg: input.alg || 'ES256',
        public_jwk: input.public_jwk,
        private_key_ref: input.private_key_ref || 'ref://test-key',
        status: 'active',
        created_at: new Date().toISOString()
      };
      return Promise.resolve(activeKey);
    }),
    setActiveManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
    retireManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
    revokeManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
    listManifestVerificationKeysWithEtag: vi.fn(() => Promise.resolve({keys: [], etag: 'test'})),
    persistManifestKeysetMetadata: vi.fn(() => Promise.resolve(undefined)),
    getCryptoVerificationDefaultsByTenant: vi.fn(() => Promise.resolve(null)),
    upsertCryptoVerificationDefaults: vi.fn(() => Promise.resolve(undefined))
  };
};

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
  manifestTtlSeconds: 600,
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
  secretKey: Buffer.alloc(32, 'a'),
  secretKeyId: 'v1',
  expectedSanUriPrefix: 'spiffe://broker/tenants/'
});

const createAllowRule = () => ({
  policy_id: 'pol_allow',
  rule_type: 'allow' as const,
  scope: {
    tenant_id: 't_1',
    workload_id: 'w_1',
    integration_id: 'i_1',
    template_id: 'tpl_openai_safe',
    template_version: 1,
    action_group: 'openai_responses',
    method: 'POST',
    host: 'api.openai.com',
    query_keys: []
  }
});

const createRateLimitRule = () => ({
  policy_id: 'pol_limit',
  rule_type: 'rate_limit' as const,
  scope: {
    tenant_id: 't_1',
    workload_id: 'w_1',
    integration_id: 'i_1',
    template_id: 'tpl_openai_safe',
    template_version: 1,
    action_group: 'openai_responses',
    method: 'POST',
    host: 'api.openai.com',
    query_keys: []
  },
  rate_limit: {
    max_requests: 1,
    interval_seconds: 60
  }
});

const createBaseState = ({
  approvalMode = 'none',
  includeAllowPolicy = true,
  includeRateLimit = false,
  dpopRequired = false,
  tenantDpopRequired = false
}: {
  approvalMode?: 'none' | 'required';
  includeAllowPolicy?: boolean;
  includeRateLimit?: boolean;
  dpopRequired?: boolean;
  tenantDpopRequired?: boolean;
} = {}) => ({
  version: 1,
  workloads: [
    {
      workload_id: 'w_1',
      tenant_id: 't_1',
      name: 'workload-one',
      mtls_san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1',
      enabled: true,
      ip_allowlist: ['203.0.113.0/24']
    }
  ],
  integrations: [
    {
      integration_id: 'i_1',
      tenant_id: 't_1',
      provider: 'openai',
      name: 'OpenAI Integration',
      template_id: 'tpl_openai_safe',
      enabled: true
    }
  ],
  templates: [
    {
      template_id: 'tpl_openai_safe',
      version: 1,
      provider: 'openai',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['api.openai.com'],
      redirect_policy: {mode: 'deny'},
      path_groups: [
        {
          group_id: 'openai_responses',
          risk_tier: 'medium',
          approval_mode: approvalMode,
          methods: ['POST'],
          path_patterns: ['^/v1/responses$'],
          query_allowlist: [],
          header_forward_allowlist: ['content-type', 'accept'],
          body_policy: {
            max_bytes: 2048,
            content_types: ['application/json']
          }
        }
      ],
      network_safety: {
        deny_private_ip_ranges: true,
        deny_link_local: true,
        deny_loopback: true,
        deny_metadata_ranges: true,
        dns_resolution_required: true
      }
    }
  ],
  policies: [...(includeAllowPolicy ? [createAllowRule()] : []), ...(includeRateLimit ? [createRateLimitRule()] : [])],
  approvals: [],
  sessions: [],
  integration_secret_headers: {
    i_1: [{name: 'authorization', value: 'Bearer provider-secret'}]
  },
  dpop_required_workload_ids: dpopRequired ? ['w_1'] : [],
  dpop_required_tenant_ids: tenantDpopRequired ? ['t_1'] : []
});

const executeRequestBody = {
  integration_id: 'i_1',
  request: {
    method: 'POST' as const,
    url: 'https://api.openai.com/v1/responses',
    headers: [
      {name: 'content-type', value: 'application/json'},
      {name: 'accept', value: 'application/json'}
    ],
    body_base64: Buffer.from(JSON.stringify({input: 'hello'}), 'utf8').toString('base64')
  },
  client_context: {
    request_id: 'req_1',
    source: 'test'
  }
};

const toSha256Base64Url = (value: string) => createHash('sha256').update(value, 'utf8').digest('base64url');

type DpopKeyPair = Awaited<ReturnType<typeof generateKeyPair>>;

const buildDpopProof = async ({
  method,
  url,
  accessToken,
  keyPair
}: {
  method: string;
  url: string;
  accessToken?: string;
  keyPair?: DpopKeyPair;
}) => {
  const effectiveKeyPair = keyPair ?? (await generateKeyPair('ES256'));
  const exportedJwk = await exportJWK(effectiveKeyPair.publicKey);
  const publicJwk: JWK = {
    kty: 'EC',
    crv: 'P-256',
    x: String(exportedJwk.x),
    y: String(exportedJwk.y)
  };

  const dpopPayload: Record<string, unknown> = {
    htm: method.toUpperCase(),
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: `jti_${randomUUID()}`
  };
  if (accessToken) {
    dpopPayload.ath = toSha256Base64Url(accessToken);
  }

  const jwt = await new SignJWT(dpopPayload)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: publicJwk
    })
    .sign(effectiveKeyPair.privateKey);

  const jkt = await calculateJwkThumbprint(publicJwk as Record<string, unknown>);
  if (!jkt) {
    throw new Error('failed to compute JWK thumbprint');
  }

  return {jwt, jkt, keyPair: effectiveKeyPair};
};

const encryptApiKeyEnvelope = async ({
  secretKey,
  keyId,
  aadContext
}: {
  secretKey: Buffer;
  keyId: string;
  aadContext: Readonly<Record<string, string>>;
}) => {
  const kms = createAesGcmKeyManagementService({
    active_key_id: keyId,
    keys: {
      [keyId]: secretKey.toString('base64')
    }
  });
  if (!kms.ok) {
    throw new Error(`failed to initialize test KMS: ${kms.error.message}`);
  }

  const encrypted = await encryptSecretMaterial({
    secret_material: {
      type: 'api_key',
      value: 'provider-secret'
    },
    key_management_service: kms.value,
    requested_key_id: keyId,
    aad: buildEnvelopeAad(aadContext)
  });
  if (!encrypted.ok) {
    throw new Error(`failed to encrypt test secret envelope: ${encrypted.error.message}`);
  }

  return encrypted.value.envelope;
};

const invokeHandler = async ({
  handler,
  method,
  path,
  token,
  dpop,
  body,
  rawBody,
  headers,
  tls
}: {
  handler: ReturnType<typeof createBrokerApiRequestHandler>;
} & RequestOptions): Promise<ResponseShape> => {
  const requestHeaders: Record<string, string> = {
    host: 'broker.example',
    ...(headers ?? {}),
    ...(token ? {authorization: `Bearer ${token}`} : {}),
    ...(dpop ? {dpop} : {})
  };

  const payload =
    typeof rawBody === 'string' ? rawBody : typeof body !== 'undefined' ? JSON.stringify(body) : undefined;

  if (payload && !requestHeaders['content-type']) {
    requestHeaders['content-type'] = 'application/json';
  }
  if (payload) {
    requestHeaders['content-length'] = String(Buffer.byteLength(payload, 'utf8'));
  }

  const request = new Readable({
    read() {
      if (payload) {
        this.push(payload);
      }
      this.push(null);
    }
  }) as IncomingMessage;
  request.method = method;
  request.url = path;
  request.headers = requestHeaders;

  const socket = {
    authorized: tls?.authorized ?? true,
    authorizationError: tls?.authorized === false ? new Error('mtls denied') : undefined,
    remoteAddress: tls?.remoteAddress ?? '203.0.113.10',
    getPeerCertificate: () => ({
      subjectaltname: `URI:${tls?.sanUri ?? 'spiffe://broker/tenants/t_1/workloads/w_1'}`,
      ext_key_usage: tls?.extKeyUsage ?? ['1.3.6.1.5.5.7.3.2'],
      fingerprint256: tls?.fingerprint256 ?? 'AA:BB:CC'
    })
  } as unknown as TLSSocket;

  Object.defineProperty(request, 'socket', {
    value: socket,
    writable: false
  });

  const capturedHeaders: Record<string, string> = {};
  const capturedBodyChunks: Buffer[] = [];

  let resolveEnded: () => void = () => undefined;
  const ended = new Promise<void>(resolve => {
    resolveEnded = resolve;
  });

  const response = {
    writeHead: (statusCode: number, headerValues: Record<string, string | number>) => {
      for (const [key, value] of Object.entries(headerValues)) {
        capturedHeaders[key.toLowerCase()] = String(value);
      }
      capturedHeaders[':status'] = String(statusCode);
      return response;
    },
    end: (chunk?: string | Buffer) => {
      if (typeof chunk === 'string') {
        capturedBodyChunks.push(Buffer.from(chunk, 'utf8'));
      } else if (chunk) {
        capturedBodyChunks.push(Buffer.from(chunk));
      }
      resolveEnded();
      return response;
    }
  } as unknown as ServerResponse;

  await handler(request, response);
  await ended;

  const text = Buffer.concat(capturedBodyChunks).toString('utf8');
  let parsedBody: unknown = undefined;
  if (text.length > 0) {
    try {
      parsedBody = JSON.parse(text) as unknown;
    } catch {
      parsedBody = text;
    }
  }

  return {
    status: Number(capturedHeaders[':status'] ?? 0),
    body: parsedBody,
    text,
    headers: capturedHeaders
  };
};

const createContext = async ({
  state = createBaseState(),
  fetchImpl,
  dnsResolver,
  processInfrastructure,
  secretKey,
  secretKeyId,
  logger
}: {
  state?: unknown;
  fetchImpl?: (...args: Parameters<typeof fetch>) => ReturnType<typeof fetch>;
  dnsResolver?: (input: {hostname: string}) => Promise<string[]> | string[];
  processInfrastructure?: ProcessInfrastructure;
  secretKey?: Buffer;
  secretKeyId?: string;
  logger?: StructuredLogger;
} = {}): Promise<ServerContext> => {
  const repository = await DataPlaneRepository.create({
    initialState: state,
    approvalTtlSeconds: 300,
    manifestTtlSeconds: 600,
    ...(processInfrastructure ? {processInfrastructure} : {}),
    ...(secretKey ? {secretKey} : {}),
    ...(secretKeyId ? {secretKeyId} : {})
  });

  const auditStore = createInMemoryAuditStore();
  const auditService = createAuditService({store: auditStore});
  const effectiveDnsResolver = dnsResolver ?? (() => ['198.51.100.10']);

  const handler = createBrokerApiRequestHandler({
    config: makeConfig(),
    repository,
    auditService,
    ...(logger ? {logger} : {}),
    ...(fetchImpl ? {fetchImpl} : {}),
    dnsResolver: effectiveDnsResolver
  });

  return {
    request: (options: RequestOptions) => invokeHandler({handler, ...options}),
    repository,
    auditService
  };
};

const createMockLogger = (): StructuredLogger => ({
  log: vi.fn(),
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  fatal: vi.fn()
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('broker-api', () => {
  it('exports app name', () => {
    expect(appName).toBe('broker-api');
  });

  it('logs request route without query parameters', async () => {
    const logger = createMockLogger();
    const context = await createContext({logger});

    const response = await context.request({
      method: 'GET',
      path: '/healthz?api_key=secret-value'
    });

    expect(response.status).toBe(200);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'request.received',
        route: '/healthz'
      })
    );
  });

  it('logs mTLS authentication outcomes', async () => {
    const logger = createMockLogger();
    const context = await createContext({logger});

    const successResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    expect(successResponse.status).toBe(200);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'auth.mtls.verified'
      })
    );

    const deniedResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      },
      tls: {
        authorized: false
      }
    });

    expect(deniedResponse.status).toBe(401);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'auth.mtls.denied',
        reason_code: 'mtls_required'
      })
    );
  });

  it('logs session authentication denials with reason codes', async () => {
    const logger = createMockLogger();
    const context = await createContext({logger});

    const response = await context.request({
      method: 'POST',
      path: '/v1/execute',
      body: executeRequestBody
    });

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({error: 'session_missing'});
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'auth.session.denied',
        reason_code: 'session_missing'
      })
    );
  });

  it('rejects data-plane requests without mTLS', async () => {
    const context = await createContext();

    const response = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      },
      tls: {
        authorized: false
      }
    });

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({error: 'mtls_required'});
  });

  it('issues sessions and executes allowed requests with full enforcement chain', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );

    const context = await createContext({fetchImpl});

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute', 'manifest.read']
      }
    });

    expect(sessionResponse.status).toBe(200);
    const sessionBody = sessionResponse.body as {session_token: string; expires_at: string};
    expect(sessionBody.session_token).toBeTypeOf('string');
    expect(sessionBody.expires_at).toContain('T');

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token: sessionBody.session_token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(200);
    expect(executeResponse.body).toMatchObject({
      status: 'executed',
      upstream: {
        status_code: 200
      }
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const auditResult = await context.auditService.queryAuditEvents({
      query: {
        tenant_id: 't_1'
      }
    });
    expect(auditResult.ok).toBe(true);
    if (!auditResult.ok) {
      return;
    }

    expect(auditResult.value.events.some(event => event.event_type === 'policy_decision')).toBe(true);
    expect(auditResult.value.events.some(event => event.event_type === 'execute')).toBe(true);
  });

  it('keeps successful execute responses when ssrf projection persistence fails', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const logger = createMockLogger();
    const appendSsrfGuardDecisionProjection = vi.fn(() => Promise.reject(new Error('projection write failed')));

    const context = await createContext({
      fetchImpl,
      logger,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() => Promise.resolve(createBaseState().integrations[0])),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          auditEventRepository: {
            appendSsrfGuardDecisionProjection
          },
          secretRepository: createMockSecretRepository()
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey: Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64'),
      secretKeyId: 'v1'
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(200);
    expect(executeResponse.body).toMatchObject({status: 'executed'});
    expect(appendSsrfGuardDecisionProjection).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'repository.persistence.warning'
      })
    );
  });

  it('keeps ssrf rejection semantics when ssrf projection persistence fails', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const dnsResolver = vi.fn(() => Promise.resolve(['10.0.0.8']));
    const logger = createMockLogger();
    const appendSsrfGuardDecisionProjection = vi.fn(() => Promise.reject(new Error('projection write failed')));

    const context = await createContext({
      fetchImpl,
      dnsResolver,
      logger,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() => Promise.resolve(createBaseState().integrations[0])),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          auditEventRepository: {
            appendSsrfGuardDecisionProjection
          },
          secretRepository: createMockSecretRepository()
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey: Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64'),
      secretKeyId: 'v1'
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(400);
    expect(executeResponse.body).toMatchObject({error: 'resolved_ip_denied_private_range'});
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(appendSsrfGuardDecisionProjection).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'repository.persistence.warning'
      })
    );
  });

  it('executes when shared secret envelope AAD includes secret_type', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const secretKey = Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64');
    const secretKeyId = 'v1';
    const envelope = await encryptApiKeyEnvelope({
      secretKey,
      keyId: secretKeyId,
      aadContext: {
        tenant_id: 't_1',
        integration_id: 'i_1',
        secret_type: 'api_key'
      }
    });
    const secretRepositoryBase = createMockSecretRepository();
    const secretRepository = {
      ...secretRepositoryBase,
      getActiveSecretEnvelope: vi.fn(() =>
        Promise.resolve({
          secret_ref: 'sec_1',
          tenant_id: 't_1',
          integration_id: 'i_1',
          secret_type: 'api_key',
          version: 1,
          envelope: {
            key_id: envelope.key_id,
            content_encryption_alg: envelope.content_encryption_alg,
            key_encryption_alg: envelope.key_encryption_alg,
            wrapped_data_key_b64: envelope.wrapped_data_key_b64,
            iv_b64: envelope.iv_b64,
            ciphertext_b64: envelope.ciphertext_b64,
            auth_tag_b64: envelope.auth_tag_b64,
            ...(envelope.aad_b64 ? {aad_b64: envelope.aad_b64} : {})
          },
          created_at: new Date().toISOString()
        })
      )
    };

    const context = await createContext({
      fetchImpl,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() =>
              Promise.resolve({
                ...createBaseState().integrations[0],
                secret_ref: 'sec_1'
              })
            ),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          secretRepository
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey,
      secretKeyId
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(200);
    expect(executeResponse.body).toMatchObject({status: 'executed'});
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('fails closed when shared secret envelope AAD omits secret_type', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const secretKey = Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64');
    const secretKeyId = 'v1';
    const envelope = await encryptApiKeyEnvelope({
      secretKey,
      keyId: secretKeyId,
      aadContext: {
        tenant_id: 't_1',
        integration_id: 'i_1'
      }
    });
    const secretRepositoryBase = createMockSecretRepository();
    const secretRepository = {
      ...secretRepositoryBase,
      getActiveSecretEnvelope: vi.fn(() =>
        Promise.resolve({
          secret_ref: 'sec_1',
          tenant_id: 't_1',
          integration_id: 'i_1',
          secret_type: 'api_key',
          version: 1,
          envelope: {
            key_id: envelope.key_id,
            content_encryption_alg: envelope.content_encryption_alg,
            key_encryption_alg: envelope.key_encryption_alg,
            wrapped_data_key_b64: envelope.wrapped_data_key_b64,
            iv_b64: envelope.iv_b64,
            ciphertext_b64: envelope.ciphertext_b64,
            auth_tag_b64: envelope.auth_tag_b64,
            ...(envelope.aad_b64 ? {aad_b64: envelope.aad_b64} : {})
          },
          created_at: new Date().toISOString()
        })
      )
    };

    const context = await createContext({
      fetchImpl,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() =>
              Promise.resolve({
                ...createBaseState().integrations[0],
                secret_ref: 'sec_1'
              })
            ),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          secretRepository
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey,
      secretKeyId
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(503);
    expect(executeResponse.body).toMatchObject({error: 'integration_secret_unavailable'});
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('enforces DPoP on bound sessions', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const context = await createContext({fetchImpl});

    const sessionDpop = await buildDpopProof({
      method: 'POST',
      url: 'https://broker.example/v1/session'
    });
    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      },
      dpop: sessionDpop.jwt
    });

    expect(sessionResponse.status).toBe(200);
    const sessionBody = sessionResponse.body as {session_token: string; dpop_jkt: string};
    expect(sessionBody.dpop_jkt).toBe(sessionDpop.jkt);

    const missingProof = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token: sessionBody.session_token,
      body: executeRequestBody
    });
    expect(missingProof.status).toBe(401);
    expect(missingProof.body).toMatchObject({error: 'dpop_missing'});

    const auditResultAfterMissingProof = await context.auditService.queryAuditEvents({
      query: {
        tenant_id: 't_1'
      }
    });
    expect(auditResultAfterMissingProof.ok).toBe(true);
    if (!auditResultAfterMissingProof.ok) {
      return;
    }
    expect(
      auditResultAfterMissingProof.value.events.some(
        event => event.metadata?.['reason_code'] === 'dpop_missing' && event.event_type === 'execute'
      )
    ).toBe(true);

    const executeProof = await buildDpopProof({
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      accessToken: sessionBody.session_token,
      keyPair: sessionDpop.keyPair
    });
    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token: sessionBody.session_token,
      dpop: executeProof.jwt,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(200);
  });

  it('audits DPoP-required session issuance failures with reason code', async () => {
    const context = await createContext({
      state: createBaseState({
        dpopRequired: true
      })
    });

    const response = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({error: 'dpop_missing'});

    const auditResult = await context.auditService.queryAuditEvents({
      query: {
        tenant_id: 't_1'
      }
    });
    expect(auditResult.ok).toBe(true);
    if (!auditResult.ok) {
      return;
    }

    expect(
      auditResult.value.events.some(
        event => event.event_type === 'session_issued' && event.metadata?.['reason_code'] === 'dpop_missing'
      )
    ).toBe(true);
  });

  it('enforces tenant-level DPoP requirement and exposes it in manifest flags', async () => {
    const context = await createContext({
      state: createBaseState({
        tenantDpopRequired: true
      })
    });

    const missingDpopSession = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['manifest.read']
      }
    });
    expect(missingDpopSession.status).toBe(401);
    expect(missingDpopSession.body).toMatchObject({error: 'dpop_missing'});

    const sessionProof = await buildDpopProof({
      method: 'POST',
      url: 'https://broker.example/v1/session'
    });
    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['manifest.read']
      },
      dpop: sessionProof.jwt
    });
    expect(sessionResponse.status).toBe(200);

    const token = (sessionResponse.body as {session_token: string}).session_token;
    const manifestProof = await buildDpopProof({
      method: 'GET',
      url: 'https://broker.example/v1/workloads/w_1/manifest',
      accessToken: token,
      keyPair: sessionProof.keyPair
    });
    const manifestResponse = await context.request({
      method: 'GET',
      path: '/v1/workloads/w_1/manifest',
      token,
      dpop: manifestProof.jwt
    });

    expect(manifestResponse.status).toBe(200);
    expect(manifestResponse.body).toMatchObject({
      dpop_required: true,
      dpop_ath_required: true
    });
  });

  it('returns approval_required when policy/template demands human approval', async () => {
    const context = await createContext({
      state: createBaseState({
        approvalMode: 'required',
        includeAllowPolicy: false
      })
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const sessionBody = sessionResponse.body as {session_token: string};

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token: sessionBody.session_token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(202);
    expect(executeResponse.body).toMatchObject({
      status: 'approval_required',
      summary: {
        integration_id: 'i_1',
        action_group: 'openai_responses'
      }
    });
  });

  it('enforces policy rate limits', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const context = await createContext({
      state: createBaseState({
        includeRateLimit: true
      }),
      fetchImpl
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const firstAttempt = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });
    expect(firstAttempt.status).toBe(200);

    const secondAttempt = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });
    expect(secondAttempt.status).toBe(400);
    expect(secondAttempt.body).toMatchObject({error: 'policy_rate_limited'});
  });

  it('wires forwarder lock/idempotency persistence in execute path when idempotency_key is present', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );

    const redisData = new Map<string, string>();
    const redisSet = vi.fn(
      (
        key: string,
        value: string,
        options?: {
          NX?: boolean;
          PX?: number;
          EX?: number;
        }
      ) => {
        void options?.PX;
        void options?.EX;
        if (options?.NX && redisData.has(key)) {
          return Promise.resolve(null);
        }
        redisData.set(key, value);
        return Promise.resolve('OK');
      }
    );
    const redisGet = vi.fn((key: string) => Promise.resolve(redisData.get(key) ?? null));
    const redisDel = vi.fn((...keys: string[]) => Promise.resolve(keys.filter(key => redisData.delete(key)).length));
    const redisEval = vi.fn((script: string, options: {keys: string[]; arguments: string[]}) => {
      const keys = options.keys;
      const args = options.arguments;
      const key = keys[0];
      if (!key) {
        return Promise.resolve(0);
      }

      if (script.includes('forwarder_lock_release')) {
        const token = typeof args[0] === 'string' ? args[0] : String(args[0] ?? '');
        const currentToken = redisData.get(key);
        if (!currentToken || currentToken !== token) {
          return Promise.resolve(0);
        }
        redisData.delete(key);
        return Promise.resolve(1);
      }

      if (script.includes('forwarder_idem_update')) {
        const payload = redisData.get(key);
        if (!payload) {
          return Promise.resolve(0);
        }

        const parsed = JSON.parse(payload) as {
          state: string;
          correlation_id: string;
          upstream_status_code?: number;
          response_bytes?: number;
          error_code?: string;
        };
        const nextState = typeof args[0] === 'string' ? args[0] : String(args[0] ?? '');
        const correlationId = typeof args[1] === 'string' ? args[1] : String(args[1] ?? '');
        if (parsed.state !== 'in_progress' || parsed.correlation_id !== correlationId) {
          return Promise.resolve(0);
        }

        if (nextState === 'completed') {
          parsed.state = 'completed';
          parsed.upstream_status_code = Number(args[2] ?? 0);
          parsed.response_bytes = Number(args[3] ?? 0);
          delete parsed.error_code;
        } else {
          parsed.state = 'failed';
          parsed.error_code = typeof args[4] === 'string' ? args[4] : String(args[4] ?? '');
          delete parsed.upstream_status_code;
          delete parsed.response_bytes;
        }

        redisData.set(key, JSON.stringify(parsed));
        return Promise.resolve(1);
      }

      return Promise.resolve(0);
    });

    const context = await createContext({
      fetchImpl,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          set: redisSet,
          get: redisGet,
          del: redisDel,
          eval: redisEval
        } as never,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() => Promise.resolve(createBaseState().integrations[0])),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          secretRepository: createMockSecretRepository()
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey: Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64'),
      secretKeyId: 'v1'
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const firstExecute = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: {
        ...executeRequestBody,
        client_context: {
          ...executeRequestBody.client_context,
          idempotency_key: 'idem_execute_1'
        }
      }
    });

    expect(firstExecute.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(redisSet).toHaveBeenCalled();
    expect(redisEval).toHaveBeenCalled();

    const secondExecute = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: {
        ...executeRequestBody,
        client_context: {
          ...executeRequestBody.client_context,
          idempotency_key: 'idem_execute_1'
        }
      }
    });
    expect(secondExecute.status).toBe(409);
    expect(secondExecute.body).toMatchObject({error: 'idempotency_key_reused'});
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    // Repeated conflicts should not leave the execution lock stuck until TTL.
    const thirdExecute = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: {
        ...executeRequestBody,
        client_context: {
          ...executeRequestBody.client_context,
          idempotency_key: 'idem_execute_1'
        }
      }
    });
    expect(thirdExecute.status).toBe(409);
    expect(thirdExecute.body).toMatchObject({error: 'idempotency_key_reused'});
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('audits early execute rejections before policy evaluation', async () => {
    const context = await createContext();

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: {
        ...executeRequestBody,
        integration_id: 'missing_integration'
      }
    });

    expect(executeResponse.status).toBe(400);
    expect(executeResponse.body).toMatchObject({error: 'integration_not_found'});

    const auditResult = await context.auditService.queryAuditEvents({
      query: {
        tenant_id: 't_1',
        decision: 'denied'
      }
    });
    expect(auditResult.ok).toBe(true);
    if (!auditResult.ok) {
      return;
    }

    expect(
      auditResult.value.events.some(
        event => event.event_type === 'execute' && event.metadata?.['reason_code'] === 'integration_not_found'
      )
    ).toBe(true);
  });

  it('fails closed with a stable reason code when shared secret retrieval fails', async () => {
    const integrationWithSecretRef = {
      ...createBaseState().integrations[0],
      secret_ref: 'sec_1'
    };
    const secretRepository = createMockSecretRepository();
    secretRepository.getActiveSecretEnvelope.mockRejectedValue(new Error('secret store unavailable'));

    const context = await createContext({
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() => Promise.resolve(integrationWithSecretRef)),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          secretRepository
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey: Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64'),
      secretKeyId: 'v1'
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(503);
    expect(executeResponse.body).toMatchObject({error: 'integration_secret_unavailable'});

    const auditResult = await context.auditService.queryAuditEvents({
      query: {
        tenant_id: 't_1',
        decision: 'denied'
      }
    });
    expect(auditResult.ok).toBe(true);
    if (!auditResult.ok) {
      return;
    }

    expect(
      auditResult.value.events.some(
        event => event.event_type === 'execute' && event.metadata?.['reason_code'] === 'integration_secret_unavailable'
      )
    ).toBe(true);
  });

  it('blocks SSRF attempts when DNS resolves to denied ranges', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const context = await createContext({
      fetchImpl,
      dnsResolver: () => ['10.0.0.8']
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(400);
    expect(executeResponse.body).toMatchObject({error: 'resolved_ip_denied_private_range'});
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('uses SSRF DNS cache, records rebinding observations, and persists denied SSRF projections', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const redisStrings = new Map<string, string>();
    const redisLists = new Map<string, string[]>();
    const redisSet = vi.fn((key: string, value: string) => {
      redisStrings.set(key, value);
      return Promise.resolve('OK');
    });
    const redisGet = vi.fn((key: string) => Promise.resolve(redisStrings.get(key) ?? null));
    const redisRPush = vi.fn((key: string, value: string) => {
      const list = redisLists.get(key) ?? [];
      list.push(value);
      redisLists.set(key, list);
      return Promise.resolve(list.length);
    });
    const redisLTrim = vi.fn((key: string, start: number, end: number) => {
      const list = redisLists.get(key) ?? [];
      const normalizedStart = start < 0 ? Math.max(0, list.length + start) : Math.max(0, start);
      const normalizedEnd = end < 0 ? list.length + end : end;
      redisLists.set(key, list.slice(normalizedStart, normalizedEnd + 1));
      return Promise.resolve('OK');
    });
    const redisPublish = vi.fn(() => Promise.resolve(1));

    const dnsResolver = vi.fn(() => Promise.resolve(['198.51.100.10']));
    dnsResolver.mockResolvedValueOnce(['198.51.100.10']);
    dnsResolver.mockResolvedValueOnce(['10.0.0.8']);

    const context = await createContext({
      fetchImpl,
      dnsResolver,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          set: redisSet,
          get: redisGet,
          rPush: redisRPush,
          lTrim: redisLTrim,
          publish: redisPublish
        } as never,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() => Promise.resolve(createBaseState().integrations[0])),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          secretRepository: createMockSecretRepository()
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey: Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64'),
      secretKeyId: 'v1'
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const firstExecute = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });
    expect(firstExecute.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(dnsResolver).toHaveBeenCalledTimes(1);

    const cacheKey = Array.from(redisStrings.keys()).find(key => key.includes(':ssrf_dns_cache:'));
    expect(cacheKey).toBeDefined();
    if (cacheKey) {
      const cachedPayload = JSON.parse(redisStrings.get(cacheKey) ?? '{}') as {
        resolved_at_epoch_ms: number;
        resolved_ips: string[];
        ttl_seconds: number;
      };
      redisStrings.set(
        cacheKey,
        JSON.stringify({
          ...cachedPayload,
          resolved_at_epoch_ms: 0
        })
      );
    }

    const secondExecute = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });
    expect(secondExecute.status).toBe(400);
    expect(secondExecute.body).toMatchObject({error: 'resolved_ip_denied_private_range'});
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(dnsResolver).toHaveBeenCalledTimes(2);
    expect(redisRPush).toHaveBeenCalled();

    const listPayloads = Array.from(redisLists.values()).flat();
    expect(listPayloads.some(value => value.includes('"decision":"allowed"'))).toBe(true);
    expect(listPayloads.some(value => value.includes('"reason_code":"resolved_ip_denied_private_range"'))).toBe(true);
  });

  it('falls back to shared tenant/global template lookup when execute bridge returns non-executable', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ok: true}), {
          status: 200,
          headers: {
            'content-type': 'application/json'
          }
        })
      )
    );
    const getLatestTemplateByTenantTemplateId = vi.fn(({tenant_id}: {tenant_id: string}) =>
      Promise.resolve(tenant_id === 'global' ? createBaseState().templates[0] : null)
    );

    const context = await createContext({
      fetchImpl,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() =>
              Promise.resolve({
                integration_id: 'i_1',
                tenant_id: 't_1',
                provider: 'openai',
                name: 'OpenAI Integration',
                template_id: 'tpl_openai_safe',
                enabled: true
              })
            ),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: false,
                execution_status: 'integration_disabled',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          templateRepository: {
            getLatestTemplateByTenantTemplateId
          },
          secretRepository: createMockSecretRepository()
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey: Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64'),
      secretKeyId: 'v1'
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(200);
    expect(executeResponse.body).toMatchObject({
      status: 'executed'
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(getLatestTemplateByTenantTemplateId).toHaveBeenNthCalledWith(1, {
      tenant_id: 't_1',
      template_id: 'tpl_openai_safe'
    });
    expect(getLatestTemplateByTenantTemplateId).toHaveBeenNthCalledWith(2, {
      tenant_id: 'global',
      template_id: 'tpl_openai_safe'
    });
  });

  it('fails closed when template is missing in execute bridge and shared tenant/global lookups', async () => {
    const getLatestTemplateByTenantTemplateId = vi.fn(() => Promise.resolve(null));
    const context = await createContext({
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getById: vi.fn(() =>
              Promise.resolve({
                integration_id: 'i_1',
                tenant_id: 't_1',
                provider: 'openai',
                name: 'OpenAI Integration',
                template_id: 'tpl_openai_safe',
                enabled: true
              })
            ),
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: false,
                execution_status: 'integration_disabled',
                template: createBaseState().templates[0],
                template_id: 'tpl_openai_safe',
                template_version: 1
              })
            )
          },
          templateRepository: {
            getLatestTemplateByTenantTemplateId
          },
          secretRepository: createMockSecretRepository()
        } as never,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      },
      secretKey: Buffer.from('yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8=', 'base64'),
      secretKeyId: 'v1'
    });

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['execute']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const executeResponse = await context.request({
      method: 'POST',
      path: '/v1/execute',
      token,
      body: executeRequestBody
    });

    expect(executeResponse.status).toBe(400);
    expect(executeResponse.body).toMatchObject({error: 'template_not_found'});
    expect(getLatestTemplateByTenantTemplateId).toHaveBeenNthCalledWith(1, {
      tenant_id: 't_1',
      template_id: 'tpl_openai_safe'
    });
    expect(getLatestTemplateByTenantTemplateId).toHaveBeenNthCalledWith(2, {
      tenant_id: 'global',
      template_id: 'tpl_openai_safe'
    });
  });

  it('serves signed manifests for the authenticated workload', async () => {
    const context = await createContext();

    const sessionResponse = await context.request({
      method: 'POST',
      path: '/v1/session',
      body: {
        requested_ttl_seconds: 900,
        scopes: ['manifest.read']
      }
    });
    const token = (sessionResponse.body as {session_token: string}).session_token;

    const manifestResponse = await context.request({
      method: 'GET',
      path: '/v1/workloads/w_1/manifest',
      token
    });

    expect(manifestResponse.status).toBe(200);
    const parsedManifest = OpenApiManifestSchema.parse(manifestResponse.body);
    expect(parsedManifest.broker_execute_url).toBe('https://broker.example/v1/execute');
    expect(parsedManifest.signature.kid).toContain('manifest_');
    expect(parsedManifest.match_rules.length).toBeGreaterThan(0);
  });
});
