import {mkdtemp, rm, writeFile} from 'node:fs/promises'
import type {IncomingMessage, ServerResponse} from 'node:http'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {Readable} from 'node:stream'

import type {StructuredLogger} from '@broker-interceptor/logging'
import {OpenApiAdminOAuthStartResponseSchema, type OpenApiTemplate} from '@broker-interceptor/schemas'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {AdminAuthenticator} from '../auth'
import {CertificateIssuer} from '../certificateIssuer'
import type {ServiceConfig} from '../config'
import {DependencyBridge} from '../dependencyBridge'
import {ControlPlaneRepository, type RepositoryAdminAccessRequest, type RepositoryAdminIdentity} from '../repository'
import {createAdminApiRequestHandler} from '../server'

const OWNER_TOKEN = 'owner-token-0123456789abcdef'
const ADMIN_TOKEN = 'admin-token-0123456789abcdef'
const LIMITED_ADMIN_TOKEN = 'limited-admin-token-0123456789abcdef'
const TEST_CA_PEM = '-----BEGIN CERTIFICATE-----\nTEST_CA\n-----END CERTIFICATE-----'

const temporaryDirectories: string[] = []

afterEach(async () => {
  vi.restoreAllMocks()

  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop()
    if (!directory) {
      continue
    }

    await rm(directory, {recursive: true, force: true})
  }
})

const makeTemplate = (templateId = 'tpl_openai_safe'): OpenApiTemplate => ({
  template_id: templateId,
  version: 1,
  provider: 'openai',
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: ['api.openai.com'],
  redirect_policy: {mode: 'deny'},
  path_groups: [
    {
      group_id: 'openai_responses',
      risk_tier: 'low',
      approval_mode: 'none',
      methods: ['POST'],
      path_patterns: ['^/v1/responses$'],
      query_allowlist: [],
      header_forward_allowlist: ['content-type', 'accept'],
      body_policy: {
        max_bytes: 8192,
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
})

const makeConfig = (): ServiceConfig => ({
  nodeEnv: 'test',
  host: '127.0.0.1',
  port: 0,
  maxBodyBytes: 1024 * 1024,
  logging: {
    level: 'silent',
    redactExtraKeys: []
  },
  secretKey: Buffer.alloc(32, 7),
  secretKeyId: 'kid-test',
  auth: {
    mode: 'static',
    tokens: [
      {
        token: OWNER_TOKEN,
        subject: 'owner-user',
        roles: ['owner']
      },
      {
        token: ADMIN_TOKEN,
        subject: 'tenant-admin',
        roles: ['admin'],
        tenant_ids: ['t_1', 't_2']
      },
      {
        token: LIMITED_ADMIN_TOKEN,
        subject: 'limited-admin',
        roles: ['admin'],
        tenant_ids: ['t_other']
      }
    ]
  },
  enrollmentTokenTtlSeconds: 600,
  clientCertTtlSecondsMax: 3600,
  certificateIssuer: {
    mode: 'mock',
    mtlsCaPem: TEST_CA_PEM
  },
  manifestKeys: {keys: []},
  infrastructure: {
    enabled: false,
    redisConnectTimeoutMs: 2_000,
    redisKeyPrefix: 'broker-admin-api:test'
  }
})

const makeOidcConfig = (): ServiceConfig => ({
  ...makeConfig(),
  auth: {
    mode: 'oidc',
    issuer: 'https://tenant.auth0.com/',
    audience: 'broker-admin-api',
    jwksUri: 'https://tenant.auth0.com/.well-known/jwks.json',
    oauth: {
      clientId: 'auth0-client-id',
      clientSecret: 'auth0-client-secret',
      authorizationUrl: 'https://tenant.auth0.com/authorize',
      tokenUrl: 'https://tenant.auth0.com/oauth/token',
      scope: 'openid profile email',
      stateTtlSeconds: 600,
      providerConnections: {}
    },
    roleClaim: 'roles',
    tenantClaim: 'tenant_ids',
    emailClaim: 'email',
    nameClaim: 'name'
  }
})

type RequestOptions = {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  path: string
  token?: string
  body?: unknown
  rawBody?: string
  headers?: Record<string, string>
}

type ResponseShape = {
  status: number
  body: unknown
  text: string
  headers: Record<string, string>
}

type ServerContext = {
  request: (options: RequestOptions) => Promise<ResponseShape>
  repository: ControlPlaneRepository
  dependencyBridge: DependencyBridge
}

const invokeHandler = async ({
  handler,
  method,
  path,
  token = OWNER_TOKEN,
  body,
  rawBody,
  headers
}: {
  handler: ReturnType<typeof createAdminApiRequestHandler>
} & RequestOptions): Promise<ResponseShape> => {
  const requestHeaders: Record<string, string> = {
    host: 'broker-admin-api.test',
    ...(headers ?? {}),
    ...(token ? {authorization: `Bearer ${token}`} : {})
  }

  const payload =
    typeof rawBody === 'string' ? rawBody : typeof body !== 'undefined' ? JSON.stringify(body) : undefined

  if (payload && !requestHeaders['content-type']) {
    requestHeaders['content-type'] = 'application/json'
  }
  if (payload) {
    requestHeaders['content-length'] = String(Buffer.byteLength(payload, 'utf8'))
  }

  const request = new Readable({
    read() {
      if (payload) {
        this.push(payload)
      }
      this.push(null)
    }
  }) as IncomingMessage
  request.method = method
  request.url = path
  request.headers = requestHeaders

  const capturedHeaders: Record<string, string> = {}
  const capturedBodyChunks: Buffer[] = []

  let resolveEnded: () => void = () => undefined
  const ended = new Promise<void>(resolve => {
    resolveEnded = resolve
  })

  const response = {
    writeHead: (statusCode: number, headerValues: Record<string, string | number>) => {
      for (const [key, value] of Object.entries(headerValues)) {
        capturedHeaders[key.toLowerCase()] = String(value)
      }
      capturedHeaders[':status'] = String(statusCode)
      return response
    },
    end: (chunk?: string | Buffer) => {
      if (typeof chunk === 'string') {
        capturedBodyChunks.push(Buffer.from(chunk, 'utf8'))
      } else if (chunk) {
        capturedBodyChunks.push(Buffer.from(chunk))
      }
      resolveEnded()
      return response
    }
  } as unknown as ServerResponse

  await handler(request, response)
  await ended

  const text = Buffer.concat(capturedBodyChunks).toString('utf8')
  let parsedBody: unknown = undefined
  if (text.length > 0) {
    try {
      parsedBody = JSON.parse(text) as unknown
    } catch {
      parsedBody = text
    }
  }

  return {
    status: Number(capturedHeaders[':status'] ?? 0),
    body: parsedBody,
    text,
    headers: capturedHeaders
  }
}

const createContext = async ({
  statePath,
  config = makeConfig(),
  logger
}: {
  statePath?: string
  config?: ServiceConfig
  logger?: StructuredLogger
} = {}): Promise<ServerContext> => {
  const repository = await ControlPlaneRepository.create({
    ...(statePath ? {statePath} : {}),
    manifestKeys: {keys: []},
    enrollmentTokenTtlSeconds: 600
  })

  const dependencyBridge = new DependencyBridge({
    repository,
    authenticator: new AdminAuthenticator({
      mode: 'static',
      tokens: [
        {
          token: OWNER_TOKEN,
          subject: 'owner-user',
          roles: ['owner']
        },
        {
          token: ADMIN_TOKEN,
          subject: 'tenant-admin',
          roles: ['admin'],
          tenant_ids: ['t_1', 't_2']
        },
        {
          token: LIMITED_ADMIN_TOKEN,
          subject: 'limited-admin',
          roles: ['admin'],
          tenant_ids: ['t_other']
        }
      ]
    }),
    certificateIssuer: new CertificateIssuer({
      mode: 'mock',
      mtlsCaPem: TEST_CA_PEM
    })
  })

  const handler = createAdminApiRequestHandler({
    config,
    repository,
    dependencyBridge,
    ...(logger ? {logger} : {})
  })

  return {
    request: (options: RequestOptions) => invokeHandler({handler, ...options}),
    repository,
    dependencyBridge
  }
}

const createMockLogger = (): StructuredLogger => ({
  log: vi.fn(),
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  fatal: vi.fn()
})

const createUnsignedJwt = (payload: Record<string, unknown>) => {
  const header = {
    alg: 'none',
    typ: 'JWT'
  }

  const headerPart = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url')
  const payloadPart = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
  return `${headerPart}.${payloadPart}.signature`
}

const writeStateFixture = async (state: object) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'broker-admin-server-test-'))
  temporaryDirectories.push(directory)
  const statePath = path.join(directory, 'state.json')
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Test fixture path is generated in-test and scoped to a temporary directory.
  await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`, 'utf8')
  return statePath
}

const buildApprovalFixtureState = () => {
  const now = Date.now()
  const future = new Date(now + 10 * 60 * 1000).toISOString()
  const created = new Date(now - 60 * 1000).toISOString()

  return {
    version: 1,
    tenants: [{tenant_id: 't_1', name: 'Tenant One'}],
    workloads: [
      {
        workload_id: 'w_1',
        tenant_id: 't_1',
        name: 'workload-one',
        mtls_san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1',
        enabled: true,
        created_at: created
      }
    ],
    integrations: [
      {
        integration_id: 'i_1',
        tenant_id: 't_1',
        provider: 'openai',
        name: 'openai',
        template_id: 'tpl_1',
        enabled: true,
        secret_ref: 'sec_1',
        secret_version: 1,
        last_rotated_at: created
      }
    ],
    templates: [makeTemplate('tpl_1')],
    policies: [],
    approvals: [
      {
        approval_id: 'appr_approve',
        status: 'pending',
        expires_at: future,
        correlation_id: 'corr_approve',
        summary: {
          integration_id: 'i_1',
          action_group: 'openai_responses',
          risk_tier: 'low',
          destination_host: 'api.openai.com',
          method: 'POST',
          path: '/v1/responses'
        },
        canonical_descriptor: {
          tenant_id: 't_1',
          workload_id: 'w_1',
          integration_id: 'i_1',
          template_id: 'tpl_1',
          template_version: 1,
          method: 'POST',
          canonical_url: 'https://api.openai.com/v1/responses',
          matched_path_group_id: 'openai_responses',
          normalized_headers: [],
          query_keys: []
        }
      },
      {
        approval_id: 'appr_deny',
        status: 'pending',
        expires_at: future,
        correlation_id: 'corr_deny',
        summary: {
          integration_id: 'i_1',
          action_group: 'openai_responses',
          risk_tier: 'low',
          destination_host: 'api.openai.com',
          method: 'POST',
          path: '/v1/responses'
        },
        canonical_descriptor: {
          tenant_id: 't_1',
          workload_id: 'w_1',
          integration_id: 'i_1',
          template_id: 'tpl_1',
          template_version: 1,
          method: 'POST',
          canonical_url: 'https://api.openai.com/v1/responses',
          matched_path_group_id: 'openai_responses',
          normalized_headers: [],
          query_keys: []
        }
      }
    ],
    audit_events: [],
    enrollment_tokens: [],
    secrets: [
      {
        secret_ref: 'sec_1',
        tenant_id: 't_1',
        integration_id: 'i_1',
        type: 'api_key',
        active_version: 1,
        versions: [
          {
            version: 1,
            key_id: 'kid-test',
            created_at: created,
            content_encryption_alg: 'A256GCM',
            key_encryption_alg: 'mock-wrap-v1',
            wrapped_data_key_b64: 'd3JhcHBlZA==',
            iv_b64: 'AAAAAAAAAAAAAAAA',
            ciphertext_b64: 'Y2lwaGVydGV4dA==',
            auth_tag_b64: 'YXV0aHRhZw=='
          }
        ]
      }
    ],
    manifest_keys: {keys: []}
  }
}

describe('broker-admin-api server routes', () => {
  it('logs request route without query parameters', async () => {
    const logger = createMockLogger()
    const context = await createContext({logger})

    const response = await context.request({
      method: 'GET',
      path: '/healthz?api_key=secret-value',
      token: ''
    })

    expect(response.status).toBe(200)
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'request.received',
        route: '/healthz'
      })
    )
  })

  it('logs successful admin authentication outcomes', async () => {
    const logger = createMockLogger()
    const context = await createContext({logger})

    const response = await context.request({
      method: 'GET',
      path: '/v1/admin/auth/session'
    })

    expect(response.status).toBe(200)
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'auth.admin.verified',
        component: 'server.auth'
      })
    )
  })

  it('serves health checks and rejects unauthenticated admin calls', async () => {
    const context = await createContext()

    const health = await context.request({method: 'GET', path: '/healthz', token: ''})
    expect(health.status).toBe(200)
    expect(health.body).toEqual({status: 'ok'})

    const unauthorized = await context.request({method: 'GET', path: '/v1/tenants', token: ''})
    expect(unauthorized.status).toBe(401)
    expect(unauthorized.body).toMatchObject({error: 'admin_auth_missing'})
  })

  it('supports public OAuth start/callback flow in oidc mode', async () => {
    const context = await createContext({config: makeOidcConfig()})

    const oauthStart = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/start',
      token: '',
      body: {
        provider: 'google',
        redirect_uri: 'http://localhost:4173/login/callback',
        code_challenge: 'Uwi4ws14iIVotYz8324XfRsL2V9v4prHlvtTdqQkYXI',
        code_challenge_method: 'S256'
      }
    })
    expect(oauthStart.status).toBe(200)
    const startBody = OpenApiAdminOAuthStartResponseSchema.parse(oauthStart.body)
    expect(startBody.authorization_url).toContain('https://tenant.auth0.com/authorize')
    expect(startBody.state.length).toBeGreaterThanOrEqual(16)
    expect(startBody.nonce.length).toBeGreaterThanOrEqual(16)
    expect(startBody.authorization_url).toContain('connection=google-oauth2')
    expect(startBody.authorization_url).toContain('audience=broker-admin-api')

    const idToken = createUnsignedJwt({
      sub: 'auth0|admin-user',
      iss: 'https://tenant.auth0.com/',
      aud: 'auth0-client-id',
      email: 'admin@example.com',
      email_verified: true,
      roles: ['admin'],
      tenant_ids: ['t_1'],
      nonce: startBody.nonce,
      exp: Math.floor(Date.now() / 1000) + 900
    })

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          id_token: idToken,
          access_token: 'access-token-for-api',
          expires_in: '900',
          token_type: 'Bearer',
          scope: 'openid profile email'
        })
    } as Response)

    const authenticateAdminPrincipalSpy = vi
      .spyOn(context.dependencyBridge, 'authenticateAdminPrincipal')
      .mockResolvedValue({
        subject: 'auth0|admin-user',
        issuer: 'https://tenant.auth0.com/',
        email: 'admin@example.com',
        roles: ['admin'],
        tenantIds: ['t_1'],
        authContext: {
          mode: 'oidc',
          issuer: 'https://tenant.auth0.com/'
        }
      })
    const resolveAdminIdentityFromTokenSpy = vi
      .spyOn(context.dependencyBridge, 'resolveAdminIdentityFromToken')
      .mockImplementation(({principal}) => Promise.resolve(principal))

    const oauthCallback = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/callback',
      token: '',
      body: {
        provider: 'google',
        code: 'auth0-code-123',
        state: startBody.state,
        code_verifier: 'x'.repeat(64),
        redirect_uri: 'http://localhost:4173/login/callback'
      }
    })
    expect(oauthCallback.status).toBe(200)
    expect(authenticateAdminPrincipalSpy).toHaveBeenCalledWith({
      authorizationHeader: 'Bearer access-token-for-api'
    })
    const [resolveCall] = resolveAdminIdentityFromTokenSpy.mock.calls as Array<[
      {
        principal: {
          emailVerified?: boolean
        }
      }
    ]>
    expect(resolveCall?.[0].principal.emailVerified).toBe(true)
    expect(oauthCallback.body).toMatchObject({
      session_id: 'access-token-for-api',
      principal: {
        subject: 'auth0|admin-user',
        issuer: 'https://tenant.auth0.com/',
        email: 'admin@example.com',
        roles: ['admin'],
        tenant_ids: ['t_1']
      }
    })
  })

  it('does not infer verified email from id_token when identity claims do not match principal', async () => {
    const context = await createContext({config: makeOidcConfig()})

    const oauthStart = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/start',
      token: '',
      body: {
        provider: 'google',
        redirect_uri: 'http://localhost:4173/login/callback',
        code_challenge: 'Uwi4ws14iIVotYz8324XfRsL2V9v4prHlvtTdqQkYXI',
        code_challenge_method: 'S256'
      }
    })
    expect(oauthStart.status).toBe(200)
    const startBody = OpenApiAdminOAuthStartResponseSchema.parse(oauthStart.body)

    const idToken = createUnsignedJwt({
      sub: 'auth0|admin-user',
      iss: 'https://tenant.auth0.com/',
      aud: 'auth0-client-id',
      email: 'other-admin@example.com',
      email_verified: true,
      nonce: startBody.nonce,
      exp: Math.floor(Date.now() / 1000) + 900
    })

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          id_token: idToken,
          access_token: 'access-token-for-api',
          expires_in: '900',
          token_type: 'Bearer',
          scope: 'openid profile email'
        })
    } as Response)

    vi.spyOn(context.dependencyBridge, 'authenticateAdminPrincipal').mockResolvedValue({
      subject: 'auth0|admin-user',
      issuer: 'https://tenant.auth0.com/',
      email: 'admin@example.com',
      roles: ['admin'],
      tenantIds: ['t_1'],
      authContext: {
        mode: 'oidc',
        issuer: 'https://tenant.auth0.com/'
      }
    })
    const resolveAdminIdentityFromTokenSpy = vi
      .spyOn(context.dependencyBridge, 'resolveAdminIdentityFromToken')
      .mockImplementation(({principal}) => Promise.resolve(principal))

    const oauthCallback = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/callback',
      token: '',
      body: {
        provider: 'google',
        code: 'auth0-code-123',
        state: startBody.state,
        code_verifier: 'x'.repeat(64),
        redirect_uri: 'http://localhost:4173/login/callback'
      }
    })

    expect(oauthCallback.status).toBe(200)
    const [resolveCall] = resolveAdminIdentityFromTokenSpy.mock.calls as Array<[
      {
        principal: {
          emailVerified?: boolean
        }
      }
    ]>
    expect(resolveCall?.[0].principal.emailVerified).toBeUndefined()
  })

  it('fails closed for OAuth routes when oidc interactive login is not configured', async () => {
    const context = await createContext()

    const oauthStart = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/start',
      token: '',
      body: {
        provider: 'google',
        redirect_uri: 'http://localhost:4173/login/callback',
        code_challenge: 'Uwi4ws14iIVotYz8324XfRsL2V9v4prHlvtTdqQkYXI',
        code_challenge_method: 'S256'
      }
    })
    expect(oauthStart.status).toBe(400)
    expect(oauthStart.body).toMatchObject({error: 'admin_oauth_not_configured'})
  })

  it('rejects OAuth callback when state is invalid', async () => {
    const context = await createContext({config: makeOidcConfig()})

    const oauthCallback = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/callback',
      token: '',
      body: {
        provider: 'google',
        code: 'auth0-code-123',
        state: 'invalid-state',
        code_verifier: 'x'.repeat(64),
        redirect_uri: 'http://localhost:4173/login/callback'
      }
    })
    expect(oauthCallback.status).toBe(400)
    expect(oauthCallback.body).toMatchObject({error: 'admin_oauth_state_invalid'})
  })

  it('rejects OAuth callback when code exchange fails', async () => {
    const context = await createContext({config: makeOidcConfig()})

    const oauthStart = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/start',
      token: '',
      body: {
        provider: 'google',
        redirect_uri: 'http://localhost:4173/login/callback',
        code_challenge: 'Uwi4ws14iIVotYz8324XfRsL2V9v4prHlvtTdqQkYXI',
        code_challenge_method: 'S256'
      }
    })
    expect(oauthStart.status).toBe(200)
    const startBody = OpenApiAdminOAuthStartResponseSchema.parse(oauthStart.body)

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      json: () =>
        Promise.resolve({
          error: 'invalid_grant',
          error_description: 'Authorization code has expired'
        })
    } as Response)

    const oauthCallback = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/callback',
      token: '',
      body: {
        provider: 'google',
        code: 'expired-code',
        state: startBody.state,
        code_verifier: 'x'.repeat(64),
        redirect_uri: 'http://localhost:4173/login/callback'
      }
    })

    expect(oauthCallback.status).toBe(400)
    expect(oauthCallback.body).toMatchObject({error: 'admin_oauth_callback_invalid'})
  })

  it('rejects OAuth callback when token response omits access_token', async () => {
    const context = await createContext({config: makeOidcConfig()})

    const oauthStart = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/start',
      token: '',
      body: {
        provider: 'google',
        redirect_uri: 'http://localhost:4173/login/callback',
        code_challenge: 'Uwi4ws14iIVotYz8324XfRsL2V9v4prHlvtTdqQkYXI',
        code_challenge_method: 'S256'
      }
    })
    expect(oauthStart.status).toBe(200)
    const startBody = OpenApiAdminOAuthStartResponseSchema.parse(oauthStart.body)

    const idToken = createUnsignedJwt({
      sub: 'auth0|admin-user',
      iss: 'https://tenant.auth0.com/',
      aud: 'auth0-client-id',
      email: 'admin@example.com',
      roles: ['admin'],
      tenant_ids: ['t_1'],
      nonce: startBody.nonce,
      exp: Math.floor(Date.now() / 1000) + 900
    })

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          id_token: idToken,
          expires_in: '900',
          token_type: 'Bearer',
          scope: 'openid profile email'
        })
    } as Response)

    const oauthCallback = await context.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/callback',
      token: '',
      body: {
        provider: 'google',
        code: 'auth0-code-123',
        state: startBody.state,
        code_verifier: 'x'.repeat(64),
        redirect_uri: 'http://localhost:4173/login/callback'
      }
    })

    expect(oauthCallback.status).toBe(400)
    expect(oauthCallback.body).toMatchObject({error: 'admin_oauth_callback_invalid'})
  })

  it('supports admin user management routes for owner principals', async () => {
    const context = await createContext()
    const adminUser: RepositoryAdminIdentity = {
      identity_id: 'adm_1',
      issuer: 'https://issuer.example/',
      subject: 'admin-subject-1',
      email: 'admin@example.com',
      status: 'active' as const,
      roles: ['admin'],
      tenant_ids: ['t_1'],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }
    const accessRequest: RepositoryAdminAccessRequest = {
      request_id: 'aar_1',
      issuer: 'https://issuer.example/',
      subject: 'admin-subject-1',
      email: 'admin@example.com',
      requested_roles: ['admin'],
      requested_tenant_ids: ['t_1'],
      status: 'pending' as const,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }

    const listAdminUsersSpy = vi
      .spyOn(context.dependencyBridge, 'listAdminUsers')
      .mockResolvedValue({users: [adminUser], next_cursor: 'cursor_1'})
    const updateAdminUserSpy = vi
      .spyOn(context.dependencyBridge, 'updateAdminUser')
      .mockResolvedValue(adminUser)
    const listAdminAccessRequestsSpy = vi
      .spyOn(context.dependencyBridge, 'listAdminAccessRequests')
      .mockResolvedValue({requests: [accessRequest], next_cursor: 'cursor_2'})
    const approveAdminAccessRequestWithOverridesSpy = vi
      .spyOn(context.dependencyBridge, 'approveAdminAccessRequestWithOverrides')
      .mockResolvedValue({...accessRequest, status: 'approved', reason: 'approved by owner'})
    const denyAdminAccessRequestSpy = vi
      .spyOn(context.dependencyBridge, 'denyAdminAccessRequest')
      .mockResolvedValue({...accessRequest, status: 'denied', reason: 'request denied'})

    const listUsersResponse = await context.request({
      method: 'GET',
      path: '/v1/admin/users?status=active&tenant_id=t_1&role=admin&search=adm&limit=10&cursor=cursor_0'
    })
    expect(listUsersResponse.status).toBe(200)
    expect(listUsersResponse.body).toMatchObject({
      users: [{identity_id: 'adm_1'}],
      next_cursor: 'cursor_1'
    })
    const [listAdminUsersCall] = listAdminUsersSpy.mock.calls
    expect(listAdminUsersCall?.[0]?.actor.subject).toBe('owner-user')
    expect(listAdminUsersCall?.[0]?.status).toBe('active')
    expect(listAdminUsersCall?.[0]?.tenantId).toBe('t_1')
    expect(listAdminUsersCall?.[0]?.role).toBe('admin')
    expect(listAdminUsersCall?.[0]?.search).toBe('adm')
    expect(listAdminUsersCall?.[0]?.limit).toBe(10)
    expect(listAdminUsersCall?.[0]?.cursor).toBe('cursor_0')

    const patchUserResponse = await context.request({
      method: 'PATCH',
      path: '/v1/admin/users/adm_1',
      body: {
        status: 'active',
        roles: ['admin'],
        tenant_ids: ['t_1']
      }
    })
    expect(patchUserResponse.status).toBe(200)
    expect(patchUserResponse.body).toMatchObject({
      identity_id: 'adm_1'
    })
    const [updateAdminUserCall] = updateAdminUserSpy.mock.calls
    expect(updateAdminUserCall?.[0]?.identityId).toBe('adm_1')
    expect(updateAdminUserCall?.[0]?.actor.subject).toBe('owner-user')
    expect(updateAdminUserCall?.[0]?.status).toBe('active')
    expect(updateAdminUserCall?.[0]?.roles).toEqual(['admin'])
    expect(updateAdminUserCall?.[0]?.tenantIds).toEqual(['t_1'])

    const listAccessRequestsResponse = await context.request({
      method: 'GET',
      path: '/v1/admin/access-requests?status=pending&tenant_id=t_1&role=admin&search=admin&limit=5&cursor=cursor_1'
    })
    expect(listAccessRequestsResponse.status).toBe(200)
    expect(listAccessRequestsResponse.body).toMatchObject({
      requests: [{request_id: 'aar_1'}],
      next_cursor: 'cursor_2'
    })
    const [listAdminAccessRequestsCall] = listAdminAccessRequestsSpy.mock.calls
    expect(listAdminAccessRequestsCall?.[0]?.actor.subject).toBe('owner-user')
    expect(listAdminAccessRequestsCall?.[0]?.status).toBe('pending')
    expect(listAdminAccessRequestsCall?.[0]?.tenantId).toBe('t_1')
    expect(listAdminAccessRequestsCall?.[0]?.role).toBe('admin')
    expect(listAdminAccessRequestsCall?.[0]?.search).toBe('admin')
    expect(listAdminAccessRequestsCall?.[0]?.limit).toBe(5)
    expect(listAdminAccessRequestsCall?.[0]?.cursor).toBe('cursor_1')

    const approveResponse = await context.request({
      method: 'POST',
      path: '/v1/admin/access-requests/aar_1/approve',
      body: {
        roles: ['admin'],
        tenant_ids: ['t_1'],
        reason: 'approved by owner'
      }
    })
    expect(approveResponse.status).toBe(200)
    expect(approveResponse.body).toMatchObject({
      request_id: 'aar_1',
      status: 'approved'
    })
    const [approveAdminAccessRequestCall] = approveAdminAccessRequestWithOverridesSpy.mock.calls
    expect(approveAdminAccessRequestCall?.[0]?.requestId).toBe('aar_1')
    expect(approveAdminAccessRequestCall?.[0]?.actor.subject).toBe('owner-user')
    expect(approveAdminAccessRequestCall?.[0]?.roles).toEqual(['admin'])
    expect(approveAdminAccessRequestCall?.[0]?.tenantIds).toEqual(['t_1'])
    expect(approveAdminAccessRequestCall?.[0]?.reason).toBe('approved by owner')

    const denyResponse = await context.request({
      method: 'POST',
      path: '/v1/admin/access-requests/aar_1/deny',
      body: {
        reason: 'request denied'
      }
    })
    expect(denyResponse.status).toBe(200)
    expect(denyResponse.body).toMatchObject({
      request_id: 'aar_1',
      status: 'denied'
    })
    const [denyAdminAccessRequestCall] = denyAdminAccessRequestSpy.mock.calls
    expect(denyAdminAccessRequestCall?.[0]?.requestId).toBe('aar_1')
    expect(denyAdminAccessRequestCall?.[0]?.actor.subject).toBe('owner-user')
    expect(denyAdminAccessRequestCall?.[0]?.reason).toBe('request denied')
  })

  it('forbids non-owner principals on admin user management routes', async () => {
    const context = await createContext()

    const response = await context.request({
      method: 'GET',
      path: '/v1/admin/users',
      token: ADMIN_TOKEN
    })
    expect(response.status).toBe(403)
    expect(response.body).toMatchObject({error: 'admin_forbidden'})
  })

  it('covers the main control-plane lifecycle routes', async () => {
    const context = await createContext()

    const authProviders = await context.request({
      method: 'GET',
      path: '/v1/admin/auth/providers',
      token: ''
    })
    expect(authProviders.status).toBe(200)
    expect(authProviders.body).toMatchObject({
      providers: [
        {provider: 'google', enabled: false},
        {provider: 'github', enabled: false}
      ]
    })

    const authSession = await context.request({
      method: 'GET',
      path: '/v1/admin/auth/session'
    })
    expect(authSession.status).toBe(200)
    expect(authSession.body).toMatchObject({
      authenticated: true,
      principal: {
        subject: 'owner-user',
        issuer: 'https://broker-admin.local/static',
        email: 'owner-user@local.invalid',
        roles: ['owner']
      }
    })

    const signupPolicyUnavailable = await context.request({
      method: 'GET',
      path: '/v1/admin/auth/signup-policy'
    })
    expect(signupPolicyUnavailable.status).toBe(503)
    expect(signupPolicyUnavailable.body).toMatchObject({error: 'db_unavailable'})

    const createTenant = await context.request({
      method: 'POST',
      path: '/v1/tenants',
      body: {name: 'Tenant Lifecycle'}
    })
    expect(createTenant.status).toBe(201)
    const tenantId = (createTenant.body as {tenant_id: string}).tenant_id
    expect(tenantId).toMatch(/^t_/u)

    const listTenants = await context.request({method: 'GET', path: '/v1/tenants'})
    expect(listTenants.status).toBe(200)
    expect((listTenants.body as {tenants: Array<{tenant_id: string}>}).tenants).toHaveLength(1)

    const createTemplate = await context.request({
      method: 'POST',
      path: '/v1/templates',
      body: makeTemplate()
    })
    expect(createTemplate.status).toBe(201)

    const listTemplates = await context.request({method: 'GET', path: '/v1/templates'})
    expect(listTemplates.status).toBe(200)
    expect((listTemplates.body as {templates: unknown[]}).templates).toHaveLength(1)

    const getTemplateVersion = await context.request({
      method: 'GET',
      path: '/v1/templates/tpl_openai_safe/versions/1'
    })
    expect(getTemplateVersion.status).toBe(200)

    const createWorkload = await context.request({
      method: 'POST',
      path: `/v1/tenants/${tenantId}/workloads`,
      body: {
        name: 'workload-lifecycle',
        enrollment_mode: 'broker_ca',
        ip_allowlist: ['203.0.113.10']
      }
    })
    expect(createWorkload.status).toBe(201)
    const workloadBody = createWorkload.body as {workload_id: string; enrollment_token: string}
    expect(workloadBody.workload_id).toMatch(/^w_/u)
    expect(workloadBody.enrollment_token.length).toBeGreaterThan(10)

    const issueEnrollmentTokenBeforeEnrollment = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enrollment-token`,
      body: {
        rotation_mode: 'if_absent'
      }
    })
    expect(issueEnrollmentTokenBeforeEnrollment.status).toBe(200)
    const issuedTokenBeforeEnrollment = issueEnrollmentTokenBeforeEnrollment.body as {enrollment_token: string}
    expect(issuedTokenBeforeEnrollment.enrollment_token.length).toBeGreaterThan(10)

    const listWorkloads = await context.request({
      method: 'GET',
      path: `/v1/tenants/${tenantId}/workloads`
    })
    expect(listWorkloads.status).toBe(200)

    const updateWorkload = await context.request({
      method: 'PATCH',
      path: `/v1/workloads/${workloadBody.workload_id}`,
      body: {
        enabled: false,
        ip_allowlist: ['203.0.113.11']
      }
    })
    expect(updateWorkload.status).toBe(200)
    expect(updateWorkload.body).toMatchObject({enabled: false})

    vi.spyOn(
      context.dependencyBridge,
      'validateEnrollmentCsrWithAuthPackage'
    ).mockResolvedValue(undefined)
    vi.spyOn(
      context.dependencyBridge,
      'issueWorkloadCertificateWithAuthPackage'
    ).mockResolvedValue({
      clientCertPem: '-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----',
      caChainPem: TEST_CA_PEM,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString()
    })

    const enrollWorkload = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enroll`,
      body: {
        enrollment_token: issuedTokenBeforeEnrollment.enrollment_token,
        csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----',
        requested_ttl_seconds: 300
      }
    })
    expect(enrollWorkload.status).toBe(200)
    const enrollmentPayload = enrollWorkload.body as {client_cert_pem: string}
    expect(typeof enrollmentPayload.client_cert_pem).toBe('string')
    expect(enrollmentPayload.client_cert_pem).toContain('BEGIN CERTIFICATE')

    const issueEnrollmentTokenRequiresConfirmation = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enrollment-token`,
      body: {
        rotation_mode: 'if_absent'
      }
    })
    expect(issueEnrollmentTokenRequiresConfirmation.status).toBe(409)
    expect(issueEnrollmentTokenRequiresConfirmation.body).toMatchObject({
      error: 'enrollment_token_rotation_confirmation_required'
    })

    const issueEnrollmentTokenForced = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enrollment-token`,
      body: {
        rotation_mode: 'always'
      }
    })
    expect(issueEnrollmentTokenForced.status).toBe(200)
    const issuedTokenPayload = issueEnrollmentTokenForced.body as {enrollment_token: string; expires_at: string}
    expect(issuedTokenPayload.enrollment_token.length).toBeGreaterThan(10)
    expect(new Date(issuedTokenPayload.expires_at).toISOString()).toBe(issuedTokenPayload.expires_at)

    const createIntegration = await context.request({
      method: 'POST',
      path: `/v1/tenants/${tenantId}/integrations`,
      body: {
        provider: 'openai',
        name: 'openai-lifecycle',
        template_id: 'tpl_openai_safe',
        secret_material: {type: 'api_key', value: 'sk-live-123'}
      }
    })
    expect(createIntegration.status).toBe(201)
    const integrationId = (createIntegration.body as {integration_id: string}).integration_id

    const listIntegrations = await context.request({
      method: 'GET',
      path: `/v1/tenants/${tenantId}/integrations`
    })
    expect(listIntegrations.status).toBe(200)

    const patchIntegration = await context.request({
      method: 'PATCH',
      path: `/v1/integrations/${integrationId}`,
      body: {enabled: false}
    })
    expect(patchIntegration.status).toBe(200)
    expect(patchIntegration.body).toMatchObject({enabled: false})

    const createPolicy = await context.request({
      method: 'POST',
      path: '/v1/policies',
      body: {
        rule_type: 'allow',
        scope: {
          tenant_id: tenantId,
          workload_id: workloadBody.workload_id,
          integration_id: integrationId,
          template_id: 'tpl_openai_safe',
          template_version: 1,
          action_group: 'openai_responses',
          method: 'POST',
          host: 'api.openai.com',
          query_keys: []
        },
        rate_limit: null
      }
    })
    expect(createPolicy.status).toBe(201)
    const policyId = (createPolicy.body as {policy_id: string}).policy_id

    const listPolicies = await context.request({method: 'GET', path: '/v1/policies'})
    expect(listPolicies.status).toBe(200)
    expect((listPolicies.body as {policies: unknown[]}).policies).toHaveLength(1)

    const deletePolicy = await context.request({
      method: 'DELETE',
      path: `/v1/policies/${policyId}`
    })
    expect(deletePolicy.status).toBe(204)

    const listApprovals = await context.request({method: 'GET', path: '/v1/approvals'})
    expect(listApprovals.status).toBe(200)

    const listAudit = await context.request({method: 'GET', path: '/v1/audit/events'})
    expect(listAudit.status).toBe(200)

    const manifest = await context.request({method: 'GET', path: '/v1/keys/manifest'})
    expect(manifest.status).toBe(200)
    expect(manifest.headers.etag).toBeTruthy()
  })

  it('invalidates previous active enrollment tokens when rotating for the same workload', async () => {
    const context = await createContext()

    const createTenant = await context.request({
      method: 'POST',
      path: '/v1/tenants',
      body: {name: 'Tenant Rotation'}
    })
    const tenantId = (createTenant.body as {tenant_id: string}).tenant_id

    const createWorkload = await context.request({
      method: 'POST',
      path: `/v1/tenants/${tenantId}/workloads`,
      body: {
        name: 'workload-rotation',
        enrollment_mode: 'broker_ca'
      }
    })
    const workloadBody = createWorkload.body as {workload_id: string}

    vi.spyOn(context.dependencyBridge, 'validateEnrollmentCsrWithAuthPackage').mockResolvedValue(undefined)
    vi.spyOn(context.dependencyBridge, 'issueWorkloadCertificateWithAuthPackage').mockResolvedValue({
      clientCertPem: '-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----',
      caChainPem: TEST_CA_PEM,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString()
    })

    const firstTokenResponse = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enrollment-token`,
      body: {
        rotation_mode: 'always'
      }
    })
    expect(firstTokenResponse.status).toBe(200)
    const firstToken = (firstTokenResponse.body as {enrollment_token: string}).enrollment_token

    const secondTokenResponse = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enrollment-token`,
      body: {
        rotation_mode: 'always'
      }
    })
    expect(secondTokenResponse.status).toBe(200)
    const secondToken = (secondTokenResponse.body as {enrollment_token: string}).enrollment_token
    expect(secondToken).not.toBe(firstToken)

    const enrollWithInvalidatedToken = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enroll`,
      body: {
        enrollment_token: firstToken,
        csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----',
        requested_ttl_seconds: 300
      }
    })
    expect(enrollWithInvalidatedToken.status).toBe(409)
    expect(enrollWithInvalidatedToken.body).toMatchObject({
      error: 'enrollment_token_used'
    })

    const enrollWithLatestToken = await context.request({
      method: 'POST',
      path: `/v1/workloads/${workloadBody.workload_id}/enroll`,
      body: {
        enrollment_token: secondToken,
        csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----',
        requested_ttl_seconds: 300
      }
    })
    expect(enrollWithLatestToken.status).toBe(200)
  })

  it('enforces role and tenant filter restrictions for non-owner principals', async () => {
    const context = await createContext()

    const createTenantAsAdmin = await context.request({
      method: 'POST',
      path: '/v1/tenants',
      token: ADMIN_TOKEN,
      body: {name: 'Forbidden Tenant'}
    })
    expect(createTenantAsAdmin.status).toBe(400)
    expect(createTenantAsAdmin.body).toMatchObject({error: 'tenant_create_forbidden'})

    const auditMissingTenantFilter = await context.request({
      method: 'GET',
      path: '/v1/audit/events',
      token: ADMIN_TOKEN
    })
    expect(auditMissingTenantFilter.status).toBe(400)
    expect(auditMissingTenantFilter.body).toMatchObject({error: 'tenant_filter_required'})

    const auditForbiddenTenant = await context.request({
      method: 'GET',
      path: '/v1/audit/events?tenant_id=t_denied',
      token: ADMIN_TOKEN
    })
    expect(auditForbiddenTenant.status).toBe(400)
    expect(auditForbiddenTenant.body).toMatchObject({error: 'tenant_filter_forbidden'})
  })

  it('returns deterministic validation and routing errors', async () => {
    const context = await createContext()

    const invalidHostHeader = await context.request({
      method: 'GET',
      path: '/v1/tenants',
      headers: {
        host: 'invalid host header'
      }
    })
    expect(invalidHostHeader.status).toBe(400)
    expect(invalidHostHeader.body).toMatchObject({error: 'request_url_invalid'})

    const invalidTemplateVersion = await context.request({
      method: 'GET',
      path: '/v1/templates/tpl_openai_safe/versions/not-an-int'
    })
    expect(invalidTemplateVersion.status).toBe(400)
    expect(invalidTemplateVersion.body).toMatchObject({error: 'template_version_invalid'})

    const invalidEncodedPath = await context.request({
      method: 'GET',
      path: '/v1/templates/%E0%A4%A/versions/1'
    })
    expect(invalidEncodedPath.status).toBe(400)
    expect(invalidEncodedPath.body).toMatchObject({error: 'path_param_invalid'})

    const invalidJsonBody = await context.request({
      method: 'POST',
      path: '/v1/templates',
      rawBody: '{"broken":',
      headers: {'content-type': 'application/json'}
    })
    expect(invalidJsonBody.status).toBe(400)
    expect(invalidJsonBody.body).toMatchObject({error: 'request_body_invalid_json'})

    const invalidTimeRange = await context.request({
      method: 'GET',
      path: '/v1/audit/events?time_min=2026-01-02T00:00:00.000Z&time_max=2026-01-01T00:00:00.000Z'
    })
    expect(invalidTimeRange.status).toBe(400)
    expect(invalidTimeRange.body).toMatchObject({error: 'time_range_invalid'})

    const routeNotFound = await context.request({
      method: 'GET',
      path: '/v1/not-found'
    })
    expect(routeNotFound.status).toBe(404)
    expect(routeNotFound.body).toMatchObject({error: 'route_not_found'})
  })

  it('supports approval decision routes and keeps mutation scoped by tenant', async () => {
    const statePath = await writeStateFixture(buildApprovalFixtureState())
    const context = await createContext({statePath})

    const approve = await context.request({
      method: 'POST',
      path: '/v1/approvals/appr_approve/approve',
      body: {mode: 'once'}
    })
    expect(approve.status).toBe(200)
    expect(approve.body).toMatchObject({status: 'approved'})

    const deny = await context.request({
      method: 'POST',
      path: '/v1/approvals/appr_deny/deny'
    })
    expect(deny.status).toBe(200)
    expect(deny.body).toMatchObject({status: 'denied'})

    const policies = await context.request({method: 'GET', path: '/v1/policies'})
    expect(policies.status).toBe(200)
    expect((policies.body as {policies: unknown[]}).policies).toHaveLength(1)

    const secondStatePath = await writeStateFixture(buildApprovalFixtureState())
    const limitedContext = await createContext({statePath: secondStatePath})
    const forbiddenApproval = await limitedContext.request({
      method: 'POST',
      path: '/v1/approvals/appr_approve/approve',
      token: LIMITED_ADMIN_TOKEN,
      body: {mode: 'once'}
    })
    expect(forbiddenApproval.status).toBe(403)
    expect(forbiddenApproval.body).toMatchObject({error: 'admin_tenant_forbidden'})

    const approvalAfterForbidden = await limitedContext.repository.getApproval({
      approvalId: 'appr_approve'
    })
    expect(approvalAfterForbidden.status).toBe('pending')
  })

  it('maps unexpected exceptions to internal_error responses', async () => {
    const context = await createContext()
    vi.spyOn(context.repository, 'listTenants').mockImplementation(() => {
      throw new Error('unexpected repository failure')
    })

    const response = await context.request({method: 'GET', path: '/v1/tenants'})
    expect(response.status).toBe(500)
    expect(response.body).toMatchObject({error: 'internal_error'})
  })
})
