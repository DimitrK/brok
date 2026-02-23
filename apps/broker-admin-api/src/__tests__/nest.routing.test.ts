import {afterEach, describe, expect, it} from 'vitest'
import {OpenApiTenantCreateResponseSchema, OpenApiWorkloadCreateResponseSchema} from '@broker-interceptor/schemas'

import {createAdminApiApp} from '../app'
import type {ServiceConfig} from '../config'

const OWNER_TOKEN = 'owner-token-0123456789abcdef'

const makeConfig = (): ServiceConfig => ({
  nodeEnv: 'test',
  host: '127.0.0.1',
  port: 0,
  maxBodyBytes: 1024 * 1024,
  logging: {
    level: 'silent',
    redactExtraKeys: []
  },
  secretKey: Buffer.alloc(32, 9),
  secretKeyId: 'kid-nest-routing-test',
  auth: {
    mode: 'static',
    tokens: [
      {
        token: OWNER_TOKEN,
        subject: 'owner-user',
        roles: ['owner']
      }
    ]
  },
  enrollmentTokenTtlSeconds: 600,
  clientCertTtlSecondsMax: 3600,
  certificateIssuer: {
    mode: 'mock',
    mtlsCaPem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
  },
  manifestKeys: {keys: []},
  corsAllowedOrigins: ['http://localhost:4173'],
  infrastructure: {
    enabled: false,
    redisConnectTimeoutMs: 2_000,
    redisKeyPrefix: 'broker-admin-api:nest-routing-test'
  }
})

let activeApp: Awaited<ReturnType<typeof createAdminApiApp>> | null = null

afterEach(async () => {
  if (!activeApp) {
    return
  }

  await activeApp.stop()
  activeApp = null
})

const startAppOrSkip = async () => {
  const app = await createAdminApiApp({config: makeConfig()})
  activeApp = app
  try {
    await app.start()
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EPERM') {
      return null
    }
    throw error
  }

  const address = app.server.address()
  if (!address || typeof address === 'string') {
    throw new Error('expected tcp address')
  }

  return `http://127.0.0.1:${String(address.port)}`
}

describe('nest routing', () => {
  it('routes public admin-auth providers endpoint through Nest controller mapping', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const response = await fetch(`${baseUrl}/v1/admin/auth/providers`)
    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({
      providers: [
        {provider: 'google', enabled: false},
        {provider: 'github', enabled: false}
      ]
    })
  })

  it('serves healthz without authentication', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const response = await fetch(`${baseUrl}/healthz`)
    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toEqual({status: 'ok'})
  })

  it('returns route_not_found for unsupported routes when authenticated', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const response = await fetch(`${baseUrl}/unsupported-route`, {
      headers: {
        authorization: `Bearer ${OWNER_TOKEN}`
      }
    })
    expect(response.status).toBe(404)
    await expect(response.json()).resolves.toMatchObject({
      error: 'route_not_found'
    })
  })

  it('returns route_not_found for method mismatch on known path', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const response = await fetch(`${baseUrl}/v1/admin/auth/logout`, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${OWNER_TOKEN}`
      }
    })
    expect(response.status).toBe(404)
    await expect(response.json()).resolves.toMatchObject({
      error: 'route_not_found'
    })
  })

  it('routes logout through Nest controller mapping', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const response = await fetch(`${baseUrl}/v1/admin/auth/logout`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${OWNER_TOKEN}`
      }
    })
    expect(response.status).toBe(204)
    expect(await response.text()).toBe('')
  })

  it('routes protected endpoints through existing auth semantics', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const protectedChecks: Array<{
      method: 'GET' | 'POST'
      path: string
    }> = [
      {method: 'GET', path: '/v1/tenants'},
      {method: 'POST', path: '/v1/admin/auth/logout'},
      {method: 'GET', path: '/v1/keys/manifest'}
    ]

    for (const check of protectedChecks) {
      const response = await fetch(`${baseUrl}${check.path}`, {
        method: check.method
      })
      expect(response.status).toBe(401)
      await expect(response.json()).resolves.toMatchObject({
        error: 'admin_auth_missing'
      })
    }
  })

  it('routes tenant and workload parameterized paths through Nest controllers', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const createTenant = await fetch(`${baseUrl}/v1/tenants`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${OWNER_TOKEN}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify({name: 'nest-routing-tenant'})
    })
    expect(createTenant.status).toBe(201)
    const createTenantBody = OpenApiTenantCreateResponseSchema.parse(await createTenant.json())
    expect(createTenantBody.tenant_id).toMatch(/^t_/u)

    const createWorkload = await fetch(`${baseUrl}/v1/tenants/${createTenantBody.tenant_id}/workloads`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${OWNER_TOKEN}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        name: 'nest-routing-workload',
        enrollment_mode: 'broker_ca'
      })
    })
    expect(createWorkload.status).toBe(201)
    const createWorkloadBody = OpenApiWorkloadCreateResponseSchema.parse(await createWorkload.json())
    expect(createWorkloadBody.workload_id).toMatch(/^w_/u)
    expect(createWorkloadBody.enrollment_token.length).toBeGreaterThan(10)
    expect(createWorkloadBody.mtls_ca_pem).toContain('BEGIN CERTIFICATE')
  })
})
