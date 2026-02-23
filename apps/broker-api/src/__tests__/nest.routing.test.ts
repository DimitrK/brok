import {afterEach, describe, expect, it} from 'vitest'

import {createBrokerApiApp} from '../app'
import type {ServiceConfig} from '../config'

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
})

let activeApp: Awaited<ReturnType<typeof createBrokerApiApp>> | null = null

afterEach(async () => {
  if (!activeApp) {
    return
  }

  await activeApp.stop()
  activeApp = null
})

const startAppOrSkip = async () => {
  const app = await createBrokerApiApp({config: makeConfig()})
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
  it('returns broker route_not_found payload for unsupported routes', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const response = await fetch(`${baseUrl}/unsupported-route`)
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: 'route_not_found'
    })
  })

  it('returns broker route_not_found payload for method mismatch on known path', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const response = await fetch(`${baseUrl}/v1/session`, {
      method: 'GET'
    })
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: 'route_not_found'
    })
  })

  it('routes protected endpoints through broker handler semantics', async () => {
    const baseUrl = await startAppOrSkip()
    if (!baseUrl) {
      return
    }

    const checks: Array<{
      method: 'GET' | 'POST'
      path: string
      body?: unknown
    }> = [
      {method: 'GET', path: '/v1/keys/manifest'},
      {method: 'POST', path: '/v1/session', body: {requested_ttl_seconds: 900, scopes: ['execute']}},
      {method: 'POST', path: '/v1/execute'},
      {method: 'GET', path: '/v1/workloads/w_test/manifest'}
    ]

    for (const check of checks) {
      const response = await fetch(`${baseUrl}${check.path}`, {
        method: check.method,
        ...(check.body
          ? {
              headers: {
                'content-type': 'application/json'
              },
              body: JSON.stringify(check.body)
            }
          : {})
      })

      expect(response.status).toBe(401)
      await expect(response.json()).resolves.toMatchObject({
        error: 'mtls_required'
      })
    }
  })
})
