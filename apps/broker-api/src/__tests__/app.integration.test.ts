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

describe('broker api app integration', () => {
  it('starts and serves health checks', async () => {
    const app = await createBrokerApiApp({config: makeConfig()})
    activeApp = app
    try {
      await app.start()
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EPERM') {
        // Some CI sandboxes disallow binding sockets; startup path is still covered by entrypoint tests.
        return
      }
      throw error
    }

    const address = app.server.address()
    if (!address || typeof address === 'string') {
      throw new Error('expected tcp address')
    }

    const response = await fetch(`http://127.0.0.1:${String(address.port)}/healthz`)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({status: 'ok'})
  })

  it('allows the local client origin via CORS when not in production', async () => {
    const app = await createBrokerApiApp({config: makeConfig()})
    activeApp = app
    try {
      await app.start()
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EPERM') {
        return
      }
      throw error
    }

    const address = app.server.address()
    if (!address || typeof address === 'string') {
      throw new Error('expected tcp address')
    }

    const response = await fetch(`http://127.0.0.1:${String(address.port)}/healthz`, {
      headers: {
        Origin: 'http://localhost:4173'
      }
    })

    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:4173')
  })
})
