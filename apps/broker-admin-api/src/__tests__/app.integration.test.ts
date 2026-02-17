import {afterEach, describe, expect, it} from 'vitest'

import {createAdminApiApp} from '../app'
import type {ServiceConfig} from '../config'

const makeConfig = (): ServiceConfig => ({
  nodeEnv: 'test',
  host: '127.0.0.1',
  port: 0,
  maxBodyBytes: 1024 * 1024,
  secretKey: Buffer.alloc(32, 9),
  secretKeyId: 'kid-app-integration-test',
  auth: {
    mode: 'static',
    tokens: [
      {
        token: 'owner-token-0123456789abcdef',
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
    redisKeyPrefix: 'broker-admin-api:test'
  }
})

let activeApp: Awaited<ReturnType<typeof createAdminApiApp>> | null = null
const runTcpIntegrationTests = process.env.BROKER_ADMIN_API_RUN_TCP_INTEGRATION === '1'

afterEach(async () => {
  if (!activeApp) {
    return
  }

  await activeApp.stop()
  activeApp = null
})

describe('app integration', () => {
  it.skipIf(!runTcpIntegrationTests)(
    'starts listening and serves health checks over TCP',
    async () => {
      const app = await createAdminApiApp({config: makeConfig()})
      activeApp = app
      await app.start()

      const address = app.server.address()
      if (!address || typeof address === 'string') {
        throw new Error('expected TCP address from runtime server')
      }

      const response = await fetch(`http://127.0.0.1:${String(address.port)}/healthz`)
      expect(response.status).toBe(200)
      expect(await response.json()).toEqual({status: 'ok'})
    }
  )

  it.skipIf(!runTcpIntegrationTests)(
    'allows the local client origin via CORS when not in production',
    async () => {
      const app = await createAdminApiApp({config: makeConfig()})
      activeApp = app
      await app.start()

      const address = app.server.address()
      if (!address || typeof address === 'string') {
        throw new Error('expected TCP address from runtime server')
      }

      const response = await fetch(`http://127.0.0.1:${String(address.port)}/healthz`, {
        headers: {
          Origin: 'http://localhost:4173'
        }
      })
      expect(response.status).toBe(200)
      expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:4173')
    }
  )
})
