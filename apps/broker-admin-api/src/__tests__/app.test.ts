import {afterEach, describe, expect, it, vi} from 'vitest'

import type {ServiceConfig} from '../config'

const makeConfig = (): ServiceConfig => ({
  nodeEnv: 'test',
  host: '127.0.0.1',
  port: 0,
  maxBodyBytes: 1024 * 1024,
  logging: {
    level: 'silent',
    redactExtraKeys: []
  },
  secretKey: Buffer.alloc(32, 5),
  secretKeyId: 'kid-app-test',
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
  infrastructure: {
    enabled: false,
    redisConnectTimeoutMs: 2_000,
    redisKeyPrefix: 'broker-admin-api:test'
  }
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.resetModules()
})

describe('admin api app runtime wiring', () => {
  it('creates nest runtime controls and closes process infrastructure on stop', async () => {
    const fakeServer = {kind: 'server'}
    const fakeNestApp = {
      init: vi.fn().mockResolvedValue(undefined),
      getHttpServer: vi.fn().mockReturnValue(fakeServer),
      listen: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined)
    }
    const nestFactoryCreate = vi.fn().mockResolvedValue(fakeNestApp)
    const infrastructure = {
      enabled: false,
      prisma: null,
      redis: null,
      redisKeyPrefix: 'broker-admin-api:test',
      withTransaction: vi.fn(),
      close: vi.fn().mockResolvedValue(undefined)
    }
    const createProcessInfrastructure = vi.fn().mockResolvedValue(infrastructure)

    vi.doMock('@nestjs/core', () => ({
      NestFactory: {
        create: nestFactoryCreate
      }
    }))
    vi.doMock('../infrastructure', () => ({
      createProcessInfrastructure
    }))

    const {createAdminApiApp} = await import('../app')
    const app = await createAdminApiApp({config: makeConfig()})

    expect(createProcessInfrastructure).toHaveBeenCalledTimes(1)
    expect(nestFactoryCreate).toHaveBeenCalledTimes(1)
    expect(app.server).toBe(fakeServer)
    expect(app.infrastructure).toBe(infrastructure)

    await app.start()
    expect(fakeNestApp.listen).toHaveBeenCalledWith(0, '127.0.0.1')

    await app.stop()
    expect(fakeNestApp.close).toHaveBeenCalledTimes(1)
    expect(infrastructure.close).toHaveBeenCalledTimes(1)
  })

  it('closes process infrastructure when nest bootstrap fails', async () => {
    const startupError = new Error('nest bootstrap failed')
    const infrastructure = {
      enabled: false,
      prisma: null,
      redis: null,
      redisKeyPrefix: 'broker-admin-api:test',
      withTransaction: vi.fn(),
      close: vi.fn().mockResolvedValue(undefined)
    }

    vi.doMock('@nestjs/core', () => ({
      NestFactory: {
        create: vi.fn().mockRejectedValue(startupError)
      }
    }))
    vi.doMock('../infrastructure', () => ({
      createProcessInfrastructure: vi.fn().mockResolvedValue(infrastructure)
    }))

    const {createAdminApiApp} = await import('../app')
    await expect(createAdminApiApp({config: makeConfig()})).rejects.toBe(startupError)
    expect(infrastructure.close).toHaveBeenCalledTimes(1)
  })
})
