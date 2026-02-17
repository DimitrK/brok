import {afterEach, describe, expect, it, vi} from 'vitest'

import type {ServiceConfig} from '../config'

const makeConfig = (): ServiceConfig => ({
  nodeEnv: 'test',
  host: '127.0.0.1',
  port: 0,
  maxBodyBytes: 1024 * 1024,
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

describe('process infrastructure', () => {
  it('returns disabled infrastructure when disabled in config', async () => {
    const {createProcessInfrastructure} = await import('../infrastructure')

    const infrastructure = await createProcessInfrastructure({
      config: makeConfig()
    })

    expect(infrastructure.enabled).toBe(false)
    expect(infrastructure.prisma).toBeNull()
    expect(infrastructure.redis).toBeNull()
    expect(infrastructure.redisKeyPrefix).toBe('broker-admin-api:test')
    await expect(infrastructure.withTransaction(() => Promise.resolve('no-op'))).rejects.toThrow(
      'Database transaction requested while infrastructure is disabled'
    )
    await expect(infrastructure.close()).resolves.toBeUndefined()
  })

  it('fails closed when required infrastructure urls are missing', async () => {
    const {createProcessInfrastructure} = await import('../infrastructure')

    await expect(
      createProcessInfrastructure({
        config: {
          ...makeConfig(),
          infrastructure: {
            ...makeConfig().infrastructure,
            enabled: true
          }
        }
      })
    ).rejects.toThrow(
      'Infrastructure is enabled but BROKER_ADMIN_API_DATABASE_URL or BROKER_ADMIN_API_REDIS_URL is missing'
    )
  })

  it('initializes and closes prisma/redis clients exactly once per app runtime', async () => {
    const prismaClient = {
      $connect: vi.fn().mockResolvedValue(undefined),
      $disconnect: vi.fn().mockResolvedValue(undefined),
      $transaction: vi.fn((operation: (tx: {tx: true}) => Promise<string>) => operation({tx: true}))
    }
    const PrismaClient = vi.fn(() => prismaClient)

    const redisClient = {
      connect: vi.fn().mockResolvedValue(undefined),
      quit: vi.fn().mockResolvedValue(undefined)
    }
    const createClient = vi.fn(() => redisClient)

    vi.doMock('@prisma/client', () => ({
      PrismaClient
    }))
    vi.doMock('redis', () => ({
      createClient
    }))

    const {createProcessInfrastructure} = await import('../infrastructure')
    const infrastructure = await createProcessInfrastructure({
      config: {
        ...makeConfig(),
        infrastructure: {
          enabled: true,
          databaseUrl: 'postgresql://broker:broker@127.0.0.1:5432/broker',
          redisUrl: 'redis://127.0.0.1:6379/0',
          redisConnectTimeoutMs: 3_000,
          redisKeyPrefix: 'broker-admin-api:control-plane'
        }
      }
    })

    expect(infrastructure.enabled).toBe(true)
    expect(PrismaClient).toHaveBeenCalledWith({
      datasources: {
        db: {
          url: 'postgresql://broker:broker@127.0.0.1:5432/broker'
        }
      }
    })
    expect(createClient).toHaveBeenCalledWith({
      url: 'redis://127.0.0.1:6379/0',
      socket: {
        connectTimeout: 3_000
      }
    })

    const transactionResult = await infrastructure.withTransaction(tx => {
      expect(tx).toEqual({tx: true})
      return Promise.resolve('ok')
    })

    expect(transactionResult).toBe('ok')
    expect(prismaClient.$transaction).toHaveBeenCalledTimes(1)

    await infrastructure.close()
    expect(prismaClient.$disconnect).toHaveBeenCalledTimes(1)
    expect(redisClient.quit).toHaveBeenCalledTimes(1)
  })

  it('cleans up partially initialized clients when startup fails', async () => {
    const startupError = new Error('redis unavailable')
    const prismaClient = {
      $connect: vi.fn().mockResolvedValue(undefined),
      $disconnect: vi.fn().mockResolvedValue(undefined),
      $transaction: vi.fn()
    }
    const PrismaClient = vi.fn(() => prismaClient)

    const redisClient = {
      connect: vi.fn().mockRejectedValue(startupError),
      quit: vi.fn().mockResolvedValue(undefined)
    }

    vi.doMock('@prisma/client', () => ({
      PrismaClient
    }))
    vi.doMock('redis', () => ({
      createClient: vi.fn(() => redisClient)
    }))

    const {createProcessInfrastructure} = await import('../infrastructure')

    await expect(
      createProcessInfrastructure({
        config: {
          ...makeConfig(),
          infrastructure: {
            enabled: true,
            databaseUrl: 'postgresql://broker:broker@127.0.0.1:5432/broker',
            redisUrl: 'redis://127.0.0.1:6379/0',
            redisConnectTimeoutMs: 3_000,
            redisKeyPrefix: 'broker-admin-api:control-plane'
          }
        }
      })
    ).rejects.toBe(startupError)

    expect(prismaClient.$disconnect).toHaveBeenCalledTimes(1)
    expect(redisClient.quit).toHaveBeenCalledTimes(1)
  })
})
