import {beforeEach, describe, expect, it, vi} from 'vitest'

import type {ServiceConfig} from '../config'

const prismaMocks = vi.hoisted(() => ({
  connect: vi.fn<() => Promise<void>>(),
  disconnect: vi.fn<() => Promise<void>>(),
  transaction: vi.fn(<T>(operation: (tx: unknown) => Promise<T>) => operation({tx: true}))
}))

const redisMocks = vi.hoisted(() => ({
  connect: vi.fn<() => Promise<void>>(),
  quit: vi.fn<() => Promise<void>>(),
  createClient: vi.fn()
}))

vi.mock('@prisma/client', () => {
  class PrismaClient {
    public readonly $connect = prismaMocks.connect
    public readonly $disconnect = prismaMocks.disconnect
    public readonly $transaction = prismaMocks.transaction

    public constructor(_options?: unknown) {
      void _options
    }
  }

  return {PrismaClient}
})

vi.mock('redis', () => ({
  createClient: redisMocks.createClient
}))

import {createProcessInfrastructure} from '../infrastructure'

const makeEnabledConfig = (): ServiceConfig => ({
  nodeEnv: 'development',
  host: '127.0.0.1',
  port: 8081,
  publicBaseUrl: 'https://broker.example',
  maxBodyBytes: 1024 * 1024,
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
    enabled: true,
    databaseUrl: 'postgresql://broker:broker@127.0.0.1:5432/broker',
    redisUrl: 'redis://127.0.0.1:6379',
    redisConnectTimeoutMs: 2_000,
    redisKeyPrefix: 'broker-api:test'
  },
  secretKey: Buffer.alloc(32, 'a'),
  secretKeyId: 'v1'
})

beforeEach(() => {
  prismaMocks.connect.mockReset()
  prismaMocks.disconnect.mockReset()
  prismaMocks.transaction.mockReset()
  redisMocks.connect.mockReset()
  redisMocks.quit.mockReset()
  redisMocks.createClient.mockReset()

  prismaMocks.connect.mockResolvedValue()
  prismaMocks.disconnect.mockResolvedValue()
  prismaMocks.transaction.mockImplementation(<T>(operation: (tx: unknown) => Promise<T>) => operation({tx: true}))
  redisMocks.connect.mockResolvedValue()
  redisMocks.quit.mockResolvedValue()
  redisMocks.createClient.mockReturnValue({
    connect: redisMocks.connect,
    quit: redisMocks.quit
  })
})

describe('process infrastructure (enabled)', () => {
  it('creates shared prisma/redis infrastructure and transaction wrapper', async () => {
    const infrastructure = await createProcessInfrastructure({
      config: makeEnabledConfig()
    })

    expect(infrastructure.enabled).toBe(true)
    expect(infrastructure.prisma).not.toBeNull()
    expect(infrastructure.redis).not.toBeNull()
    expect(infrastructure.dbRepositories).not.toBeNull()
    expect(redisMocks.createClient).toHaveBeenCalledTimes(1)
    expect(prismaMocks.connect).toHaveBeenCalledTimes(1)
    expect(redisMocks.connect).toHaveBeenCalledTimes(1)

    const txResult = await infrastructure.withTransaction(tx => Promise.resolve(tx))

    expect(txResult).toEqual({tx: true})
    expect(prismaMocks.transaction).toHaveBeenCalledTimes(1)

    await expect(infrastructure.close()).resolves.toBeUndefined()
    expect(prismaMocks.disconnect).toHaveBeenCalledTimes(1)
    expect(redisMocks.quit).toHaveBeenCalledTimes(1)
  })

  it('rejects when enabled infrastructure is missing required urls', async () => {
    const config = makeEnabledConfig()
    config.infrastructure = {
      ...config.infrastructure,
      databaseUrl: undefined
    }

    await expect(
      createProcessInfrastructure({
        config
      })
    ).rejects.toThrow('Infrastructure is enabled but BROKER_API_DATABASE_URL or BROKER_API_REDIS_URL is missing')
  })

  it('closes clients when connect fails during startup', async () => {
    const startupFailure = new Error('db down')
    prismaMocks.connect.mockRejectedValueOnce(startupFailure)

    await expect(
      createProcessInfrastructure({
        config: makeEnabledConfig()
      })
    ).rejects.toThrow('db down')

    expect(prismaMocks.disconnect).toHaveBeenCalledTimes(1)
    expect(redisMocks.quit).toHaveBeenCalledTimes(1)
  })
})
