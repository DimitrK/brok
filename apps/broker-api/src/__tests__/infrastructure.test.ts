import {describe, expect, it} from 'vitest'

import {createProcessInfrastructure} from '../infrastructure'
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
  secretKey: Buffer.alloc(32, 'a'),
  secretKeyId: 'v1'
})

describe('process infrastructure', () => {
  it('returns disabled infrastructure in test mode and blocks transactions', async () => {
    const infrastructure = await createProcessInfrastructure({
      config: makeConfig()
    })

    expect(infrastructure.enabled).toBe(false)
    expect(infrastructure.prisma).toBeNull()
    expect(infrastructure.redis).toBeNull()
    expect(infrastructure.dbRepositories).toBeNull()
    expect(infrastructure.redisKeyPrefix).toBe('broker-api:test')
    await expect(infrastructure.withTransaction(() => Promise.resolve('no-op'))).rejects.toThrow(
      'Database transaction requested while infrastructure is disabled'
    )

    await expect(infrastructure.close()).resolves.toBeUndefined()
  })
})
