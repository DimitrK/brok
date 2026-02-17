import {PrismaClient, type Prisma} from '@prisma/client'
import {createClient} from 'redis'

import type {ServiceConfig} from './config'

type WithTransaction = <T>(operation: (tx: Prisma.TransactionClient) => Promise<T>) => Promise<T>
export type AdminRedisClient = ReturnType<typeof createClient>

export type ProcessInfrastructure = {
  enabled: boolean
  prisma: PrismaClient | null
  redis: AdminRedisClient | null
  redisKeyPrefix: string
  withTransaction: WithTransaction
  close: () => Promise<void>
}

const createDisabledInfrastructure = ({
  redisKeyPrefix
}: {
  redisKeyPrefix: string
}): ProcessInfrastructure => ({
  enabled: false,
  prisma: null,
  redis: null,
  redisKeyPrefix,
  withTransaction: () =>
    Promise.reject(new Error('Database transaction requested while infrastructure is disabled')),
  close: () => Promise.resolve()
})

export const createProcessInfrastructure = async ({
  config
}: {
  config: ServiceConfig
}): Promise<ProcessInfrastructure> => {
  if (!config.infrastructure.enabled) {
    return createDisabledInfrastructure({
      redisKeyPrefix: config.infrastructure.redisKeyPrefix
    })
  }

  if (!config.infrastructure.databaseUrl || !config.infrastructure.redisUrl) {
    throw new Error('Infrastructure is enabled but BROKER_ADMIN_API_DATABASE_URL or BROKER_ADMIN_API_REDIS_URL is missing')
  }

  const prisma = new PrismaClient({
    datasources: {
      db: {
        url: config.infrastructure.databaseUrl
      }
    }
  })

  const redis = createClient({
    url: config.infrastructure.redisUrl,
    socket: {
      connectTimeout: config.infrastructure.redisConnectTimeoutMs
    }
  })

  try {
    await Promise.all([prisma.$connect(), redis.connect()])
  } catch (error) {
    await Promise.allSettled([prisma.$disconnect(), redis.quit()])
    throw error
  }

  return {
    enabled: true,
    prisma,
    redis,
    redisKeyPrefix: config.infrastructure.redisKeyPrefix,
    withTransaction: async operation => prisma.$transaction(async tx => operation(tx)),
    close: async () => {
      await Promise.allSettled([prisma.$disconnect(), redis.quit()])
    }
  }
}
