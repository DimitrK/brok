import {PrismaClient, type Prisma} from '@prisma/client'
import {
  createDbRepositories,
  type DatabaseClient,
  type DbRepositories
} from '@broker-interceptor/db'
import {createClient} from 'redis'

import type {ServiceConfig} from './config'

type WithTransaction = <T>(operation: (tx: Prisma.TransactionClient) => Promise<T>) => Promise<T>
export type BrokerRedisClient = ReturnType<typeof createClient>

export type ProcessInfrastructure = {
  enabled: boolean
  prisma: PrismaClient | null
  redis: BrokerRedisClient | null
  dbRepositories: DbRepositories | null
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
  dbRepositories: null,
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
  const infrastructureConfig = config.infrastructure
  if (!infrastructureConfig.enabled) {
    return createDisabledInfrastructure({
      redisKeyPrefix: infrastructureConfig.redisKeyPrefix
    })
  }

  if (!infrastructureConfig.databaseUrl || !infrastructureConfig.redisUrl) {
    throw new Error('Infrastructure is enabled but BROKER_API_DATABASE_URL or BROKER_API_REDIS_URL is missing')
  }

  const prisma = new PrismaClient({
    datasources: {
      db: {
        url: infrastructureConfig.databaseUrl
      }
    }
  })

  const redis = createClient({
    url: infrastructureConfig.redisUrl,
    socket: {
      connectTimeout: infrastructureConfig.redisConnectTimeoutMs
    }
  })

  try {
    await Promise.all([prisma.$connect(), redis.connect()])
  } catch (error) {
    await Promise.allSettled([prisma.$disconnect(), redis.quit()])
    throw error
  }

  const dbRepositories = createDbRepositories(prisma as unknown as DatabaseClient)

  return {
    enabled: true,
    prisma,
    redis,
    dbRepositories,
    redisKeyPrefix: infrastructureConfig.redisKeyPrefix,
    withTransaction: async operation =>
      prisma.$transaction(async transactionClient => operation(transactionClient)),
    close: async () => {
      await Promise.allSettled([prisma.$disconnect(), redis.quit()])
    }
  }
}
