import type {Server} from 'node:http'
import {promises as fs} from 'node:fs'

import helmet from 'helmet'
import express from 'express'
import type {NestApplicationOptions} from '@nestjs/common'
import {NestFactory} from '@nestjs/core'
import {ExpressAdapter} from '@nestjs/platform-express'

import {
  createAuditService,
  createInMemoryAuditStore,
  createPersistentAuditStore_INCOMPLETE
} from '@broker-interceptor/audit'
import {createAuditRedisCacheAdapter, type RedisScanClient} from '@broker-interceptor/db'
import type {FetchLike} from '@broker-interceptor/forwarder'
import type {DnsResolver} from '@broker-interceptor/ssrf-guard'

import type {ServiceConfig} from './config'
import {createProcessInfrastructure} from './infrastructure'
import {BrokerApiNestModule} from './nest/brokerApiNestModule'
import {DataPlaneRepository} from './repository'

export const createBrokerApiApp = async ({
  config,
  fetchImpl,
  dnsResolver,
  now
}: {
  config: ServiceConfig
  fetchImpl?: FetchLike
  dnsResolver?: DnsResolver
  now?: () => Date
}) => {
  const loadHttpsOptions = async ({
    config
  }: {
    config: ServiceConfig
  }): Promise<NonNullable<NestApplicationOptions['httpsOptions']> | undefined> => {
    const tlsConfig = config.tls
    if (!tlsConfig?.enabled) {
      return undefined
    }

    try {
      const keyPromise =
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- TLS file paths are explicit service configuration.
        fs.readFile(tlsConfig.keyPath)
      const certPromise =
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- TLS file paths are explicit service configuration.
        fs.readFile(tlsConfig.certPath)
      const caPromise = tlsConfig.clientCaPath
        ? // eslint-disable-next-line security/detect-non-literal-fs-filename -- TLS file paths are explicit service configuration.
          fs.readFile(tlsConfig.clientCaPath)
        : Promise.resolve(undefined)

      const [key, cert, ca] = await Promise.all([keyPromise, certPromise, caPromise])

      return {
        key,
        cert,
        ...(ca ? {ca} : {}),
        requestCert: tlsConfig.requireClientCert,
        rejectUnauthorized: tlsConfig.rejectUnauthorizedClientCert
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : 'unknown error'
      throw new Error(`Unable to load TLS configuration for broker-api: ${reason}`)
    }
  }

  const toRepositoryOperationContext = (dbContext: unknown) => {
    if (typeof dbContext !== 'object' || dbContext === null) {
      return undefined
    }

    const raw = dbContext as {
      transaction_client?: unknown
      clients?: {
        postgres?: unknown
        redis?: unknown
      }
    }

    const hasTransactionClient = raw.transaction_client !== undefined
    const hasClients = raw.clients !== undefined
    if (!hasTransactionClient && !hasClients) {
      return undefined
    }

    return {
      ...(hasTransactionClient ? {transaction_client: raw.transaction_client} : {}),
      ...(hasClients ? {clients: raw.clients} : {})
    }
  }

  let infrastructure: Awaited<ReturnType<typeof createProcessInfrastructure>> | null = null
  try {
    infrastructure = await createProcessInfrastructure({config})
    const processInfrastructure = infrastructure
    const repository = await DataPlaneRepository.create({
      ...(config.statePath ? {statePath: config.statePath} : {}),
      ...(config.initialState ? {initialState: config.initialState} : {}),
      approvalTtlSeconds: config.approvalTtlSeconds,
      manifestTtlSeconds: config.manifestTtlSeconds,
      processInfrastructure
    })

    const sharedAuditRepository = processInfrastructure.dbRepositories?.auditEventRepository
    const toAuditFilterIso = (value: Date | string | undefined) => {
      if (typeof value === 'string') {
        return value
      }
      if (value instanceof Date) {
        return value.toISOString()
      }
      return undefined
    }

    const redisCacheRepository =
      processInfrastructure.redis && processInfrastructure.enabled
        ? createAuditRedisCacheAdapter({
            redisClient: processInfrastructure.redis as unknown as RedisScanClient,
            keyPrefix: `${processInfrastructure.redisKeyPrefix}:audit`
          })
        : undefined

    const auditStore =
      sharedAuditRepository && processInfrastructure.enabled
        ? createPersistentAuditStore_INCOMPLETE({
            postgres_repository: {
              appendAuditEvent: async ({event, db_context}) => {
                const repositoryContext = toRepositoryOperationContext(db_context)
                await sharedAuditRepository.appendAuditEvent({
                  event,
                  ...(repositoryContext ? {context: repositoryContext} : {})
                })
              },
              queryAuditEvents: async filter => {
                const normalizedFilter = {
                  ...(toAuditFilterIso(filter.time_min) ? {time_min: toAuditFilterIso(filter.time_min)} : {}),
                  ...(toAuditFilterIso(filter.time_max) ? {time_max: toAuditFilterIso(filter.time_max)} : {}),
                  ...(filter.tenant_id ? {tenant_id: filter.tenant_id} : {}),
                  ...(filter.workload_id ? {workload_id: filter.workload_id} : {}),
                  ...(filter.integration_id ? {integration_id: filter.integration_id} : {}),
                  ...(filter.action_group ? {action_group: filter.action_group} : {}),
                  ...(filter.decision ? {decision: filter.decision} : {})
                }

                return sharedAuditRepository.queryAuditEvents({
                  ...normalizedFilter
                })
              },
              selectAuditRedactionProfileByTenant: async (input: {tenant_id: string; db_context?: unknown}) => {
                const repositoryContext = toRepositoryOperationContext(input.db_context)
                return sharedAuditRepository.getAuditRedactionProfileByTenant({
                  tenant_id: input.tenant_id,
                  ...(repositoryContext ? {db_context: repositoryContext} : {})
                })
              }
            },
            ...(redisCacheRepository ? {redis_cache_repository: redisCacheRepository} : {}),
            cache_ttl_seconds: 30
          })
        : createInMemoryAuditStore()

    const auditService = createAuditService({
      store: auditStore,
      ...(sharedAuditRepository && processInfrastructure.enabled
        ? {
            resolveRedactionProfile: async ({tenant_id, db_context}: {tenant_id: string; db_context?: unknown}) =>
              sharedAuditRepository.getAuditRedactionProfileByTenant({
                tenant_id,
                ...(toRepositoryOperationContext(db_context)
                  ? {db_context: toRepositoryOperationContext(db_context)}
                  : {})
              })
          }
        : {})
    })

    const expressApp = express()
    expressApp.disable('x-powered-by')
    expressApp.use(
      helmet({
        contentSecurityPolicy: false
      })
    )

    const httpsOptions = await loadHttpsOptions({config})

    const nestApp = await NestFactory.create(
      BrokerApiNestModule.register({
        config,
        repository,
        auditService,
        ...(fetchImpl ? {fetchImpl} : {}),
        ...(dnsResolver ? {dnsResolver} : {}),
        ...(now ? {now} : {})
      }),
      new ExpressAdapter(expressApp),
      {
        bodyParser: false,
        logger: config.nodeEnv === 'test' ? false : ['error', 'warn', 'log'],
        ...(httpsOptions ? {httpsOptions} : {})
      }
    )

    if ((config.corsAllowedOrigins ?? []).length > 0) {
      nestApp.enableCors({
        origin: config.corsAllowedOrigins
      })
    }

    await nestApp.init()

    const server = nestApp.getHttpServer() as Server

    const start = async () => {
      await nestApp.listen(config.port, config.host)
    }

    const stop = async () => {
      await Promise.allSettled([nestApp.close(), processInfrastructure.close()])
    }

    return {
      server,
      start,
      stop,
      repository,
      auditService,
      infrastructure: processInfrastructure
    }
  } catch (error) {
    if (infrastructure) {
      await infrastructure.close()
    }

    throw error
  }
}

export type BrokerApiApp = Awaited<ReturnType<typeof createBrokerApiApp>>
