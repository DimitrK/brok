import {createHash} from 'node:crypto'

import {OpenApiAuditEventSchema, type OpenApiAuditEvent} from '@broker-interceptor/schemas'

import {
  AuditEventSearchFilterSchema,
  type AuditEventSearchFilter,
  type AuditRedactionProfile
} from './contracts'
import {filterAuditEvents} from './search'

export type AuditStoreAdapter<TDataAccessContext = unknown> = {
  appendAuditEvent: (input: {event: OpenApiAuditEvent; db_context?: TDataAccessContext}) => Promise<void> | void
  queryAuditEvents: (input: {
    filter: AuditEventSearchFilter
    db_context?: TDataAccessContext
  }) => Promise<OpenApiAuditEvent[]> | OpenApiAuditEvent[]
}

type CursorPageLike<TItem> = {
  items: TItem[]
}

type AuditEventQueryResult = OpenApiAuditEvent[] | CursorPageLike<OpenApiAuditEvent>

type DbAuditQueryFilter = {
  time_min?: string
  time_max?: string
  tenant_id?: string
  workload_id?: string
  integration_id?: string
  action_group?: string
  decision?: 'allowed' | 'denied' | 'approval_required' | 'throttled'
}

export type PostgresAuditStorageAdapter<TDataAccessContext = unknown> = {
  insertAuditEvent?: (input: {event: OpenApiAuditEvent; db_context?: TDataAccessContext}) => Promise<void>
  appendAuditEvent?: (input: {event: OpenApiAuditEvent; db_context?: TDataAccessContext}) => Promise<void>
  selectAuditEvents?: (input: {
    filter: AuditEventSearchFilter
    db_context?: TDataAccessContext
  }) => Promise<AuditEventQueryResult>
  queryAuditEvents?: (filter: AuditEventSearchFilter | DbAuditQueryFilter) => Promise<AuditEventQueryResult>
  selectAuditRedactionProfileByTenant?: (input: {
    tenant_id: string
    db_context?: TDataAccessContext
  }) => Promise<AuditRedactionProfile | null>
  getAuditRedactionProfileByTenant?: (input: {
    tenant_id: string
    db_context?: TDataAccessContext
  }) => Promise<AuditRedactionProfile | null>
}

export type RedisAuditCacheAdapter<TDataAccessContext = unknown> = {
  getJson: (input: {key: string; db_context?: TDataAccessContext}) => Promise<Record<string, unknown> | null>
  setJson: (input: {
    key: string
    value: unknown
    ttl_seconds: number
    db_context?: TDataAccessContext
  }) => Promise<void>
  deleteByPrefix: (input: {prefix: string; db_context?: TDataAccessContext}) => Promise<void>
}

export type PersistentAuditStoreDependencies<TDataAccessContext = unknown> = {
  postgres_repository: PostgresAuditStorageAdapter<TDataAccessContext>
  redis_cache_repository?: RedisAuditCacheAdapter<TDataAccessContext>
  cache_ttl_seconds?: number
}

const throwIncompleteDependencyError = (methodName: string): never => {
  throw new Error(
    `${methodName} is not wired yet. Integrate @broker-interceptor/db Postgres/Redis adapters before use.`
  )
}

const cloneAuditEvent = (event: OpenApiAuditEvent): OpenApiAuditEvent => OpenApiAuditEventSchema.parse(event)

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const normalizeAuditEventQueryResult = (result: AuditEventQueryResult): OpenApiAuditEvent[] => {
  const events = Array.isArray(result) ? result : result.items
  if (!Array.isArray(events)) {
    throw new Error('queryAuditEventsFromPostgres_INCOMPLETE returned an invalid response shape.')
  }
  return events.map(cloneAuditEvent)
}

const tryParseCachedAuditEvents = (
  cachedValue: Record<string, unknown> | null
): OpenApiAuditEvent[] | null => {
  if (!cachedValue) {
    return null
  }

  const eventsValue = cachedValue.events
  if (!Array.isArray(eventsValue)) {
    return null
  }

  try {
    return eventsValue.map(event => OpenApiAuditEventSchema.parse(event))
  } catch {
    return null
  }
}

const toStableHashInput = (value: unknown): string => {
  if (typeof value === 'undefined') {
    return '"__undefined__"'
  }
  if (value === null || typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (value instanceof Date) {
    return JSON.stringify(value.toISOString())
  }
  if (Array.isArray(value)) {
    return `[${value.map(item => toStableHashInput(item)).join(',')}]`
  }
  if (isRecord(value)) {
    const serialized = Object.entries(value)
      .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey))
      .map(([key, entry]) => `${JSON.stringify(key)}:${toStableHashInput(entry)}`)
      .join(',')
    return `{${serialized}}`
  }
  if (typeof value === 'bigint') {
    return JSON.stringify(value.toString())
  }
  if (typeof value === 'symbol') {
    return JSON.stringify(value.description ?? 'symbol')
  }
  if (typeof value === 'function') {
    return JSON.stringify('[function]')
  }
  return JSON.stringify(null)
}

const toDbAuditQueryFilter = (filter: AuditEventSearchFilter): DbAuditQueryFilter => ({
  ...(filter.time_min ? {time_min: filter.time_min.toISOString()} : {}),
  ...(filter.time_max ? {time_max: filter.time_max.toISOString()} : {}),
  ...(filter.tenant_id ? {tenant_id: filter.tenant_id} : {}),
  ...(filter.workload_id ? {workload_id: filter.workload_id} : {}),
  ...(filter.integration_id ? {integration_id: filter.integration_id} : {}),
  ...(filter.action_group ? {action_group: filter.action_group} : {}),
  ...(filter.decision ? {decision: filter.decision} : {})
})

const buildAuditQueryCacheKey = ({
  tenant_id,
  filter
}: {
  tenant_id: string
  filter: AuditEventSearchFilter
}): string => {
  const filterHash = createHash('sha256').update(toStableHashInput(filter)).digest('hex')
  return `audit:${tenant_id}:query:${filterHash}`
}

const getAuditQueryCachePrefixForTenant = (tenant_id: string): string => `audit:${tenant_id}:query:`

export const appendAuditEventInPostgres_INCOMPLETE = async <TDataAccessContext = unknown>({
  postgres_repository,
  event,
  db_context
}: {
  postgres_repository: PostgresAuditStorageAdapter<TDataAccessContext>
  event: OpenApiAuditEvent
  db_context?: TDataAccessContext
}): Promise<void> => {
  const parsedEvent = OpenApiAuditEventSchema.parse(event)

  if (typeof postgres_repository.insertAuditEvent === 'function') {
    await postgres_repository.insertAuditEvent({
      event: parsedEvent,
      db_context
    })
    return
  }

  if (typeof postgres_repository.appendAuditEvent === 'function') {
    await postgres_repository.appendAuditEvent({
      event: parsedEvent,
      db_context
    })
    return
  }

  return throwIncompleteDependencyError('appendAuditEventInPostgres_INCOMPLETE')
}

export const queryAuditEventsFromPostgres_INCOMPLETE = async <TDataAccessContext = unknown>({
  postgres_repository,
  filter,
  db_context
}: {
  postgres_repository: PostgresAuditStorageAdapter<TDataAccessContext>
  filter: AuditEventSearchFilter
  db_context?: TDataAccessContext
}): Promise<OpenApiAuditEvent[]> => {
  const parsedFilter = AuditEventSearchFilterSchema.parse(filter)

  if (typeof postgres_repository.selectAuditEvents === 'function') {
    const events = await postgres_repository.selectAuditEvents({
      filter: parsedFilter,
      db_context
    })
    return normalizeAuditEventQueryResult(events)
  }

  if (typeof postgres_repository.queryAuditEvents === 'function') {
    const events = await postgres_repository.queryAuditEvents(toDbAuditQueryFilter(parsedFilter))
    return normalizeAuditEventQueryResult(events)
  }

  return throwIncompleteDependencyError('queryAuditEventsFromPostgres_INCOMPLETE')
}

export const getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE = async <TDataAccessContext = unknown>({
  postgres_repository,
  tenant_id,
  db_context
}: {
  postgres_repository: PostgresAuditStorageAdapter<TDataAccessContext>
  tenant_id: string
  db_context?: TDataAccessContext
}): Promise<AuditRedactionProfile | null> => {
  if (typeof postgres_repository.selectAuditRedactionProfileByTenant === 'function') {
    return postgres_repository.selectAuditRedactionProfileByTenant({
      tenant_id,
      db_context
    })
  }

  if (typeof postgres_repository.getAuditRedactionProfileByTenant === 'function') {
    return postgres_repository.getAuditRedactionProfileByTenant({
      tenant_id,
      db_context
    })
  }

  return throwIncompleteDependencyError('getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE')
}

export const readAuditQueryCacheFromRedis_INCOMPLETE = async <TDataAccessContext = unknown>({
  redis,
  key,
  db_context
}: {
  redis: RedisAuditCacheAdapter<TDataAccessContext>
  key: string
  db_context?: TDataAccessContext
}): Promise<Record<string, unknown> | null> => {
  return redis.getJson({
    key,
    db_context
  })
}

export const writeAuditQueryCacheToRedis_INCOMPLETE = async <TDataAccessContext = unknown>({
  redis,
  key,
  value,
  ttl_seconds,
  db_context
}: {
  redis: RedisAuditCacheAdapter<TDataAccessContext>
  key: string
  value: unknown
  ttl_seconds: number
  db_context?: TDataAccessContext
}): Promise<void> => {
  await redis.setJson({
    key,
    value,
    ttl_seconds,
    db_context
  })
}

export const invalidateAuditQueryCacheByTenantFromRedis_INCOMPLETE = async <
  TDataAccessContext = unknown
>({
  redis,
  tenant_id,
  db_context
}: {
  redis: RedisAuditCacheAdapter<TDataAccessContext>
  tenant_id: string
  db_context?: TDataAccessContext
}): Promise<void> => {
  await redis.deleteByPrefix({
    prefix: getAuditQueryCachePrefixForTenant(tenant_id),
    db_context
  })
}

export const createPersistentAuditStore_INCOMPLETE = <TDataAccessContext = unknown>(
  dependencies: PersistentAuditStoreDependencies<TDataAccessContext>
): AuditStoreAdapter<TDataAccessContext> => {
  const cacheTtlSeconds = dependencies.cache_ttl_seconds ?? 30

  return {
    appendAuditEvent: async ({event, db_context}) => {
      const parsedEvent = OpenApiAuditEventSchema.parse(event)
      await appendAuditEventInPostgres_INCOMPLETE({
        postgres_repository: dependencies.postgres_repository,
        event: parsedEvent,
        db_context
      })

      if (!dependencies.redis_cache_repository) {
        return
      }

      try {
        await invalidateAuditQueryCacheByTenantFromRedis_INCOMPLETE({
          redis: dependencies.redis_cache_repository,
          tenant_id: parsedEvent.tenant_id,
          db_context
        })
      } catch {
        // Cache invalidation is best-effort; Postgres remains source-of-truth.
      }
    },
    queryAuditEvents: async ({filter, db_context}) => {
      const parsedFilter = AuditEventSearchFilterSchema.parse(filter)
      const tenantId = parsedFilter.tenant_id
      const redis = dependencies.redis_cache_repository
      const cacheKey =
        redis && tenantId
          ? buildAuditQueryCacheKey({
              tenant_id: tenantId,
              filter: parsedFilter
            })
          : null

      if (redis && cacheKey) {
        try {
          const cached = await readAuditQueryCacheFromRedis_INCOMPLETE({
            redis,
            key: cacheKey,
            db_context
          })
          const cachedEvents = tryParseCachedAuditEvents(cached)
          if (cachedEvents) {
            return cachedEvents.map(cloneAuditEvent)
          }
        } catch {
          // Cache lookup is best-effort; fallback to Postgres when unavailable.
        }
      }

      const events = await queryAuditEventsFromPostgres_INCOMPLETE({
        postgres_repository: dependencies.postgres_repository,
        filter: parsedFilter,
        db_context
      })

      if (redis && cacheKey) {
        try {
          await writeAuditQueryCacheToRedis_INCOMPLETE({
            redis,
            key: cacheKey,
            value: {events},
            ttl_seconds: cacheTtlSeconds,
            db_context
          })
        } catch {
          // Cache write is best-effort; query path still succeeds from Postgres.
        }
      }

      return events.map(cloneAuditEvent)
    }
  }
}

export const createAuditRedactionProfileResolverFromDb_INCOMPLETE =
  <TDataAccessContext = unknown>(dependencies: {
    postgres_repository: PostgresAuditStorageAdapter<TDataAccessContext>
  }) =>
  async ({
    tenant_id,
    db_context
  }: {
    tenant_id: string
    db_context?: TDataAccessContext
  }): Promise<AuditRedactionProfile | null> =>
    getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE({
      postgres_repository: dependencies.postgres_repository,
      tenant_id,
      db_context
    })

export const createInMemoryAuditStore = (): AuditStoreAdapter => {
  const events: OpenApiAuditEvent[] = []

  return {
    appendAuditEvent: ({event, db_context}) => {
      const parsedEvent = OpenApiAuditEventSchema.parse(event)
      void db_context
      events.push(cloneAuditEvent(parsedEvent))
    },
    queryAuditEvents: ({filter, db_context}) => {
      const parsedFilter = AuditEventSearchFilterSchema.parse(filter)
      void db_context
      return filterAuditEvents({
        events,
        filter: parsedFilter
      }).map(cloneAuditEvent)
    }
  }
}
