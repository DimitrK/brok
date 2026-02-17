import {describe, expect, it, vi} from 'vitest'

import {buildAuditEvent} from './fixtures'
import {
  appendAuditEventInPostgres_INCOMPLETE,
  createAuditRedactionProfileResolverFromDb_INCOMPLETE,
  createPersistentAuditStore_INCOMPLETE,
  getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE,
  invalidateAuditQueryCacheByTenantFromRedis_INCOMPLETE,
  queryAuditEventsFromPostgres_INCOMPLETE,
  readAuditQueryCacheFromRedis_INCOMPLETE,
  writeAuditQueryCacheToRedis_INCOMPLETE,
  type PostgresAuditStorageAdapter,
  type RedisAuditCacheAdapter
} from '../store'

describe('db-dependent placeholders', () => {
  it('passes append/query through app-injected postgres adapter and preserves db_context', async () => {
    const insertAuditEvent = vi.fn(() => Promise.resolve())
    const selectAuditEvents = vi.fn(() => Promise.resolve([buildAuditEvent({event_id: 'evt_pg_1'})]))
    const postgres: PostgresAuditStorageAdapter = {
      insertAuditEvent,
      selectAuditEvents
    }
    const db_context = {transaction_client: {id: 'tx_1'}}

    await appendAuditEventInPostgres_INCOMPLETE({
      postgres_repository: postgres,
      event: buildAuditEvent({event_id: 'evt_pg_append'}),
      db_context
    })

    expect(insertAuditEvent).toHaveBeenCalledTimes(1)
    expect(insertAuditEvent).toHaveBeenCalledWith({
      event: buildAuditEvent({event_id: 'evt_pg_append'}),
      db_context
    })

    const queried = await queryAuditEventsFromPostgres_INCOMPLETE({
      postgres_repository: postgres,
      filter: {tenant_id: 'tenant_1'},
      db_context
    })

    expect(selectAuditEvents).toHaveBeenCalledTimes(1)
    expect(selectAuditEvents).toHaveBeenCalledWith({
      filter: {tenant_id: 'tenant_1'},
      db_context
    })
    expect(queried).toHaveLength(1)
    expect(queried[0]?.event_id).toBe('evt_pg_1')
  })

  it('accepts db repository cursor-page query shape', async () => {
    const queryAuditEvents = vi.fn(() =>
      Promise.resolve({
        items: [buildAuditEvent({event_id: 'evt_page_1'})]
      })
    )
    const postgres: PostgresAuditStorageAdapter = {
      queryAuditEvents
    }

    const events = await queryAuditEventsFromPostgres_INCOMPLETE({
      postgres_repository: postgres,
      filter: {
        tenant_id: 'tenant_1',
        time_min: new Date('2026-02-07T10:00:00.000Z')
      }
    })

    expect(queryAuditEvents).toHaveBeenCalledWith({
      tenant_id: 'tenant_1',
      time_min: '2026-02-07T10:00:00.000Z'
    })
    expect(events).toHaveLength(1)
    expect(events[0]?.event_id).toBe('evt_page_1')
  })

  it('supports db append method fallback shape', async () => {
    const appendAuditEvent = vi.fn(() => Promise.resolve())
    const postgres: PostgresAuditStorageAdapter = {
      appendAuditEvent
    }

    await appendAuditEventInPostgres_INCOMPLETE({
      postgres_repository: postgres,
      event: buildAuditEvent({event_id: 'evt_append_fallback'})
    })

    expect(appendAuditEvent).toHaveBeenCalledWith({
      event: buildAuditEvent({event_id: 'evt_append_fallback'}),
      db_context: undefined
    })
  })

  it('loads redaction profile through injected postgres adapter when available', async () => {
    const selectAuditRedactionProfileByTenant = vi.fn(() =>
      Promise.resolve({
        tenant_id: 'tenant_1',
        profile_id: 'profile_1',
        rules: {
          message_action: 'mask' as const,
          metadata_default_action: 'mask' as const,
          metadata_key_actions: {},
          metadata_allow_keys: [],
          sensitive_key_patterns: ['token'],
          canonical_header_value_action: 'mask' as const,
          policy_identifier_action: 'mask' as const,
          max_depth: 5,
          max_collection_size: 100,
          max_string_length: 512
        }
      })
    )
    const postgres: PostgresAuditStorageAdapter = {
      selectAuditRedactionProfileByTenant
    }
    const db_context = {transaction_client: {id: 'tx_1'}}

    const profile = await getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE({
      postgres_repository: postgres,
      tenant_id: 'tenant_1',
      db_context
    })

    expect(selectAuditRedactionProfileByTenant).toHaveBeenCalledWith({
      tenant_id: 'tenant_1',
      db_context
    })
    expect(profile?.profile_id).toBe('profile_1')
  })

  it('supports db redaction profile getter shape with db_context input', async () => {
    const getAuditRedactionProfileByTenant = vi.fn(() =>
      Promise.resolve({
        tenant_id: 'tenant_1',
        profile_id: 'profile_fallback',
        rules: {
          message_action: 'mask' as const,
          metadata_default_action: 'mask' as const,
          metadata_key_actions: {},
          metadata_allow_keys: [],
          sensitive_key_patterns: ['token'],
          canonical_header_value_action: 'mask' as const,
          policy_identifier_action: 'mask' as const,
          max_depth: 5,
          max_collection_size: 100,
          max_string_length: 512
        }
      })
    )
    const profile = await getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE({
      postgres_repository: {
        getAuditRedactionProfileByTenant
      },
      tenant_id: 'tenant_1',
      db_context: {transaction_client: {id: 'tx_4'}}
    })

    expect(getAuditRedactionProfileByTenant).toHaveBeenCalledWith({
      tenant_id: 'tenant_1',
      db_context: {transaction_client: {id: 'tx_4'}}
    })
    expect(profile?.profile_id).toBe('profile_fallback')
  })

  it('passes through redis cache adapter with db_context', async () => {
    const getJson = vi.fn(() => Promise.resolve({events: []}))
    const setJson = vi.fn(() => Promise.resolve())
    const deleteByPrefix = vi.fn(() => Promise.resolve())
    const redis: RedisAuditCacheAdapter = {
      getJson,
      setJson,
      deleteByPrefix
    }
    const db_context = {transaction_client: {id: 'tx_2'}}

    await readAuditQueryCacheFromRedis_INCOMPLETE({
      redis,
      key: 'audit:tenant_1:query_1',
      db_context
    })
    await writeAuditQueryCacheToRedis_INCOMPLETE({
      redis,
      key: 'audit:tenant_1:query_1',
      value: {events: []},
      ttl_seconds: 30,
      db_context
    })
    await invalidateAuditQueryCacheByTenantFromRedis_INCOMPLETE({
      redis,
      tenant_id: 'tenant_1',
      db_context
    })

    expect(getJson).toHaveBeenCalledWith({
      key: 'audit:tenant_1:query_1',
      db_context
    })
    expect(setJson).toHaveBeenCalledWith({
      key: 'audit:tenant_1:query_1',
      value: {events: []},
      ttl_seconds: 30,
      db_context
    })
    expect(deleteByPrefix).toHaveBeenCalledWith({
      prefix: 'audit:tenant_1:query:',
      db_context
    })
  })

  it('creates persistent store using injected repositories, cache read/write, and tenant invalidation', async () => {
    const selectAuditEvents = vi.fn(() => Promise.resolve([buildAuditEvent({event_id: 'evt_store_1'})]))
    const insertAuditEvent = vi.fn(() => Promise.resolve())
    const cache = new Map<string, Record<string, unknown>>()
    const getJson = vi.fn(({key}: {key: string}) => Promise.resolve(cache.get(key) ?? null))
    const setJson = vi.fn(({key, value}: {key: string; value: unknown}) => {
      cache.set(key, value as Record<string, unknown>)
      return Promise.resolve()
    })
    const deleteByPrefix = vi.fn(({prefix}: {prefix: string}) => {
      for (const cacheKey of cache.keys()) {
        if (cacheKey.startsWith(prefix)) {
          cache.delete(cacheKey)
        }
      }
      return Promise.resolve()
    })

    const store = createPersistentAuditStore_INCOMPLETE({
      postgres_repository: {
        insertAuditEvent,
        selectAuditEvents
      },
      redis_cache_repository: {
        getJson,
        setJson,
        deleteByPrefix
      },
      cache_ttl_seconds: 60
    })

    const first = await store.queryAuditEvents({
      filter: {
        tenant_id: 'tenant_1',
        decision: 'allowed'
      },
      db_context: {transaction_client: {id: 'tx_3'}}
    })

    expect(first).toHaveLength(1)
    expect(selectAuditEvents).toHaveBeenCalledTimes(1)
    expect(setJson).toHaveBeenCalledTimes(1)

    const second = await store.queryAuditEvents({
      filter: {
        tenant_id: 'tenant_1',
        decision: 'allowed'
      }
    })

    expect(second).toHaveLength(1)
    expect(selectAuditEvents).toHaveBeenCalledTimes(1)

    await store.appendAuditEvent({
      event: buildAuditEvent({event_id: 'evt_store_append'})
    })
    expect(insertAuditEvent).toHaveBeenCalledTimes(1)
    expect(deleteByPrefix).toHaveBeenCalledTimes(1)
  })

  it('keeps append/query operational when cache operations fail', async () => {
    const store = createPersistentAuditStore_INCOMPLETE({
      postgres_repository: {
        insertAuditEvent: () => Promise.resolve(),
        selectAuditEvents: () => Promise.resolve([buildAuditEvent({event_id: 'evt_store_2'})])
      },
      redis_cache_repository: {
        getJson: () => Promise.reject(new Error('cache down')),
        setJson: () => Promise.reject(new Error('cache down')),
        deleteByPrefix: () => Promise.reject(new Error('cache down'))
      }
    })

    await expect(
      store.appendAuditEvent({
        event: buildAuditEvent({event_id: 'evt_store_append_2'})
      })
    ).resolves.toBeUndefined()

    await expect(
      store.queryAuditEvents({
        filter: {tenant_id: 'tenant_1'}
      })
    ).resolves.toHaveLength(1)
  })

  it('works without redis adapter and still queries postgres', async () => {
    const selectAuditEvents = vi.fn(() => Promise.resolve([buildAuditEvent({event_id: 'evt_no_cache'})]))
    const store = createPersistentAuditStore_INCOMPLETE({
      postgres_repository: {
        insertAuditEvent: () => Promise.resolve(),
        selectAuditEvents
      }
    })

    await expect(
      store.appendAuditEvent({
        event: buildAuditEvent({event_id: 'evt_no_cache_append'})
      })
    ).resolves.toBeUndefined()

    const events = await store.queryAuditEvents({
      filter: {tenant_id: 'tenant_1'}
    })

    expect(events).toHaveLength(1)
    expect(selectAuditEvents).toHaveBeenCalledTimes(1)
  })

  it('throws explicit incomplete errors when required postgres methods are missing', async () => {
    const emptyPostgres = {} as PostgresAuditStorageAdapter
    const store = createPersistentAuditStore_INCOMPLETE({
      postgres_repository: emptyPostgres
    })

    await expect(
      appendAuditEventInPostgres_INCOMPLETE({
        postgres_repository: emptyPostgres,
        event: buildAuditEvent()
      })
    ).rejects.toThrow('appendAuditEventInPostgres_INCOMPLETE')

    await expect(
      queryAuditEventsFromPostgres_INCOMPLETE({
        postgres_repository: emptyPostgres,
        filter: {tenant_id: 'tenant_1'}
      })
    ).rejects.toThrow('queryAuditEventsFromPostgres_INCOMPLETE')

    await expect(
      store.appendAuditEvent({
        event: buildAuditEvent()
      })
    ).rejects.toThrow('appendAuditEventInPostgres_INCOMPLETE')

    await expect(
      store.queryAuditEvents({
        filter: {tenant_id: 'tenant_1'}
      })
    ).rejects.toThrow('queryAuditEventsFromPostgres_INCOMPLETE')
  })

  it('throws explicit incomplete errors for unresolved redaction profile dependencies', async () => {
    const resolver = createAuditRedactionProfileResolverFromDb_INCOMPLETE({
      postgres_repository: {} as PostgresAuditStorageAdapter
    })

    await expect(
      resolver({
        tenant_id: 'tenant_1',
        db_context: {transaction_client: {id: 'tx_1'}}
      })
    ).rejects.toThrow('getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE')
  })

  it('creates resolver that loads profile via injected postgres repository', async () => {
    const getAuditRedactionProfileByTenant = vi.fn(() =>
      Promise.resolve({
        tenant_id: 'tenant_1',
        profile_id: 'profile_resolver',
        rules: {
          message_action: 'mask' as const,
          metadata_default_action: 'mask' as const,
          metadata_key_actions: {},
          metadata_allow_keys: [],
          sensitive_key_patterns: ['token'],
          canonical_header_value_action: 'mask' as const,
          policy_identifier_action: 'mask' as const,
          max_depth: 5,
          max_collection_size: 100,
          max_string_length: 512
        }
      })
    )

    const resolver = createAuditRedactionProfileResolverFromDb_INCOMPLETE({
      postgres_repository: {
        getAuditRedactionProfileByTenant
      }
    })

    const profile = await resolver({
      tenant_id: 'tenant_1',
      db_context: {transaction_client: {id: 'tx_5'}}
    })

    expect(getAuditRedactionProfileByTenant).toHaveBeenCalledWith({
      tenant_id: 'tenant_1',
      db_context: {transaction_client: {id: 'tx_5'}}
    })
    expect(profile?.profile_id).toBe('profile_resolver')
  })
})
