import {describe, expect, it} from 'vitest'

import {AuditRedactionProfileSchema} from '../contracts'
import {createAuditService} from '../service'
import {createInMemoryAuditStore} from '../store'
import {buildAuditEvent} from './fixtures'

describe('AuditService.appendAuditEvent', () => {
  it('appends a redacted immutable event into append-only storage', async () => {
    const store = createInMemoryAuditStore()
    const service = createAuditService({store})
    const sourceEvent = buildAuditEvent({
      event_id: 'evt_append_1'
    })

    const appendResult = await service.appendAuditEvent({event: sourceEvent})
    expect(appendResult.ok).toBe(true)
    if (!appendResult.ok) {
      return
    }

    expect(appendResult.value.delivery_status).toBe('stored')
    expect(appendResult.value.event.metadata).toEqual({
      action: 'execute',
      api_key: '[REDACTED]',
      request_body: '[REDACTED]'
    })

    sourceEvent.metadata = {action: 'mutated'}

    const listResult = await service.queryAuditEvents({
      query: {
        tenant_id: 'tenant_1'
      }
    })
    expect(listResult.ok).toBe(true)
    if (!listResult.ok) {
      return
    }

    expect(listResult.value.events).toHaveLength(1)
    expect(listResult.value.events[0]?.metadata).toEqual({
      action: 'execute',
      api_key: '[REDACTED]',
      request_body: '[REDACTED]'
    })

    const first = listResult.value.events[0]
    if (!first) {
      return
    }
    first.message = 'mutated'

    const secondListResult = await service.queryAuditEvents({
      query: {
        tenant_id: 'tenant_1'
      }
    })
    expect(secondListResult.ok).toBe(true)
    if (!secondListResult.ok) {
      return
    }

    expect(secondListResult.value.events[0]?.message).toBe('[REDACTED]')
  })

  it('fails when resolved redaction profile tenant does not match event tenant', async () => {
    const store = createInMemoryAuditStore()
    const service = createAuditService({
      store,
      resolveRedactionProfile: () =>
        AuditRedactionProfileSchema.parse({
          tenant_id: 'another_tenant',
          profile_id: 'bad_profile',
          rules: {
            message_action: 'mask',
            metadata_default_action: 'mask',
            metadata_key_actions: {},
            metadata_allow_keys: [],
            sensitive_key_patterns: ['token'],
            canonical_header_value_action: 'mask',
            policy_identifier_action: 'mask',
            max_depth: 5,
            max_collection_size: 100,
            max_string_length: 512
          }
        })
    })

    const appendResult = await service.appendAuditEvent({
      event: buildAuditEvent()
    })

    expect(appendResult.ok).toBe(false)
    if (!appendResult.ok) {
      expect(appendResult.error.code).toBe('redaction_profile_invalid')
    }
  })

  it('fails closed on invalid append payload shape', async () => {
    const service = createAuditService({
      store: createInMemoryAuditStore()
    })

    const appendResult = await service.appendAuditEvent({
      event: {tenant_id: 'tenant_1'}
    })

    expect(appendResult.ok).toBe(false)
    if (!appendResult.ok) {
      expect(appendResult.error.code).toBe('invalid_input')
    }
  })

  it('returns storage_write_failed when store append throws', async () => {
    const service = createAuditService({
      store: {
        appendAuditEvent: () => {
          throw new Error('storage unavailable')
        },
        queryAuditEvents: () => []
      }
    })

    const appendResult = await service.appendAuditEvent({
      event: buildAuditEvent()
    })

    expect(appendResult.ok).toBe(false)
    if (!appendResult.ok) {
      expect(appendResult.error.code).toBe('storage_write_failed')
      expect(appendResult.error.message).toContain('storage unavailable')
    }
  })

  it('maps resolver failures into redaction profile errors', async () => {
    const service = createAuditService({
      store: createInMemoryAuditStore(),
      resolveRedactionProfile: () => {
        throw new Error('resolver_failed')
      }
    })

    const appendResult = await service.appendAuditEvent({
      event: buildAuditEvent()
    })

    expect(appendResult.ok).toBe(false)
    if (!appendResult.ok) {
      expect(appendResult.error.code).toBe('redaction_profile_invalid')
      expect(appendResult.error.message).toContain('resolver_failed')
    }
  })

  it('passes db_context to redaction profile resolver and store append', async () => {
    const captured: {
      resolver_context?: unknown
      store_context?: unknown
    } = {}

    const service = createAuditService({
      store: {
        appendAuditEvent: ({db_context}) => {
          captured.store_context = db_context
        },
        queryAuditEvents: () => []
      },
      resolveRedactionProfile: ({db_context}) => {
        captured.resolver_context = db_context
        return null
      }
    })

    const db_context = {
      transaction_client: {id: 'tx_123'}
    }

    const appendResult = await service.appendAuditEvent({
      event: buildAuditEvent(),
      db_context
    })

    expect(appendResult.ok).toBe(true)
    expect(captured.resolver_context).toEqual(db_context)
    expect(captured.store_context).toEqual(db_context)
  })
})

describe('AuditService.queryAuditEvents', () => {
  it('returns search-filtered events with OpenAPI response model', async () => {
    const store = createInMemoryAuditStore()
    const service = createAuditService({store})

    await service.appendAuditEvent({
      event: buildAuditEvent({
        event_id: 'evt_q_1',
        tenant_id: 'tenant_1',
        decision: 'allowed',
        action_group: 'group_a',
        timestamp: '2026-02-07T10:00:00.000Z'
      })
    })

    await service.appendAuditEvent({
      event: buildAuditEvent({
        event_id: 'evt_q_2',
        tenant_id: 'tenant_1',
        decision: 'denied',
        action_group: 'group_b',
        timestamp: '2026-02-07T11:00:00.000Z'
      })
    })

    const result = await service.queryAuditEvents({
      query: {
        tenant_id: 'tenant_1',
        decision: 'denied',
        action_group: 'group_b',
        time_min: '2026-02-07T10:30:00.000Z'
      }
    })

    expect(result.ok).toBe(true)
    if (!result.ok) {
      return
    }

    expect(result.value.events).toHaveLength(1)
    expect(result.value.events[0]?.event_id).toBe('evt_q_2')
  })

  it('rejects invalid query time ranges', async () => {
    const store = createInMemoryAuditStore()
    const service = createAuditService({store})

    const result = await service.queryAuditEvents({
      query: {
        time_min: '2026-02-07T12:00:00.000Z',
        time_max: '2026-02-07T10:00:00.000Z'
      }
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error.code).toBe('invalid_time_range')
    }
  })

  it('fails closed on invalid query payload shape', async () => {
    const service = createAuditService({
      store: createInMemoryAuditStore()
    })

    const result = await service.queryAuditEvents({
      query: {time_min: 'not-a-date'}
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error.code).toBe('invalid_input')
    }
  })

  it('returns storage_query_failed when store query throws', async () => {
    const service = createAuditService({
      store: {
        appendAuditEvent: () => undefined,
        queryAuditEvents: () => {
          throw new Error('query unavailable')
        }
      }
    })

    const result = await service.queryAuditEvents({
      query: {tenant_id: 'tenant_1'}
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error.code).toBe('storage_query_failed')
      expect(result.error.message).toContain('query unavailable')
    }
  })

  it('passes db_context to store query path', async () => {
    const captured: {
      store_context?: unknown
    } = {}
    const service = createAuditService({
      store: {
        appendAuditEvent: () => undefined,
        queryAuditEvents: ({db_context}) => {
          captured.store_context = db_context
          return []
        }
      }
    })

    const db_context = {
      transaction_client: {id: 'tx_456'}
    }

    const result = await service.queryAuditEvents({
      query: {tenant_id: 'tenant_1'},
      db_context
    })

    expect(result.ok).toBe(true)
    expect(captured.store_context).toEqual(db_context)
  })
})
