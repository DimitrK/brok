import {describe, expect, it} from 'vitest'

import {filterAuditEvents, normalizeAuditEventSearchFilter} from '../search'
import {buildAuditEvent} from './fixtures'

describe('normalizeAuditEventSearchFilter', () => {
  it('normalizes OpenAPI query input into typed filter model', () => {
    const result = normalizeAuditEventSearchFilter({
      time_min: '2026-02-07T10:00:00.000Z',
      time_max: '2026-02-07T11:00:00.000Z',
      tenant_id: 'tenant_1',
      decision: 'allowed'
    })

    expect(result.ok).toBe(true)
    if (!result.ok) {
      return
    }

    expect(result.value.tenant_id).toBe('tenant_1')
    expect(result.value.decision).toBe('allowed')
    expect(result.value.time_min).toBeInstanceOf(Date)
    expect(result.value.time_max).toBeInstanceOf(Date)
  })

  it('fails closed when time_min is later than time_max', () => {
    const result = normalizeAuditEventSearchFilter({
      time_min: '2026-02-07T12:00:00.000Z',
      time_max: '2026-02-07T10:00:00.000Z'
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error.code).toBe('invalid_time_range')
    }
  })

  it('fails when query payload has unexpected fields', () => {
    const result = normalizeAuditEventSearchFilter({
      tenant_id: 'tenant_1',
      unknown_field: 'not-allowed'
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error.code).toBe('invalid_search_query')
    }
  })
})

describe('filterAuditEvents', () => {
  it('filters by tenant, action_group, decision, and time range', () => {
    const events = [
      buildAuditEvent({
        event_id: 'evt_1',
        timestamp: '2026-02-07T10:00:00.000Z',
        tenant_id: 'tenant_1',
        action_group: 'group_a',
        decision: 'allowed'
      }),
      buildAuditEvent({
        event_id: 'evt_2',
        timestamp: '2026-02-07T10:30:00.000Z',
        tenant_id: 'tenant_1',
        action_group: 'group_b',
        decision: 'denied'
      }),
      buildAuditEvent({
        event_id: 'evt_3',
        timestamp: '2026-02-07T11:00:00.000Z',
        tenant_id: 'tenant_2',
        action_group: 'group_a',
        decision: 'allowed'
      })
    ]

    const filterResult = normalizeAuditEventSearchFilter({
      time_min: '2026-02-07T09:55:00.000Z',
      time_max: '2026-02-07T10:40:00.000Z',
      tenant_id: 'tenant_1',
      action_group: 'group_b',
      decision: 'denied'
    })
    expect(filterResult.ok).toBe(true)
    if (!filterResult.ok) {
      return
    }

    const filtered = filterAuditEvents({
      events,
      filter: filterResult.value
    })

    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.event_id).toBe('evt_2')
  })

  it('filters by workload and integration identifiers', () => {
    const events = [
      buildAuditEvent({
        event_id: 'evt_workload_1',
        workload_id: 'workload_1',
        integration_id: 'integration_1'
      }),
      buildAuditEvent({
        event_id: 'evt_workload_2',
        workload_id: 'workload_2',
        integration_id: 'integration_2'
      })
    ]

    const filterResult = normalizeAuditEventSearchFilter({
      workload_id: 'workload_2',
      integration_id: 'integration_2'
    })
    expect(filterResult.ok).toBe(true)
    if (!filterResult.ok) {
      return
    }

    const filtered = filterAuditEvents({
      events,
      filter: filterResult.value
    })

    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.event_id).toBe('evt_workload_2')
  })

  it('filters by decision mismatches', () => {
    const events = [
      buildAuditEvent({
        event_id: 'evt_decision_allowed',
        decision: 'allowed'
      }),
      buildAuditEvent({
        event_id: 'evt_decision_denied',
        decision: 'denied'
      })
    ]

    const filterResult = normalizeAuditEventSearchFilter({
      decision: 'allowed'
    })
    expect(filterResult.ok).toBe(true)
    if (!filterResult.ok) {
      return
    }

    const filtered = filterAuditEvents({
      events,
      filter: filterResult.value
    })

    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.event_id).toBe('evt_decision_allowed')
  })
})
