import type {OpenApiAuditEvent} from '@broker-interceptor/schemas';
import {describe, expect, it, vi} from 'vitest';

import type {BrokerAdminApiClient} from '../../api/client';
import type {AuditFilter} from '../../api/querySchemas';
import {DEFAULT_AUDIT_PAGE_LIMIT, fetchAuditEventPage} from './auditEventPaging';

const makeEvent = (input: {eventId: string; timestamp: string}): OpenApiAuditEvent => ({
  event_id: input.eventId,
  timestamp: input.timestamp,
  tenant_id: 't_1',
  workload_id: 'w_1',
  integration_id: 'int_1',
  correlation_id: 'cid_1',
  event_type: 'policy_decision',
  decision: 'denied',
  action_group: 'responses_create',
  risk_tier: 'low',
  destination: null,
  latency_ms: null,
  upstream_status_code: null,
  canonical_descriptor: null,
  policy: null,
  message: null,
  metadata: null
});

describe('auditEventPaging', () => {
  it('forwards cursor/limit to API and preserves next_cursor', async () => {
    const listAuditEvents = vi.fn().mockResolvedValue({
      events: [makeEvent({eventId: 'evt_1', timestamp: '2026-01-02T00:00:00.000Z'})],
      next_cursor: 'cursor_2'
    });

    const page = await fetchAuditEventPage({
      api: {listAuditEvents} as unknown as BrokerAdminApiClient,
      filter: {
        tenant_id: 't_1'
      },
      cursor: 'cursor_1',
      limit: 25
    });

    const firstCallArg = listAuditEvents.mock.calls[0]?.[0] as {filter?: AuditFilter} | undefined;
    expect(firstCallArg?.filter?.cursor).toBe('cursor_1');
    expect(firstCallArg?.filter?.limit).toBe(25);
    expect(page.next_cursor).toBe('cursor_2');
    expect(page.events).toHaveLength(1);
  });

  it('applies default page size and safe fallback when response is undefined', async () => {
    const listAuditEvents = vi.fn().mockResolvedValue(undefined);

    const page = await fetchAuditEventPage({
      api: {listAuditEvents} as unknown as BrokerAdminApiClient,
      filter: {}
    });

    const firstCallArg = listAuditEvents.mock.calls[0]?.[0] as {filter?: AuditFilter} | undefined;
    expect(firstCallArg?.filter?.limit).toBe(DEFAULT_AUDIT_PAGE_LIMIT);
    expect(page.events).toEqual([]);
    expect(page.next_cursor).toBeUndefined();
  });
});
