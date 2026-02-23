import {describe, expect, it} from 'vitest';
import type {OpenApiAuditEvent} from '@broker-interceptor/schemas';

import {
  buildPathPatternSuggestion,
  buildTemplateDraftFromAuditEvent,
  collectMatchingFailingEvents,
  getPathFromEvent
} from './templateSuggestion';

const makeEvent = (overrides: Partial<OpenApiAuditEvent>): OpenApiAuditEvent => ({
  event_id: overrides.event_id ?? 'evt_1',
  timestamp: overrides.timestamp ?? '2026-02-22T08:00:00.000Z',
  tenant_id: overrides.tenant_id ?? 'tenant_1',
  correlation_id: overrides.correlation_id ?? 'corr_1',
  event_type: overrides.event_type ?? 'execute',
  decision: overrides.decision ?? 'denied',
  ...overrides
});

describe('templateSuggestion', () => {
  it('suggests regex for multiple path variants', () => {
    const suggested = buildPathPatternSuggestion([
      '/v1/messages/123',
      '/v1/messages/456',
      '/v1/messages/789'
    ]);

    expect(suggested).toBe('^/v1/messages/[^/]+$');
  });

  it('collects matching failing events by host and method', () => {
    const selected = makeEvent({
      event_id: 'evt_selected',
      canonical_descriptor: {
        tenant_id: 'tenant_1',
        workload_id: 'workload_1',
        integration_id: 'integration_1',
        template_id: 'tpl_openai_core_v1',
        template_version: 1,
        method: 'POST',
        canonical_url: 'https://api.openai.com/v1/responses',
        matched_path_group_id: 'responses_create',
        normalized_headers: [{name: 'content-type', value: 'application/json'}],
        query_keys: []
      }
    });

    const matching = makeEvent({
      event_id: 'evt_matching',
      canonical_descriptor: {
        ...selected.canonical_descriptor!,
        canonical_url: 'https://api.openai.com/v1/responses/abc'
      }
    });

    const differentHost = makeEvent({
      event_id: 'evt_other_host',
      canonical_descriptor: {
        ...selected.canonical_descriptor!,
        canonical_url: 'https://api.anthropic.com/v1/messages'
      }
    });

    const collected = collectMatchingFailingEvents(selected, [selected, matching, differentHost]);
    expect(collected.map(event => event.event_id)).toEqual(['evt_selected', 'evt_matching']);
  });

  it('builds a template draft route state from a selected event', () => {
    const selected = makeEvent({
      event_id: 'evt_selected',
      risk_tier: 'high',
      action_group: 'responses_create',
      canonical_descriptor: {
        tenant_id: 'tenant_1',
        workload_id: 'workload_1',
        integration_id: 'integration_1',
        template_id: 'tpl_openai_core_v1',
        template_version: 1,
        method: 'POST',
        canonical_url: 'https://api.openai.com/v1/responses',
        matched_path_group_id: 'responses_create',
        normalized_headers: [
          {name: 'content-type', value: 'application/json'},
          {name: 'accept', value: 'application/json'}
        ],
        query_keys: ['model']
      }
    });

    const another = makeEvent({
      event_id: 'evt_second',
      canonical_descriptor: {
        ...selected.canonical_descriptor!,
        canonical_url: 'https://api.openai.com/v1/responses/xyz'
      }
    });

    const draft = buildTemplateDraftFromAuditEvent({
      selectedEvent: selected,
      allEvents: [selected, another],
      traits: {
        includeAllObservedHosts: true,
        includeActionGroup: true,
        includeNormalizedHeaders: true,
        includeQueryKeys: true,
        includeRiskTier: true,
        useSuggestedPathPattern: true
      }
    });

    expect(draft?.templateDraft.provider).toBe('openai');
    expect(draft?.templateDraft.path_groups[0]?.group_id).toBe('responses_create');
    expect(draft?.templateDraft.path_groups[0]?.path_patterns[0]).toBe('^/v1/responses(?:/.*)?$');
    expect(getPathFromEvent(selected)).toBe('/v1/responses');
  });
});
