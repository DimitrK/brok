import React, {useMemo, useState} from 'react';
import {useQuery} from '@tanstack/react-query';
import {useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from '../../api/client';
import {auditFilterSchema, type AuditFilter} from '../../api/querySchemas';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';
import {
  buildPathPatternSuggestion,
  buildTemplateDraftFromAuditEvent,
  collectMatchingFailingEvents,
  getCanonicalUrlFromEvent,
  getPathFromEvent,
  isFailingAuditEvent,
  TEMPLATE_DRAFT_STORAGE_KEY
} from './templateSuggestion';

type AuditPanelProps = {
  api: BrokerAdminApiClient;
};

export const AuditPanel = ({api}: AuditPanelProps) => {
  const navigate = useNavigate();

  const [timeMin, setTimeMin] = useState('');
  const [timeMax, setTimeMax] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [workloadId, setWorkloadId] = useState('');
  const [integrationId, setIntegrationId] = useState('');
  const [actionGroup, setActionGroup] = useState('');
  const [decision, setDecision] = useState<'allowed' | 'denied' | 'approval_required' | 'throttled' | ''>('');

  const [appliedFilter, setAppliedFilter] = useState<AuditFilter>({});
  const [selectedEventId, setSelectedEventId] = useState<string | undefined>();

  const [includeAllObservedHosts, setIncludeAllObservedHosts] = useState(true);
  const [includeQueryKeys, setIncludeQueryKeys] = useState(true);
  const [includeNormalizedHeaders, setIncludeNormalizedHeaders] = useState(true);
  const [includeActionGroup, setIncludeActionGroup] = useState(true);
  const [includeRiskTier, setIncludeRiskTier] = useState(true);
  const [useSuggestedPathPattern, setUseSuggestedPathPattern] = useState(true);

  const filterHash = useMemo(() => JSON.stringify(appliedFilter), [appliedFilter]);

  const auditQuery = useQuery({
    queryKey: ['audit-events', filterHash],
    queryFn: ({signal}) => api.listAuditEvents({filter: appliedFilter, signal})
  });

  const events = useMemo(() => auditQuery.data?.events ?? [], [auditQuery.data]);
  const failingEvents = useMemo(() => events.filter(isFailingAuditEvent), [events]);

  const resolvedSelectedEventId =
    selectedEventId && events.some(event => event.event_id === selectedEventId)
      ? selectedEventId
      : (failingEvents[0]?.event_id ?? events[0]?.event_id);

  const selectedEvent = useMemo(
    () => events.find(event => event.event_id === resolvedSelectedEventId),
    [events, resolvedSelectedEventId]
  );

  const matchingFailingEvents = useMemo(
    () => (selectedEvent ? collectMatchingFailingEvents(selectedEvent, events) : []),
    [events, selectedEvent]
  );

  const suggestedPathPattern = useMemo(() => {
    const paths = matchingFailingEvents.map(event => getPathFromEvent(event)).filter(Boolean) as string[];
    return buildPathPatternSuggestion(paths);
  }, [matchingFailingEvents]);

  const draftRouteState = useMemo(() => {
    if (!selectedEvent) {
      return null;
    }

    return buildTemplateDraftFromAuditEvent({
      selectedEvent,
      allEvents: events,
      traits: {
        includeAllObservedHosts,
        includeQueryKeys,
        includeNormalizedHeaders,
        includeActionGroup,
        includeRiskTier,
        useSuggestedPathPattern
      }
    });
  }, [
    events,
    includeActionGroup,
    includeAllObservedHosts,
    includeNormalizedHeaders,
    includeQueryKeys,
    includeRiskTier,
    selectedEvent,
    useSuggestedPathPattern
  ]);

  return (
    <Panel
      title="Audit"
      subtitle="Review failing events, inspect canonical descriptors, and draft template contracts from real traffic."
    >
      <form
        className="inline-form"
        onSubmit={event => {
          event.preventDefault();

          const nextFilter = auditFilterSchema.parse({
            ...(timeMin ? {time_min: new Date(timeMin).toISOString()} : {}),
            ...(timeMax ? {time_max: new Date(timeMax).toISOString()} : {}),
            ...(tenantId.trim() ? {tenant_id: tenantId.trim()} : {}),
            ...(workloadId.trim() ? {workload_id: workloadId.trim()} : {}),
            ...(integrationId.trim() ? {integration_id: integrationId.trim()} : {}),
            ...(actionGroup.trim() ? {action_group: actionGroup.trim()} : {}),
            ...(decision ? {decision} : {})
          });

          setAppliedFilter(nextFilter);
        }}
      >
        <label className="field">
          <span>Time min</span>
          <input type="datetime-local" value={timeMin} onChange={event => setTimeMin(event.currentTarget.value)} />
        </label>

        <label className="field">
          <span>Time max</span>
          <input type="datetime-local" value={timeMax} onChange={event => setTimeMax(event.currentTarget.value)} />
        </label>

        <label className="field">
          <span>Tenant ID</span>
          <input value={tenantId} onChange={event => setTenantId(event.currentTarget.value)} />
        </label>

        <label className="field">
          <span>Workload ID</span>
          <input value={workloadId} onChange={event => setWorkloadId(event.currentTarget.value)} />
        </label>

        <label className="field">
          <span>Integration ID</span>
          <input value={integrationId} onChange={event => setIntegrationId(event.currentTarget.value)} />
        </label>

        <label className="field">
          <span>Action group</span>
          <input value={actionGroup} onChange={event => setActionGroup(event.currentTarget.value)} />
        </label>

        <label className="field">
          <span>Decision</span>
          <select
            value={decision}
            onChange={event =>
              setDecision(
                event.currentTarget.value as 'allowed' | 'denied' | 'approval_required' | 'throttled' | ''
              )
            }
          >
            <option value="">any</option>
            <option value="allowed">allowed</option>
            <option value="denied">denied</option>
            <option value="approval_required">approval_required</option>
            <option value="throttled">throttled</option>
          </select>
        </label>

        <button type="submit" disabled={auditQuery.isFetching}>
          Apply filter
        </button>
      </form>

      <ErrorNotice error={auditQuery.error} />

      <p className="helper-text">
        Click a failing event row to inspect details and draft a template. Matching failing events suggest reusable path
        regex patterns.
      </p>

      <div className="table-shell">
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Event type</th>
              <th>Tenant</th>
              <th>Workload</th>
              <th>Integration</th>
              <th>Decision</th>
              <th>Correlation</th>
            </tr>
          </thead>
          <tbody>
            {events.map(event => {
              const selected = event.event_id === resolvedSelectedEventId;
              return (
                <tr
                  key={event.event_id}
                  className={`interactive-row${selected ? ' selected-row' : ''}`}
                  onClick={() => setSelectedEventId(event.event_id)}
                >
                  <td>{event.timestamp}</td>
                  <td>{event.event_type}</td>
                  <td>{event.tenant_id}</td>
                  <td>{event.workload_id ?? '-'}</td>
                  <td>{event.integration_id ?? '-'}</td>
                  <td>{event.decision ?? '-'}</td>
                  <td>{event.correlation_id}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {selectedEvent ? (
        <section className="management-surface">
          <div className="management-surface-header">
            <h3>Selected event details</h3>
            <p>
              Event `{selectedEvent.event_id}` | Decision `{selectedEvent.decision ?? 'n/a'}` | Correlation `
              {selectedEvent.correlation_id}`
            </p>
          </div>

          <div className="editor-grid">
            <label className="field wide">
              <span>Canonical URL</span>
              <input value={getCanonicalUrlFromEvent(selectedEvent)} readOnly />
            </label>

            <label className="field">
              <span>Path</span>
              <input value={getPathFromEvent(selectedEvent) ?? 'Unavailable'} readOnly />
            </label>

            <label className="field">
              <span>Matched action group</span>
              <input
                value={
                  selectedEvent.canonical_descriptor?.matched_path_group_id ?? selectedEvent.action_group ?? 'Unavailable'
                }
                readOnly
              />
            </label>

            <label className="field wide">
              <span>Query keys</span>
              <input value={(selectedEvent.canonical_descriptor?.query_keys ?? []).join(', ')} readOnly />
            </label>

            <label className="field wide">
              <span>Normalized headers</span>
              <input
                value={
                  (selectedEvent.canonical_descriptor?.normalized_headers ?? [])
                    .map(header => header.name)
                    .join(', ') || 'none'
                }
                readOnly
              />
            </label>
          </div>

          <hr className="divider" />

          <div className="management-surface-header">
            <h3>Template traits from this event</h3>
            <p>Select which event traits should be included in the template draft.</p>
          </div>

          <div className="checkbox-grid">
            <label className="chip-checkbox">
              <input
                type="checkbox"
                checked={includeAllObservedHosts}
                onChange={event => setIncludeAllObservedHosts(event.currentTarget.checked)}
              />
              <span className="chip-label">Include all matched failing hosts</span>
            </label>

            <label className="chip-checkbox">
              <input
                type="checkbox"
                checked={useSuggestedPathPattern}
                onChange={event => setUseSuggestedPathPattern(event.currentTarget.checked)}
              />
              <span className="chip-label">Use suggested path regex from matches</span>
            </label>

            <label className="chip-checkbox">
              <input type="checkbox" checked={includeQueryKeys} onChange={event => setIncludeQueryKeys(event.currentTarget.checked)} />
              <span className="chip-label">Include query keys</span>
            </label>

            <label className="chip-checkbox">
              <input
                type="checkbox"
                checked={includeNormalizedHeaders}
                onChange={event => setIncludeNormalizedHeaders(event.currentTarget.checked)}
              />
              <span className="chip-label">Include normalized header names</span>
            </label>

            <label className="chip-checkbox">
              <input
                type="checkbox"
                checked={includeActionGroup}
                onChange={event => setIncludeActionGroup(event.currentTarget.checked)}
              />
              <span className="chip-label">Use action group as path-group ID</span>
            </label>

            <label className="chip-checkbox">
              <input type="checkbox" checked={includeRiskTier} onChange={event => setIncludeRiskTier(event.currentTarget.checked)} />
              <span className="chip-label">Include risk tier and approval mode</span>
            </label>
          </div>

          <p className="helper-text">
            Matching failing events: {matchingFailingEvents.length}. Suggested path pattern: `{suggestedPathPattern}`.
          </p>

          <div className="row-actions">
            <button
              type="button"
              disabled={!isFailingAuditEvent(selectedEvent) || !draftRouteState}
              onClick={() => {
                if (!draftRouteState) {
                  return;
                }
                if (typeof window !== 'undefined') {
                  window.sessionStorage.setItem(TEMPLATE_DRAFT_STORAGE_KEY, JSON.stringify(draftRouteState));
                }
                navigate('/templates?draft=audit');
              }}
            >
              Open template draft
            </button>
          </div>

          {!isFailingAuditEvent(selectedEvent) ? (
            <p className="helper-text">Template drafting is available only for failing decisions.</p>
          ) : null}

          <pre className="json-view">{JSON.stringify(selectedEvent, null, 2)}</pre>
        </section>
      ) : null}
    </Panel>
  );
};
