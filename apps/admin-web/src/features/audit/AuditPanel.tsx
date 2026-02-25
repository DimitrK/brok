import React, {useEffect, useMemo, useState} from 'react';
import type {OpenApiAuditEvent} from '@broker-interceptor/schemas';
import {useQuery} from '@tanstack/react-query';
import {useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from '../../api/client';
import {auditFilterSchema, type AuditFilter} from '../../api/querySchemas';
import {AppIcon} from '../../components/AppIcon';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';
import {useOverlayDismiss} from '../../components/useOverlayDismiss';
import {useCursorInfiniteQuery} from '../../components/useCursorInfiniteQuery';
import {useAdminStore} from '../../store/adminStore';
import {
  VirtualizedInfiniteTable,
  type VirtualizedInfiniteTableColumn
} from '../../components/VirtualizedInfiniteTable';
import {
  AUDIT_LOAD_MORE_THRESHOLD_ROWS,
  AUDIT_OVERSCAN_ROWS,
  AUDIT_ROW_HEIGHT_PX,
  AUDIT_VIEWPORT_ROWS
} from './auditEventListWindow';
import {DEFAULT_AUDIT_PAGE_LIMIT, fetchAuditEventPage} from './auditEventPaging';
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

const mobileAuditColumns: VirtualizedInfiniteTableColumn<OpenApiAuditEvent>[] = [
  {
    id: 'timestamp',
    header: 'Timestamp',
    width: 'minmax(0, 1.2fr)',
    renderCell: event => event.timestamp
  },
  {
    id: 'event_type',
    header: 'Event type',
    width: 'minmax(0, 1.1fr)',
    renderCell: event => event.event_type
  },
  {
    id: 'decision',
    header: 'Decision',
    width: 'minmax(0, 0.8fr)',
    renderCell: event => event.decision ?? '-'
  }
];

export const AuditPanel = ({api}: AuditPanelProps) => {
  const navigate = useNavigate();
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);

  const [timeMin, setTimeMin] = useState('');
  const [timeMax, setTimeMax] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [workloadId, setWorkloadId] = useState('');
  const [integrationId, setIntegrationId] = useState('');
  const [actionGroup, setActionGroup] = useState('');
  const [decision, setDecision] = useState<'allowed' | 'denied' | 'approval_required' | 'throttled' | ''>('');
  const [isMobileAuditList, setIsMobileAuditList] = useState(() =>
    typeof window !== 'undefined' ? window.matchMedia('(max-width: 700px)').matches : false
  );

  const [appliedFilter, setAppliedFilter] = useState<AuditFilter>({});
  const [selectedEventId, setSelectedEventId] = useState<string | undefined>();

  const [includeAllObservedHosts, setIncludeAllObservedHosts] = useState(true);
  const [includeQueryKeys, setIncludeQueryKeys] = useState(true);
  const [includeNormalizedHeaders, setIncludeNormalizedHeaders] = useState(true);
  const [includeActionGroup, setIncludeActionGroup] = useState(true);
  const [includeRiskTier, setIncludeRiskTier] = useState(true);
  const [useSuggestedPathPattern, setUseSuggestedPathPattern] = useState(true);
  const tenantsQuery = useQuery({
    queryKey: ['tenants'],
    queryFn: ({signal}) => api.listTenants(signal)
  });
  const workloadsQuery = useQuery({
    queryKey: ['workloads', selectedTenantId],
    enabled: Boolean(selectedTenantId),
    queryFn: ({signal}) => api.listWorkloads({tenantId: selectedTenantId ?? '', signal})
  });
  const integrationsQuery = useQuery({
    queryKey: ['integrations', selectedTenantId],
    enabled: Boolean(selectedTenantId),
    queryFn: ({signal}) => api.listIntegrations({tenantId: selectedTenantId ?? '', signal})
  });

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    const mediaQuery = window.matchMedia('(max-width: 700px)');
    const applyMatch = (matches: boolean) => setIsMobileAuditList(matches);
    applyMatch(mediaQuery.matches);

    const handleChange = (event: MediaQueryListEvent) => applyMatch(event.matches);
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  const filterHash = useMemo(() => JSON.stringify(appliedFilter), [appliedFilter]);

  const auditQuery = useCursorInfiniteQuery({
    queryKey: ['audit-events', filterHash],
    queryPage: ({cursor, signal}) =>
      fetchAuditEventPage({
        api,
        filter: appliedFilter,
        cursor,
        limit: DEFAULT_AUDIT_PAGE_LIMIT,
        signal
      }),
    getItems: page => page.events,
    getNextCursor: page => page.next_cursor,
    getItemKey: event => event.event_id
  });

  const events = auditQuery.items;
  const selectedEvent = useMemo(() => {
    if (!selectedEventId) {
      return undefined;
    }
    return events.find(event => event.event_id === selectedEventId);
  }, [events, selectedEventId]);

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
  const tenantNameById = useMemo(
    () => new Map((tenantsQuery.data?.tenants ?? []).map(tenant => [tenant.tenant_id, tenant.name])),
    [tenantsQuery.data?.tenants]
  );
  const workloadNameById = useMemo(
    () => new Map((workloadsQuery.data?.workloads ?? []).map(workload => [workload.workload_id, workload.name])),
    [workloadsQuery.data?.workloads]
  );
  const integrationNameById = useMemo(
    () => new Map((integrationsQuery.data?.integrations ?? []).map(integration => [integration.integration_id, integration.name])),
    [integrationsQuery.data?.integrations]
  );
  const resolveEntityCell = (entityId: string | null | undefined, fallback: string) => {
    if (!entityId) {
      return '-';
    }
    return <span title={entityId}>{fallback}</span>;
  };
  const auditColumns = useMemo(
    () =>
      isMobileAuditList
        ? mobileAuditColumns
        : [
            {
              id: 'timestamp',
              header: 'Timestamp',
              width: 'minmax(0, 1.25fr)',
              renderCell: (event: OpenApiAuditEvent) => event.timestamp
            },
            {
              id: 'event_type',
              header: 'Event type',
              width: 'minmax(0, 1fr)',
              renderCell: (event: OpenApiAuditEvent) => event.event_type
            },
            {
              id: 'tenant_id',
              header: 'Tenant',
              width: 'minmax(0, 1fr)',
              renderCell: (event: OpenApiAuditEvent) =>
                resolveEntityCell(event.tenant_id, tenantNameById.get(event.tenant_id) ?? event.tenant_id)
            },
            {
              id: 'workload_id',
              header: 'Workload',
              width: 'minmax(0, 1fr)',
              renderCell: (event: OpenApiAuditEvent) =>
                resolveEntityCell(
                  event.workload_id,
                  event.workload_id ? workloadNameById.get(event.workload_id) ?? event.workload_id : '-'
                )
            },
            {
              id: 'integration_id',
              header: 'Integration',
              width: 'minmax(0, 1fr)',
              renderCell: (event: OpenApiAuditEvent) =>
                resolveEntityCell(
                  event.integration_id,
                  event.integration_id ? integrationNameById.get(event.integration_id) ?? event.integration_id : '-'
                )
            },
            {
              id: 'decision',
              header: 'Decision',
              width: 'minmax(0, 0.9fr)',
              renderCell: (event: OpenApiAuditEvent) => event.decision ?? '-'
            },
            {
              id: 'correlation_id',
              header: 'Correlation',
              width: 'minmax(0, 1.4fr)',
              renderCell: (event: OpenApiAuditEvent) => event.correlation_id
            }
          ],
    [integrationNameById, isMobileAuditList, tenantNameById, workloadNameById]
  );
  const closeSelectedEvent = () => setSelectedEventId(undefined);
  const selectedEventOverlay = useOverlayDismiss({
    isOpen: Boolean(selectedEvent),
    onClose: closeSelectedEvent,
    scope: 'audit-selected-event'
  });

  return (
    <Panel
      title="Audit"
      subtitle="Review failing events, inspect canonical descriptors, and draft template contracts from real traffic."
    >
      <form
        className="inline-form mobile-filter-form"
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
          setSelectedEventId(undefined);
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

        <button type="submit" disabled={auditQuery.isFetching && !auditQuery.isFetchingNextPage}>
          Apply filter
        </button>
      </form>

      <ErrorNotice error={auditQuery.error ?? tenantsQuery.error ?? workloadsQuery.error ?? integrationsQuery.error} />

      <p className="helper-text">
        Click an event row to inspect details and draft a template. Matching failing events suggest reusable path
        regex patterns.
      </p>

      <div className="audit-list-controls">
        <p className="helper-text">Loaded {events.length} event(s).</p>
        <p className="helper-text">
          {auditQuery.hasNextPage
            ? auditQuery.isFetchingNextPage
              ? 'Loading more events...'
              : 'Scroll down in the list to load more events.'
            : 'End of list reached.'}
        </p>
      </div>

      <VirtualizedInfiniteTable
        ariaLabel="Audit events list"
        columns={auditColumns}
        items={events}
        rowKey={event => event.event_id}
        rowHeightPx={AUDIT_ROW_HEIGHT_PX}
        viewportRows={AUDIT_VIEWPORT_ROWS}
        overscanRows={AUDIT_OVERSCAN_ROWS}
        hasMore={Boolean(auditQuery.hasNextPage)}
        isLoadingMore={auditQuery.isFetchingNextPage}
        onLoadMore={() => {
          if (auditQuery.hasNextPage && !auditQuery.isFetchingNextPage) {
            void auditQuery.fetchNextPage();
          }
        }}
        loadMoreThresholdRows={AUDIT_LOAD_MORE_THRESHOLD_ROWS}
        selectedRowKey={selectedEventId}
        onRowClick={event => setSelectedEventId(event.event_id)}
        emptyState="No audit events matched this filter."
      />

      <p className="helper-text audit-list-end">
        {auditQuery.hasNextPage ? `Scroll to load more (${events.length} loaded).` : `End of list (${events.length} loaded).`}
      </p>

      {selectedEvent ? (
        <section className="entity-screen">
          <header className="entity-screen-header">
            <button
              type="button"
              className="icon-back-button"
              aria-label="Back to audit list"
              onClick={selectedEventOverlay.requestClose}
            >
              <AppIcon name="arrow-left" />
            </button>
            <strong className="entity-screen-title">Selected event details</strong>
            <span className="entity-screen-spacer" aria-hidden />
          </header>

          <div className="entity-screen-content">
            <section className="management-surface">
              <div className="management-surface-header">
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
                  <input
                    type="checkbox"
                    checked={includeQueryKeys}
                    onChange={event => setIncludeQueryKeys(event.currentTarget.checked)}
                  />
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
                  <input
                    type="checkbox"
                    checked={includeRiskTier}
                    onChange={event => setIncludeRiskTier(event.currentTarget.checked)}
                  />
                  <span className="chip-label">Include risk tier and approval mode</span>
                </label>
              </div>

              <p className="helper-text">
                Matching failing events: {matchingFailingEvents.length}. Suggested path pattern: `
                {suggestedPathPattern ?? 'n/a'}`.
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
          </div>
        </section>
      ) : null}
    </Panel>
  );
};
