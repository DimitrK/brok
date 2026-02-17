import React, {useMemo, useState} from 'react';
import {useQuery} from '@tanstack/react-query';

import {BrokerAdminApiClient} from '../../api/client';
import {auditFilterSchema, type AuditFilter} from '../../api/querySchemas';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';

type AuditPanelProps = {
  api: BrokerAdminApiClient;
};

export const AuditPanel = ({api}: AuditPanelProps) => {
  const [timeMin, setTimeMin] = useState('');
  const [timeMax, setTimeMax] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [workloadId, setWorkloadId] = useState('');
  const [integrationId, setIntegrationId] = useState('');
  const [actionGroup, setActionGroup] = useState('');
  const [decision, setDecision] = useState<'allowed' | 'denied' | 'approval_required' | 'throttled' | ''>('');

  const [appliedFilter, setAppliedFilter] = useState<AuditFilter>({});

  const filterHash = useMemo(() => JSON.stringify(appliedFilter), [appliedFilter]);

  const auditQuery = useQuery({
    queryKey: ['audit-events', filterHash],
    queryFn: ({signal}) => api.listAuditEvents({filter: appliedFilter, signal})
  });

  return (
    <Panel title="Audit" subtitle="Query immutable audit events by tenant, workload, integration, and decision.">
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
          {(auditQuery.data?.events ?? []).map(event => (
            <tr key={event.event_id}>
              <td>{event.timestamp}</td>
              <td>{event.event_type}</td>
              <td>{event.tenant_id}</td>
              <td>{event.workload_id ?? '-'}</td>
              <td>{event.integration_id ?? '-'}</td>
              <td>{event.decision ?? '-'}</td>
              <td>{event.correlation_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
};
