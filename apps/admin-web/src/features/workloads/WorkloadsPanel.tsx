import React, {useCallback, useMemo, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';

import {BrokerAdminApiClient} from '../../api/client';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';
import {ToggleSwitch} from '../../components/ToggleSwitch';
import {useAdminStore} from '../../store/adminStore';

const toIpAllowlist = (raw: string) => {
  const entries = raw
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);

  return entries.length > 0 ? entries : undefined;
};

type WorkloadsPanelProps = {
  api: BrokerAdminApiClient;
};

export const WorkloadsPanel = ({api}: WorkloadsPanelProps) => {
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);
  const queryClient = useQueryClient();

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [workloadName, setWorkloadName] = useState('');
  const [enrollmentMode, setEnrollmentMode] = useState<'broker_ca' | 'external_ca'>('broker_ca');
  const [ipAllowlist, setIpAllowlist] = useState('');

  const [enrollWorkloadId, setEnrollWorkloadId] = useState('');
  const [enrollmentToken, setEnrollmentToken] = useState('');
  const [csrPem, setCsrPem] = useState('');
  const [requestedTtlSeconds, setRequestedTtlSeconds] = useState('3600');

  const workloadsQuery = useQuery({
    queryKey: ['workloads', selectedTenantId],
    enabled: Boolean(selectedTenantId),
    queryFn: ({signal}) => api.listWorkloads({tenantId: selectedTenantId ?? '', signal})
  });

  const selectedWorkload = useMemo(
    () => (workloadsQuery.data?.workloads ?? []).find(workload => workload.workload_id === enrollWorkloadId),
    [enrollWorkloadId, workloadsQuery.data]
  );

  const createWorkloadMutation = useMutation({
    mutationFn: () =>
      api.createWorkload({
        tenantId: selectedTenantId ?? '',
        payload: {
          name: workloadName,
          enrollment_mode: enrollmentMode,
          ...(toIpAllowlist(ipAllowlist) ? {ip_allowlist: toIpAllowlist(ipAllowlist)} : {})
        }
      }),
    onSuccess: async data => {
      setWorkloadName('');
      setIpAllowlist('');
      setShowCreateForm(false);
      if (data?.workload_id) {
        setEnrollWorkloadId(data.workload_id);
        setEnrollmentToken(data.enrollment_token);
      }
      await queryClient.invalidateQueries({queryKey: ['workloads', selectedTenantId]});
    }
  });

  const updateWorkloadMutation = useMutation({
    mutationFn: (input: {workloadId: string; enabled: boolean; ipAllowlistValue?: string[]}) =>
      api.updateWorkload({
        workloadId: input.workloadId,
        payload: {
          enabled: input.enabled,
          ...(input.ipAllowlistValue ? {ip_allowlist: input.ipAllowlistValue} : {})
        }
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({queryKey: ['workloads', selectedTenantId]});
    }
  });

  const enrollMutation = useMutation({
    mutationFn: () =>
      api.enrollWorkload({
        workloadId: enrollWorkloadId,
        payload: {
          enrollment_token: enrollmentToken,
          csr_pem: csrPem,
          requested_ttl_seconds: Number.parseInt(requestedTtlSeconds, 10)
        }
      })
  });

  const csrGenerationCommands = useMemo(() => {
    if (!selectedWorkload) {
      return '';
    }

    return [
      "cat > workload-openssl.cnf <<'EOF'",
      '[req]',
      'prompt = no',
      'default_md = sha256',
      'distinguished_name = dn',
      'req_extensions = req_ext',
      '[dn]',
      `CN = ${selectedWorkload.name}`,
      '[req_ext]',
      'subjectAltName = @alt_names',
      'extendedKeyUsage = clientAuth',
      '[alt_names]',
      `URI.1 = ${selectedWorkload.mtls_san_uri}`,
      'EOF',
      '',
      'openssl genrsa -out workload.key 2048',
      'openssl req -new -key workload.key -out workload.csr -config workload-openssl.cnf',
      'cat workload.csr'
    ].join('\n');
  }, [selectedWorkload]);

  const downloadFile = useCallback((content: string, filename: string) => {
    const blob = new Blob([content], {type: 'application/x-pem-file'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, []);

  return (
    <Panel
      title="Workloads"
      subtitle="Manage tenant workloads, issue enrollment tokens, and submit workload CSRs."
      action={
        <button type="button" onClick={() => setShowCreateForm(current => !current)}>
          {showCreateForm ? 'Close new workload' : 'New workload'}
        </button>
      }
    >
      {!selectedTenantId ? <p className="muted">Select a tenant first in the Tenants route.</p> : null}

      {showCreateForm ? (
        <form
          className="inline-form"
          onSubmit={event => {
            event.preventDefault();
            if (!selectedTenantId || !workloadName.trim()) {
              return;
            }
            createWorkloadMutation.mutate();
          }}
        >
          <label className="field">
            <span>Name</span>
            <input
              value={workloadName}
              onChange={event => setWorkloadName(event.currentTarget.value)}
              placeholder="payments-worker"
            />
          </label>

          <label className="field">
            <span>Enrollment mode</span>
            <select
              value={enrollmentMode}
              onChange={event => setEnrollmentMode(event.currentTarget.value as typeof enrollmentMode)}
            >
              <option value="broker_ca">broker_ca</option>
              <option value="external_ca">external_ca</option>
            </select>
          </label>

          <label className="field wide">
            <span>IP allowlist (comma-separated, optional)</span>
            <input value={ipAllowlist} onChange={event => setIpAllowlist(event.currentTarget.value)} />
          </label>

          <div className="row-actions">
            <button type="submit" disabled={!selectedTenantId || createWorkloadMutation.isPending}>
              Create workload
            </button>
            <button type="button" className="btn-secondary" onClick={() => setShowCreateForm(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <ErrorNotice error={workloadsQuery.error ?? createWorkloadMutation.error ?? updateWorkloadMutation.error} />

      <p className="helper-text">Click any workload row to target it in the enrollment section below.</p>

      <div className="table-shell">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Enabled</th>
              <th>SAN URI</th>
            </tr>
          </thead>
          <tbody>
            {(workloadsQuery.data?.workloads ?? []).map(workload => (
              <tr
                key={workload.workload_id}
                className={`interactive-row${enrollWorkloadId === workload.workload_id ? ' selected-row' : ''}`}
                onClick={() => setEnrollWorkloadId(workload.workload_id)}
              >
                <td>{workload.workload_id}</td>
                <td>{workload.name}</td>
                <td>
                  <ToggleSwitch
                    checked={workload.enabled}
                    label={workload.enabled ? 'Enabled' : 'Disabled'}
                    disabled={updateWorkloadMutation.isPending}
                    onChange={nextValue =>
                      updateWorkloadMutation.mutate({
                        workloadId: workload.workload_id,
                        enabled: nextValue,
                        ...(workload.ip_allowlist ? {ipAllowlistValue: workload.ip_allowlist} : {})
                      })
                    }
                  />
                </td>
                <td>{workload.mtls_san_uri}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="helper-text">Deleting workloads is not yet exposed by the current Admin API contract.</p>

      <hr className="divider" />

      <form
        className="stack-form"
        onSubmit={event => {
          event.preventDefault();
          if (!enrollWorkloadId || !enrollmentToken || !csrPem.trim()) {
            return;
          }
          enrollMutation.mutate();
        }}
      >
        <h3>Enroll workload certificate</h3>

        <label className="field">
          <span>Workload ID</span>
          <select value={enrollWorkloadId} onChange={event => setEnrollWorkloadId(event.currentTarget.value)}>
            <option value="">Select workload</option>
            {(workloadsQuery.data?.workloads ?? []).map(workload => (
              <option key={workload.workload_id} value={workload.workload_id}>
                {workload.name} ({workload.workload_id})
              </option>
            ))}
          </select>
        </label>

        {selectedWorkload ? (
          <>
            <p className="helper-text">
              Generate a private key and CSR on the tenant machine with the expected SPIFFE SAN URI, then paste the CSR
              PEM here.
            </p>
            <pre className="json-view command-view">{csrGenerationCommands}</pre>
          </>
        ) : null}

        <label className="field">
          <span>Enrollment token</span>
          <input value={enrollmentToken} onChange={event => setEnrollmentToken(event.currentTarget.value)} />
        </label>

        <label className="field">
          <span>Requested TTL seconds</span>
          <input
            value={requestedTtlSeconds}
            onChange={event => setRequestedTtlSeconds(event.currentTarget.value)}
            inputMode="numeric"
          />
        </label>

        <label className="field">
          <span>CSR PEM</span>
          <textarea
            rows={10}
            value={csrPem}
            onChange={event => setCsrPem(event.currentTarget.value)}
            spellCheck={false}
          />
        </label>

        <button type="submit" disabled={enrollMutation.isPending}>
          Submit CSR
        </button>
      </form>

      <ErrorNotice error={enrollMutation.error} />
      {enrollMutation.data ? (
        <div className="enrollment-result">
          <h4>Enrollment Successful</h4>
          <p>
            <strong>Certificate expires:</strong> {enrollMutation.data.expires_at}
          </p>
          <div className="button-row">
            <button
              type="button"
              onClick={() =>
                downloadFile(enrollMutation.data!.client_cert_pem, `${'workload'.replace(/\s+/g, '-')}.crt`)
              }
            >
              Download certificate
            </button>
            <button type="button" onClick={() => downloadFile(enrollMutation.data!.ca_chain_pem, 'ca-chain.pem')}>
              Download CA chain
            </button>
          </div>
          <details>
            <summary>View raw enrollment response</summary>
            <pre className="json-view">{JSON.stringify(enrollMutation.data, null, 2)}</pre>
          </details>
        </div>
      ) : null}
    </Panel>
  );
};
