import React, {useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {OpenApiPolicyRuleSchema} from '@broker-interceptor/schemas';

import {BrokerAdminApiClient} from '../../api/client';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';
import {useAdminStore} from '../../store/adminStore';

const toCsvList = (value: string) =>
  value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);

type PolicyPreset = {
  id: string;
  label: string;
  ruleType: 'allow' | 'deny' | 'approval_required' | 'rate_limit';
  actionGroup: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  host: string;
  maxBodyBytes?: number;
};

const policyPresets: PolicyPreset[] = [
  {
    id: 'approval-openai-responses',
    label: 'Approval for OpenAI responses',
    ruleType: 'approval_required',
    actionGroup: 'responses_create',
    method: 'POST',
    host: 'api.openai.com',
    maxBodyBytes: 262144
  },
  {
    id: 'allow-low-risk-get',
    label: 'Allow low-risk GET',
    ruleType: 'allow',
    actionGroup: 'models_list',
    method: 'GET',
    host: 'api.openai.com'
  },
  {
    id: 'rate-limit-chat',
    label: 'Rate limit chat completions',
    ruleType: 'rate_limit',
    actionGroup: 'chat_completions',
    method: 'POST',
    host: 'api.openai.com',
    maxBodyBytes: 524288
  }
];

type PoliciesPanelProps = {
  api: BrokerAdminApiClient;
};

export const PoliciesPanel = ({api}: PoliciesPanelProps) => {
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);
  const queryClient = useQueryClient();

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [ruleType, setRuleType] = useState<'allow' | 'deny' | 'approval_required' | 'rate_limit'>('approval_required');
  const [tenantId, setTenantId] = useState(() => selectedTenantId ?? '');
  const [integrationId, setIntegrationId] = useState('');
  const [actionGroup, setActionGroup] = useState('responses_create');
  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>('POST');
  const [host, setHost] = useState('api.openai.com');
  const [queryKeysText, setQueryKeysText] = useState('');
  const [maxBodyBytes, setMaxBodyBytes] = useState('262144');
  const [maxRequests, setMaxRequests] = useState('60');
  const [intervalSeconds, setIntervalSeconds] = useState('60');

  const resolvedTenantId = tenantId.trim() || selectedTenantId || '';
  const normalizedIntegrationId = integrationId.trim();
  const normalizedActionGroup = actionGroup.trim();
  const normalizedHost = host.trim();
  const normalizedMaxBodyBytes = maxBodyBytes.trim();

  const hasRequiredPolicyScope = Boolean(resolvedTenantId && normalizedIntegrationId && normalizedActionGroup && normalizedHost);

  const hasValidRateLimitFields =
    ruleType !== 'rate_limit' || Boolean(maxRequests.trim() && intervalSeconds.trim());

  const policiesQuery = useQuery({
    queryKey: ['policies'],
    queryFn: ({signal}) => api.listPolicies(signal)
  });

  const tenantsQuery = useQuery({
    queryKey: ['tenants'],
    queryFn: ({signal}) => api.listTenants(signal)
  });

  const integrationsQuery = useQuery({
    queryKey: ['integrations', resolvedTenantId],
    enabled: Boolean(resolvedTenantId),
    queryFn: ({signal}) => api.listIntegrations({tenantId: resolvedTenantId, signal})
  });

  const createPolicyMutation = useMutation({
    mutationFn: async () => {
      const queryKeys = toCsvList(queryKeysText);

      const payload = OpenApiPolicyRuleSchema.parse({
        rule_type: ruleType,
        scope: {
          tenant_id: resolvedTenantId,
          integration_id: normalizedIntegrationId,
          action_group: normalizedActionGroup,
          method,
          host: normalizedHost,
          ...(queryKeys.length > 0 ? {query_keys: queryKeys} : {})
        },
        ...(normalizedMaxBodyBytes
          ? {
              constraints: {
                max_body_bytes: Number.parseInt(normalizedMaxBodyBytes, 10)
              }
            }
          : {}),
        ...(ruleType === 'rate_limit'
          ? {
              rate_limit: {
                max_requests: Number.parseInt(maxRequests, 10),
                interval_seconds: Number.parseInt(intervalSeconds, 10)
              }
            }
          : {})
      });

      return api.createPolicy({payload});
    },
    onSuccess: async () => {
      setShowCreateForm(false);
      await queryClient.invalidateQueries({queryKey: ['policies']});
    }
  });

  const deletePolicyMutation = useMutation({
    mutationFn: (policyId: string) => api.deletePolicy({policyId}),
    onSuccess: async () => {
      await queryClient.invalidateQueries({queryKey: ['policies']});
    }
  });

  const createPolicyDisabled = !hasRequiredPolicyScope || !hasValidRateLimitFields || createPolicyMutation.isPending;

  const applyPreset = (preset: PolicyPreset) => {
    setRuleType(preset.ruleType);
    setActionGroup(preset.actionGroup);
    setMethod(preset.method);
    setHost(preset.host);
    setMaxBodyBytes(preset.maxBodyBytes ? String(preset.maxBodyBytes) : '');
  };

  return (
    <Panel
      title="Policies"
      subtitle="Inspect active policy rules and create new rules on demand."
      action={
        <button type="button" onClick={() => setShowCreateForm(current => !current)}>
          {showCreateForm ? 'Close new policy' : 'New policy'}
        </button>
      }
    >
      {showCreateForm ? (
        <form
          className="stack-form"
          onSubmit={event => {
            event.preventDefault();
            createPolicyMutation.mutate();
          }}
        >
          <h3>Create policy rule</h3>

          <div className="preset-row" role="group" aria-label="Policy presets">
            {policyPresets.map(preset => (
              <button key={preset.id} type="button" className="btn-secondary" onClick={() => applyPreset(preset)}>
                {preset.label}
              </button>
            ))}
          </div>

          <div className="inline-form">
            <label className="field">
              <span>Rule type</span>
              <select value={ruleType} onChange={event => setRuleType(event.currentTarget.value as typeof ruleType)}>
                <option value="allow">allow</option>
                <option value="deny">deny</option>
                <option value="approval_required">approval_required</option>
                <option value="rate_limit">rate_limit</option>
              </select>
            </label>

            <label className="field">
              <span>Tenant</span>
              <select
                value={resolvedTenantId}
                onChange={event => {
                  setTenantId(event.currentTarget.value);
                  setIntegrationId('');
                }}
              >
                <option value="">Select tenant</option>
                {(tenantsQuery.data?.tenants ?? []).map(tenant => (
                  <option key={tenant.tenant_id} value={tenant.tenant_id}>
                    {tenant.name} ({tenant.tenant_id})
                  </option>
                ))}
              </select>
            </label>

            <label className="field">
              <span>Integration</span>
              <input
                value={integrationId}
                onChange={event => setIntegrationId(event.currentTarget.value)}
                list="policy-integration-options"
                placeholder="Search by integration ID"
              />
            </label>

            <label className="field">
              <span>Action group</span>
              <input
                value={actionGroup}
                onChange={event => setActionGroup(event.currentTarget.value)}
                list="policy-action-group-options"
                placeholder="responses_create"
              />
            </label>

            <label className="field">
              <span>Method</span>
              <select value={method} onChange={event => setMethod(event.currentTarget.value as typeof method)}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="DELETE">DELETE</option>
              </select>
            </label>

            <label className="field">
              <span>Host</span>
              <input value={host} onChange={event => setHost(event.currentTarget.value)} placeholder="api.openai.com" />
            </label>

            <label className="field wide">
              <span>Allowed query keys (comma-separated, optional)</span>
              <input value={queryKeysText} onChange={event => setQueryKeysText(event.currentTarget.value)} />
            </label>

            <label className="field">
              <span>Max body bytes (optional)</span>
              <input
                value={maxBodyBytes}
                onChange={event => setMaxBodyBytes(event.currentTarget.value)}
                inputMode="numeric"
              />
            </label>

            {ruleType === 'rate_limit' ? (
              <>
                <label className="field">
                  <span>Rate max requests</span>
                  <input value={maxRequests} onChange={event => setMaxRequests(event.currentTarget.value)} inputMode="numeric" />
                </label>

                <label className="field">
                  <span>Rate interval seconds</span>
                  <input
                    value={intervalSeconds}
                    onChange={event => setIntervalSeconds(event.currentTarget.value)}
                    inputMode="numeric"
                  />
                </label>
              </>
            ) : null}
          </div>

          <datalist id="policy-integration-options">
            {(integrationsQuery.data?.integrations ?? []).map(integration => (
              <option
                key={integration.integration_id}
                value={integration.integration_id}
                label={`${integration.name} (${integration.integration_id})`}
              />
            ))}
          </datalist>

          <datalist id="policy-action-group-options">
            <option value="responses_create" />
            <option value="chat_completions" />
            <option value="models_list" />
            <option value="files_upload" />
          </datalist>

          <p className="helper-text">
            Action group values map to template path-group identifiers. The backend currently does not publish a canonical enum list.
          </p>

          {!hasRequiredPolicyScope ? (
            <p className="helper-text">Tenant, Integration, Action group, and Host are required.</p>
          ) : null}

          {ruleType === 'rate_limit' && !hasValidRateLimitFields ? (
            <p className="helper-text">Rate limit rules require max requests and interval seconds.</p>
          ) : null}

          <div className="row-actions">
            <button type="submit" disabled={createPolicyDisabled}>
              Create policy
            </button>
            <button type="button" className="btn-secondary" onClick={() => setShowCreateForm(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <ErrorNotice
        error={
          policiesQuery.error ?? tenantsQuery.error ?? integrationsQuery.error ?? createPolicyMutation.error ?? deletePolicyMutation.error
        }
      />

      <div className="table-shell">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Rule Type</th>
              <th>Tenant</th>
              <th>Integration</th>
              <th>Action Group</th>
              <th>Method</th>
              <th>Host</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {(policiesQuery.data?.policies ?? []).map(policy => {
              const policyId = typeof policy.policy_id === 'string' ? policy.policy_id : undefined;
              return (
                <tr key={policyId ?? `${policy.scope.tenant_id}:${policy.scope.integration_id}:${policy.scope.action_group}`}>
                  <td>{policyId ?? '(generated)'}</td>
                  <td>{policy.rule_type}</td>
                  <td>{policy.scope.tenant_id}</td>
                  <td>{policy.scope.integration_id}</td>
                  <td>{policy.scope.action_group}</td>
                  <td>{policy.scope.method}</td>
                  <td>{policy.scope.host}</td>
                  <td>
                    {policyId ? (
                      <button className="btn-danger" type="button" onClick={() => deletePolicyMutation.mutate(policyId)}>
                        Delete
                      </button>
                    ) : (
                      <span className="muted">No policy_id</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
};
