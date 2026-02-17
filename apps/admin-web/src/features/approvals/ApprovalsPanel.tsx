import React, {useMemo, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {OpenApiPolicyConstraintsSchema, type OpenApiPolicyConstraints} from '@broker-interceptor/schemas';

import {BrokerAdminApiClient} from '../../api/client';
import {approvalStatusFilterSchema, type ApprovalStatusFilter} from '../../api/querySchemas';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';

const toCsvList = (value: string) =>
  value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);

const buildConstraints = (input: {
  maxBodyBytes: string;
  allowedQueryKeys: string;
  recipientDomainAllowlist: string;
  requireMfaApproval: boolean;
}): OpenApiPolicyConstraints | undefined => {
  const constraints: Record<string, unknown> = {};

  if (input.maxBodyBytes.trim()) {
    constraints.max_body_bytes = Number.parseInt(input.maxBodyBytes, 10);
  }

  const queryKeys = toCsvList(input.allowedQueryKeys);
  if (queryKeys.length > 0) {
    constraints.allowed_query_keys = queryKeys;
  }

  const recipientDomains = toCsvList(input.recipientDomainAllowlist);
  if (recipientDomains.length > 0) {
    constraints.recipient_domain_allowlist = recipientDomains;
  }

  if (input.requireMfaApproval) {
    constraints.require_mfa_approval = true;
  }

  return Object.keys(constraints).length > 0 ? OpenApiPolicyConstraintsSchema.parse(constraints) : undefined;
};

type ApprovalsPanelProps = {
  api: BrokerAdminApiClient;
};

export const ApprovalsPanel = ({api}: ApprovalsPanelProps) => {
  const queryClient = useQueryClient();

  const [status, setStatus] = useState<ApprovalStatusFilter>('pending');
  const [mode, setMode] = useState<'once' | 'rule'>('once');
  const [maxBodyBytes, setMaxBodyBytes] = useState('');
  const [allowedQueryKeys, setAllowedQueryKeys] = useState('');
  const [recipientDomainAllowlist, setRecipientDomainAllowlist] = useState('');
  const [requireMfaApproval, setRequireMfaApproval] = useState(false);

  const approvalsQuery = useQuery({
    queryKey: ['approvals', status],
    queryFn: ({signal}) =>
      api.listApprovals({
        status: approvalStatusFilterSchema.parse(status),
        signal
      })
  });

  const approveMutation = useMutation({
    mutationFn: (approvalId: string) => {
      const constraints = buildConstraints({
        maxBodyBytes,
        allowedQueryKeys,
        recipientDomainAllowlist,
        requireMfaApproval
      });

      return api.approveApproval({
        approvalId,
        payload: {
          mode,
          ...(constraints ? {constraints} : {})
        }
      });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({queryKey: ['approvals']});
      await queryClient.invalidateQueries({queryKey: ['policies']});
    }
  });

  const denyMutation = useMutation({
    mutationFn: (approvalId: string) => {
      const constraints = buildConstraints({
        maxBodyBytes,
        allowedQueryKeys,
        recipientDomainAllowlist,
        requireMfaApproval
      });

      return api.denyApproval({
        approvalId,
        payload: {
          mode,
          ...(constraints ? {constraints} : {})
        }
      });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({queryKey: ['approvals']});
    }
  });

  const approvalsCount = useMemo(() => approvalsQuery.data?.approvals.length ?? 0, [approvalsQuery.data]);

  return (
    <Panel title="Approvals" subtitle="Review pending requests and decide approve/deny actions with explicit scope.">
      <form className="stack-form" onSubmit={event => event.preventDefault()}>
        <div className="inline-form">
          <label className="field">
            <span>Status</span>
            <select
              value={status}
              onChange={event => setStatus(approvalStatusFilterSchema.parse(event.currentTarget.value))}
            >
              <option value="pending">pending</option>
              <option value="approved">approved</option>
              <option value="denied">denied</option>
              <option value="expired">expired</option>
            </select>
          </label>

          <label className="field">
            <span>Decision mode</span>
            <select value={mode} onChange={event => setMode(event.currentTarget.value as typeof mode)}>
              <option value="once">once</option>
              <option value="rule">rule</option>
            </select>
          </label>

          <label className="field">
            <span>Max body bytes (optional)</span>
            <input value={maxBodyBytes} onChange={event => setMaxBodyBytes(event.currentTarget.value)} inputMode="numeric" />
          </label>

          <label className="field wide">
            <span>Allowed query keys (optional)</span>
            <input
              value={allowedQueryKeys}
              onChange={event => setAllowedQueryKeys(event.currentTarget.value)}
              placeholder="model,temperature"
            />
          </label>

          <label className="field wide">
            <span>Recipient domain allowlist (optional)</span>
            <input
              value={recipientDomainAllowlist}
              onChange={event => setRecipientDomainAllowlist(event.currentTarget.value)}
              placeholder="example.com,company.org"
            />
          </label>

          <label className="field inline-toggle">
            <input
              type="checkbox"
              checked={requireMfaApproval}
              onChange={event => setRequireMfaApproval(event.currentTarget.checked)}
            />
            <span>Require MFA approval</span>
          </label>
        </div>

        <p className="helper-text">
          Constraint fields are optional and validated against the shared policy-constraints schema before decision submit.
        </p>
      </form>

      <ErrorNotice error={approvalsQuery.error ?? approveMutation.error ?? denyMutation.error} />

      <p className="muted">Approvals in current filter: {approvalsCount}</p>

      <table className="data-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Status</th>
            <th>Integration</th>
            <th>Action group</th>
            <th>Risk tier</th>
            <th>Destination</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(approvalsQuery.data?.approvals ?? []).map(approval => (
            <tr key={approval.approval_id}>
              <td>{approval.approval_id}</td>
              <td>{approval.status}</td>
              <td>{approval.summary.integration_id}</td>
              <td>{approval.summary.action_group}</td>
              <td>{approval.summary.risk_tier}</td>
              <td>{approval.summary.destination_host}</td>
              <td>
                <div className="row-actions">
                  <button
                    type="button"
                    disabled={approval.status !== 'pending' || approveMutation.isPending}
                    onClick={() => approveMutation.mutate(approval.approval_id)}
                  >
                    Approve
                  </button>
                  <button
                    className="btn-danger"
                    type="button"
                    disabled={approval.status !== 'pending' || denyMutation.isPending}
                    onClick={() => denyMutation.mutate(approval.approval_id)}
                  >
                    Deny
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
};
