import React, {useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {useLocation, useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from '../../api/client';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';
import {useAdminStore} from '../../store/adminStore';

type TenantsPanelProps = {
  api: BrokerAdminApiClient;
};

export const TenantsPanel = ({api}: TenantsPanelProps) => {
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);
  const setSelectedTenantId = useAdminStore(state => state.setSelectedTenantId);
  const [name, setName] = useState('');

  const nextPath = (() => {
    const params = new URLSearchParams(location.search);
    const candidate = params.get('next');
    if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//')) {
      return undefined;
    }

    return candidate;
  })();

  const applyTenantSelection = (tenantId: string) => {
    setSelectedTenantId(tenantId);
    if (nextPath) {
      navigate(nextPath, {replace: true});
    }
  };

  const tenantsQuery = useQuery({
    queryKey: ['tenants'],
    queryFn: ({signal}) => api.listTenants(signal)
  });

  const createTenantMutation = useMutation({
    mutationFn: (tenantName: string) => api.createTenant({name: tenantName}),
    onSuccess: async data => {
      setName('');
      if (data?.tenant_id) {
        applyTenantSelection(data.tenant_id);
      }
      await queryClient.invalidateQueries({queryKey: ['tenants']});
    }
  });

  return (
    <Panel
      title="Tenants"
      subtitle="Create tenants and pick the active tenant scope for the rest of the admin tools."
    >
      <form
        className="inline-form"
        onSubmit={event => {
          event.preventDefault();
          if (!name.trim()) {
            return;
          }
          createTenantMutation.mutate(name.trim());
        }}
      >
        <label className="field">
          <span>Name</span>
          <input value={name} onChange={event => setName(event.currentTarget.value)} placeholder="acme-prod" />
        </label>
        <button type="submit" disabled={createTenantMutation.isPending}>
          Create tenant
        </button>
      </form>

      <ErrorNotice error={tenantsQuery.error ?? createTenantMutation.error} />

      <div className="list-grid">
        {(tenantsQuery.data?.tenants ?? []).map(tenant => (
          <button
            key={tenant.tenant_id}
            type="button"
            className={`list-card ${selectedTenantId === tenant.tenant_id ? 'selected' : ''}`}
            onClick={() => applyTenantSelection(tenant.tenant_id)}
          >
            <strong>{tenant.name}</strong>
            <span>{tenant.tenant_id}</span>
          </button>
        ))}
      </div>
    </Panel>
  );
};
