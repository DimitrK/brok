import React, {useMemo, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {OpenApiIntegrationWriteSchema} from '@broker-interceptor/schemas';

import {BrokerAdminApiClient} from '../../api/client';
import {AppIcon} from '../../components/AppIcon';
import {ErrorNotice} from '../../components/ErrorNotice';
import {MobileEntityList} from '../../components/MobileEntityList';
import {Panel} from '../../components/Panel';
import {ToggleSwitch} from '../../components/ToggleSwitch';
import {useAdminStore} from '../../store/adminStore';

type IntegrationPreset = {
  id: string;
  label: string;
  provider: string;
  name: string;
  templateId?: string;
  secretType: 'api_key' | 'oauth_refresh_token';
};

const integrationPresets: IntegrationPreset[] = [
  {
    id: 'openai-key',
    label: 'OpenAI key',
    provider: 'openai',
    name: 'openai-prod',
    templateId: 'tpl_openai_core_v1',
    secretType: 'api_key'
  },
  {
    id: 'anthropic-key',
    label: 'Anthropic key',
    provider: 'anthropic',
    name: 'anthropic-prod',
    templateId: 'tpl_anthropic_core_v1',
    secretType: 'api_key'
  },
  {
    id: 'oauth-refresh',
    label: 'OAuth refresh token',
    provider: 'google',
    name: 'google-oauth-prod',
    templateId: undefined,
    secretType: 'oauth_refresh_token'
  }
];

type IntegrationDraft = {
  enabled: boolean;
  templateId: string;
};

type IntegrationsPanelProps = {
  api: BrokerAdminApiClient;
};

export const IntegrationsPanel = ({api}: IntegrationsPanelProps) => {
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);
  const queryClient = useQueryClient();

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [provider, setProvider] = useState('openai');
  const [name, setName] = useState('openai-prod');
  const [createTemplateId, setCreateTemplateId] = useState('');
  const [secretType, setSecretType] = useState<'api_key' | 'oauth_refresh_token'>('api_key');
  const [secretValue, setSecretValue] = useState('');
  const [draftsByIntegrationId, setDraftsByIntegrationId] = useState<Record<string, IntegrationDraft>>({});

  const normalizedProvider = provider.trim();
  const normalizedName = name.trim();
  const normalizedCreateTemplateId = createTemplateId.trim();
  const normalizedSecretValue = secretValue.trim();

  const integrationsQuery = useQuery({
    queryKey: ['integrations', selectedTenantId],
    enabled: Boolean(selectedTenantId),
    queryFn: ({signal}) => api.listIntegrations({tenantId: selectedTenantId ?? '', signal})
  });

  const templatesQuery = useQuery({
    queryKey: ['templates'],
    queryFn: ({signal}) => api.listTemplates(signal)
  });

  const templateOptions = useMemo(() => {
    const byTemplateId = new Map<string, {templateId: string; version: number; provider: string; displayName: string}>();
    for (const template of templatesQuery.data?.templates ?? []) {
      const current = byTemplateId.get(template.template_id);
      if (!current || template.version > current.version) {
        const description = template.description?.trim();
        byTemplateId.set(template.template_id, {
          templateId: template.template_id,
          version: template.version,
          provider: template.provider,
          displayName: description && description.length > 0 ? description : template.template_id
        });
      }
    }

    return [...byTemplateId.values()].sort((left, right) => left.templateId.localeCompare(right.templateId));
  }, [templatesQuery.data]);

  const createIntegrationMutation = useMutation({
    mutationFn: async () => {
      const payload = OpenApiIntegrationWriteSchema.parse({
        provider: normalizedProvider,
        name: normalizedName,
        template_id: normalizedCreateTemplateId,
        secret_material: {
          type: secretType,
          value: normalizedSecretValue
        }
      });

      return api.createIntegration({tenantId: selectedTenantId ?? '', payload});
    },
    onSuccess: async () => {
      setSecretValue('');
      setCreateTemplateId('');
      setShowCreateForm(false);
      await queryClient.invalidateQueries({queryKey: ['integrations', selectedTenantId]});
    }
  });

  const updateIntegrationMutation = useMutation({
    mutationFn: (input: {integrationId: string; enabled: boolean; templateId: string}) =>
      api.updateIntegration({
        integrationId: input.integrationId,
        payload: {
          enabled: input.enabled,
          template_id: input.templateId
        }
      }),
    onSuccess: async (_, variables) => {
      setDraftsByIntegrationId(current => {
        const next = {...current};
        delete next[variables.integrationId];
        return next;
      });
      await queryClient.invalidateQueries({queryKey: ['integrations', selectedTenantId]});
    }
  });

  const applyPreset = (preset: IntegrationPreset) => {
    setProvider(preset.provider);
    setName(preset.name);
    setCreateTemplateId(preset.templateId ?? '');
    setSecretType(preset.secretType);
  };

  const createIntegrationDisabled =
    !selectedTenantId ||
    !normalizedProvider ||
    !normalizedName ||
    !normalizedCreateTemplateId ||
    !normalizedSecretValue ||
    createIntegrationMutation.isPending;

  const integrations = useMemo(() => integrationsQuery.data?.integrations ?? [], [integrationsQuery.data]);

  const getDraftForIntegration = (integration: (typeof integrations)[number]): IntegrationDraft =>
    draftsByIntegrationId[integration.integration_id] ?? {
      enabled: integration.enabled,
      templateId: integration.template_id
    };

  const setIntegrationDraft = (integration: (typeof integrations)[number], updater: (draft: IntegrationDraft) => IntegrationDraft) => {
    setDraftsByIntegrationId(current => {
      const currentDraft = current[integration.integration_id] ?? {
        enabled: integration.enabled,
        templateId: integration.template_id
      };

      return {
        ...current,
        [integration.integration_id]: updater(currentDraft)
      };
    });
  };

  const saveIntegrationDraft = (integration: (typeof integrations)[number], draft: IntegrationDraft) => {
    updateIntegrationMutation.mutate({
      integrationId: integration.integration_id,
      enabled: draft.enabled,
      templateId: draft.templateId.trim()
    });
  };

  return (
    <Panel
      title="Integrations"
      subtitle="Create integrations and manage template binding and enabled status."
      action={
        <button type="button" className="btn-tertiary-icon" onClick={() => setShowCreateForm(current => !current)}>
          <AppIcon name="plus" />
          New
        </button>
      }
    >
      {!selectedTenantId ? <p className="muted">Select a tenant first in the Tenants route.</p> : null}

      {showCreateForm ? (
        <form
          className="stack-form"
          onSubmit={event => {
            event.preventDefault();
            if (!selectedTenantId) {
              return;
            }
            createIntegrationMutation.mutate();
          }}
        >
          <h3>Create integration</h3>

          <div className="preset-row" role="group" aria-label="Integration presets">
            {integrationPresets.map(preset => (
              <button key={preset.id} type="button" className="btn-secondary" onClick={() => applyPreset(preset)}>
                {preset.label}
              </button>
            ))}
          </div>

          <div className="inline-form">
            <label className="field">
              <span>Provider</span>
              <input value={provider} onChange={event => setProvider(event.currentTarget.value)} placeholder="openai" />
            </label>

            <label className="field">
              <span>Integration name</span>
              <input value={name} onChange={event => setName(event.currentTarget.value)} placeholder="openai-prod" />
            </label>

            <label className="field">
              <span>Template</span>
              <select value={createTemplateId} onChange={event => setCreateTemplateId(event.currentTarget.value)}>
                <option value="">Select template</option>
                {templateOptions.map(template => (
                  <option key={template.templateId} value={template.templateId}>
                    {template.displayName === template.templateId
                      ? `${template.templateId} (v${template.version}, ${template.provider})`
                      : `${template.displayName} (${template.templateId}) (v${template.version}, ${template.provider})`}
                  </option>
                ))}
              </select>
            </label>

            <label className="field">
              <span>Secret type</span>
              <select value={secretType} onChange={event => setSecretType(event.currentTarget.value as typeof secretType)}>
                <option value="api_key">api_key</option>
                <option value="oauth_refresh_token">oauth_refresh_token</option>
              </select>
            </label>
          </div>

          <label className="field wide">
            <span>Secret value</span>
            <input
              value={secretValue}
              onChange={event => setSecretValue(event.currentTarget.value)}
              type="password"
              autoComplete="new-password"
              placeholder={secretType === 'api_key' ? 'sk-...' : 'refresh-token'}
            />
          </label>

          <p className="helper-text">Template selection is required before creating an integration.</p>

          <div className="row-actions">
            <button type="submit" disabled={createIntegrationDisabled}>
              Create integration
            </button>
            <button type="button" className="btn-secondary" onClick={() => setShowCreateForm(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <ErrorNotice
        error={
          integrationsQuery.error ?? templatesQuery.error ?? createIntegrationMutation.error ?? updateIntegrationMutation.error
        }
      />

      <p className="helper-text">
        Template disable/enable metadata is not currently exposed by the API, so template selectors list all known templates.
      </p>

      <MobileEntityList
        ariaLabel="Integration list"
        items={integrations}
        emptyState="No integrations available."
        getItemKey={integration => integration.integration_id}
        getSummary={integration => {
          const draft = getDraftForIntegration(integration);
          return {
            title: integration.name,
            subtitle: integration.integration_id,
            statusTone: draft.enabled ? 'positive' : 'neutral'
          };
        }}
        renderDetail={integration => {
          const draft = getDraftForIntegration(integration);
          const isDirty = draft.enabled !== integration.enabled || draft.templateId.trim() !== integration.template_id.trim();
          return (
            <div className="stack-form">
              <label className="field">
                <span>Integration ID</span>
                <input value={integration.integration_id} readOnly />
              </label>
              <label className="field">
                <span>Name</span>
                <input value={integration.name} readOnly />
              </label>
              <label className="field">
                <span>Provider</span>
                <input value={integration.provider} readOnly />
              </label>
              <label className="field">
                <span>Template</span>
                <select
                  value={draft.templateId}
                  onChange={event => {
                    const nextTemplateId = event.currentTarget.value;
                    setIntegrationDraft(integration, current => ({
                      ...current,
                      templateId: nextTemplateId
                    }));
                  }}
                >
                  {templateOptions.map(template => (
                    <option key={template.templateId} value={template.templateId}>
                      {template.displayName === template.templateId
                        ? `${template.templateId} (v${template.version}, ${template.provider})`
                        : `${template.displayName} (${template.templateId}) (v${template.version}, ${template.provider})`}
                    </option>
                  ))}
                </select>
              </label>
              <div className="field">
                <span>Enabled</span>
                <ToggleSwitch
                  checked={draft.enabled}
                  label={draft.enabled ? 'Enabled' : 'Disabled'}
                  disabled={updateIntegrationMutation.isPending}
                  onChange={nextEnabled =>
                    setIntegrationDraft(integration, current => ({
                      ...current,
                      enabled: nextEnabled
                    }))
                  }
                />
              </div>
              <button
                type="button"
                className="btn-secondary"
                disabled={!isDirty || updateIntegrationMutation.isPending}
                onClick={() => saveIntegrationDraft(integration, draft)}
              >
                Save changes
              </button>
            </div>
          );
        }}
      />

      <div className="table-shell desktop-table-shell">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Provider</th>
              <th>Template</th>
              <th>Enabled</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {integrations.map(integration => {
              const draft = getDraftForIntegration(integration);
              const isDirty =
                draft.enabled !== integration.enabled || draft.templateId.trim() !== integration.template_id.trim();

              return (
                <tr key={integration.integration_id}>
                  <td>{integration.integration_id}</td>
                  <td>{integration.name}</td>
                  <td>{integration.provider}</td>
                  <td>
                    <select
                      value={draft.templateId}
                      onChange={event => {
                        const nextTemplateId = event.currentTarget.value;
                        setIntegrationDraft(integration, current => ({
                          ...current,
                          templateId: nextTemplateId
                        }));
                      }}
                    >
                      {templateOptions.map(template => (
                        <option key={template.templateId} value={template.templateId}>
                          {template.displayName === template.templateId
                            ? `${template.templateId} (v${template.version}, ${template.provider})`
                            : `${template.displayName} (${template.templateId}) (v${template.version}, ${template.provider})`}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <ToggleSwitch
                      checked={draft.enabled}
                      label={draft.enabled ? 'Enabled' : 'Disabled'}
                      disabled={updateIntegrationMutation.isPending}
                      onChange={nextEnabled =>
                        setIntegrationDraft(integration, current => ({
                          ...current,
                          enabled: nextEnabled
                        }))
                      }
                    />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="btn-secondary"
                      disabled={!isDirty || updateIntegrationMutation.isPending}
                      onClick={() => saveIntegrationDraft(integration, draft)}
                    >
                      Save
                    </button>
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
