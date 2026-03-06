import React, {useEffect, useMemo, useRef, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {OpenApiIntegrationWriteSchema} from '@broker-interceptor/schemas';

import {BrokerAdminApiClient} from '../../api/client';
import {AppIcon} from '../../components/AppIcon';
import {ErrorNotice} from '../../components/ErrorNotice';
import {MobileEntityList} from '../../components/MobileEntityList';
import {Panel} from '../../components/Panel';
import {ToggleSwitch} from '../../components/ToggleSwitch';
import {useAdminStore} from '../../store/adminStore';
import {
  buildIntegrationSecretMaterial,
  hasRequiredIntegrationSecretMaterial,
  type IntegrationSecretType
} from './integrationSecretMaterial';

type IntegrationPreset = {
  id: string;
  label: string;
  provider: string;
  name: string;
  templateId?: string;
  secretType: IntegrationSecretType;
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
  },
  {
    id: 's3-sigv4',
    label: 'S3 / SigV4',
    provider: 's3',
    name: 'backup-s3',
    templateId: undefined,
    secretType: 'aws_sigv4'
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
  const AUTOSAVE_DEBOUNCE_MS = 500;
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);
  const adminPrincipal = useAdminStore(state => state.adminPrincipal);
  const queryClient = useQueryClient();

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [provider, setProvider] = useState('openai');
  const [name, setName] = useState('openai-prod');
  const [createTemplateId, setCreateTemplateId] = useState('');
  const [secretType, setSecretType] = useState<IntegrationSecretType>('api_key');
  const [secretValue, setSecretValue] = useState('');
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [sessionToken, setSessionToken] = useState('');
  const [region, setRegion] = useState('');
  const [draftsByIntegrationId, setDraftsByIntegrationId] = useState<Record<string, IntegrationDraft>>({});
  const [savingByIntegrationId, setSavingByIntegrationId] = useState<Record<string, boolean>>({});
  const [saveErrorByIntegrationId, setSaveErrorByIntegrationId] = useState<Record<string, string | undefined>>({});
  const autosaveTimeoutsRef = useRef<Record<string, number>>({});

  const normalizedProvider = provider.trim();
  const normalizedName = name.trim();
  const normalizedCreateTemplateId = createTemplateId.trim();
  const hasRequiredSecretMaterial = hasRequiredIntegrationSecretMaterial({
    secretType,
    secretValue,
    accessKeyId,
    secretAccessKey,
    sessionToken,
    region
  });

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
        secret_material: buildIntegrationSecretMaterial({
          secretType,
          secretValue,
          accessKeyId,
          secretAccessKey,
          sessionToken,
          region
        })
      });

      return api.createIntegration({tenantId: selectedTenantId ?? '', payload});
    },
    onSuccess: async () => {
      setSecretValue('');
      setAccessKeyId('');
      setSecretAccessKey('');
      setSessionToken('');
      setRegion('');
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
      })
  });
  const deleteIntegrationMutation = useMutation({
    mutationFn: (input: {integrationId: string}) => api.deleteIntegration({integrationId: input.integrationId}),
    onSuccess: async () => {
      await queryClient.invalidateQueries({queryKey: ['integrations', selectedTenantId]});
      await queryClient.invalidateQueries({queryKey: ['policies']});
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
    !hasRequiredSecretMaterial ||
    createIntegrationMutation.isPending;

  const integrations = useMemo(() => integrationsQuery.data?.integrations ?? [], [integrationsQuery.data]);
  const canDeleteIntegrations = adminPrincipal?.roles.includes('owner') ?? false;
  const showOwnerOnlyDeleteHint = adminPrincipal ? !adminPrincipal.roles.includes('owner') : false;

  useEffect(
    () => () => {
      Object.values(autosaveTimeoutsRef.current).forEach(timeoutId => window.clearTimeout(timeoutId));
      autosaveTimeoutsRef.current = {};
    },
    []
  );

  const getDraftForIntegration = (integration: (typeof integrations)[number]): IntegrationDraft =>
    draftsByIntegrationId[integration.integration_id] ?? {
      enabled: integration.enabled,
      templateId: integration.template_id
    };

  const clearAutosaveTimeout = (integrationId: string) => {
    const timeoutId = autosaveTimeoutsRef.current[integrationId];
    if (timeoutId !== undefined) {
      window.clearTimeout(timeoutId);
      delete autosaveTimeoutsRef.current[integrationId];
    }
  };

  const persistIntegrationDraft = async (integration: (typeof integrations)[number], draft: IntegrationDraft) => {
    const integrationId = integration.integration_id;
    setSavingByIntegrationId(current => ({...current, [integrationId]: true}));
    setSaveErrorByIntegrationId(current => ({...current, [integrationId]: undefined}));

    try {
      await updateIntegrationMutation.mutateAsync({
        integrationId,
        enabled: draft.enabled,
        templateId: draft.templateId.trim()
      });

      setDraftsByIntegrationId(current => {
        const currentDraft = current[integrationId];
        if (!currentDraft) {
          return current;
        }

        if (currentDraft.enabled !== draft.enabled || currentDraft.templateId.trim() !== draft.templateId.trim()) {
          return current;
        }

        const next = {...current};
        delete next[integrationId];
        return next;
      });

      await queryClient.invalidateQueries({queryKey: ['integrations', selectedTenantId]});
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to save integration changes.';
      setSaveErrorByIntegrationId(current => ({...current, [integrationId]: message}));
    } finally {
      setSavingByIntegrationId(current => ({...current, [integrationId]: false}));
    }
  };

  const scheduleIntegrationAutosave = (integration: (typeof integrations)[number], draft: IntegrationDraft) => {
    clearAutosaveTimeout(integration.integration_id);
    autosaveTimeoutsRef.current[integration.integration_id] = window.setTimeout(() => {
      void persistIntegrationDraft(integration, draft);
    }, AUTOSAVE_DEBOUNCE_MS);
  };

  const setIntegrationDraft = (integration: (typeof integrations)[number], updater: (draft: IntegrationDraft) => IntegrationDraft) => {
    const currentDraft = getDraftForIntegration(integration);
    const nextDraft = updater(currentDraft);
    const integrationId = integration.integration_id;
    const matchesPersistedState =
      nextDraft.enabled === integration.enabled && nextDraft.templateId.trim() === integration.template_id.trim();

    setSaveErrorByIntegrationId(current => ({...current, [integrationId]: undefined}));

    if (matchesPersistedState) {
      clearAutosaveTimeout(integrationId);
      setDraftsByIntegrationId(current => {
        const next = {...current};
        delete next[integrationId];
        return next;
      });
      return;
    }

    setDraftsByIntegrationId(current => ({
      ...current,
      [integrationId]: nextDraft
    }));
    scheduleIntegrationAutosave(integration, nextDraft);
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
                <option value="aws_sigv4">aws_sigv4</option>
              </select>
            </label>
          </div>

          {secretType === 'aws_sigv4' ? (
            <>
              <div className="inline-form">
                <label className="field">
                  <span>Access key ID</span>
                  <input
                    value={accessKeyId}
                    onChange={event => setAccessKeyId(event.currentTarget.value)}
                    autoComplete="off"
                    placeholder="AKIA..."
                  />
                </label>

                <label className="field">
                  <span>Region</span>
                  <input
                    value={region}
                    onChange={event => setRegion(event.currentTarget.value)}
                    autoComplete="off"
                    placeholder="eu-west-1"
                  />
                </label>
              </div>
              <p className="helper-text">
                Region is required for SigV4 credentials. For non-AWS or custom S3-compatible hosts, use the explicit
                region expected by the upstream signer configuration.
              </p>

              <label className="field wide">
                <span>Secret access key</span>
                <input
                  value={secretAccessKey}
                  onChange={event => setSecretAccessKey(event.currentTarget.value)}
                  type="password"
                  autoComplete="new-password"
                  placeholder="AWS secret access key"
                />
              </label>

              <label className="field wide">
                <span>Session token (optional)</span>
                <input
                  value={sessionToken}
                  onChange={event => setSessionToken(event.currentTarget.value)}
                  type="password"
                  autoComplete="new-password"
                  placeholder="Temporary credentials session token"
                />
              </label>
            </>
          ) : (
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
          )}

          <p className="helper-text">
            Template selection is required before creating an integration. For S3-compatible storage, choose
            `aws_sigv4` secret material and pair it with a template path group that enables S3 SigV4 upstream auth.
            Backup flows also require a bucket-root list path group for `GET /?list-type=2...`.
          </p>

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
          integrationsQuery.error ??
          templatesQuery.error ??
          createIntegrationMutation.error ??
          updateIntegrationMutation.error ??
          deleteIntegrationMutation.error
        }
      />

      <p className="helper-text">
        Template disable/enable metadata is not currently exposed by the API, so template selectors list all known templates.
      </p>
      {showOwnerOnlyDeleteHint ? <p className="helper-text">Only owner role can delete integrations.</p> : null}

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
        renderDetail={(integration, controls) => {
          const draft = getDraftForIntegration(integration);
          const isSaving = savingByIntegrationId[integration.integration_id] ?? false;
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
                  disabled={isSaving}
                  onChange={nextEnabled =>
                    setIntegrationDraft(integration, current => ({
                      ...current,
                      enabled: nextEnabled
                    }))
                  }
                />
              </div>
              {canDeleteIntegrations ? (
                <button
                  type="button"
                  className="btn-danger"
                  disabled={deleteIntegrationMutation.isPending}
                  onClick={() => {
                    if (!window.confirm(`Delete integration ${integration.name} (${integration.integration_id})?`)) {
                      return;
                    }
                    clearAutosaveTimeout(integration.integration_id);
                    deleteIntegrationMutation.mutate({integrationId: integration.integration_id});
                    controls.close();
                  }}
                >
                  Delete integration
                </button>
              ) : null}
            </div>
          );
        }}
      />

      <div className="table-shell desktop-table-shell">
        <table className="data-table integrations-table">
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
              const isSaving = savingByIntegrationId[integration.integration_id] ?? false;
              const saveError = saveErrorByIntegrationId[integration.integration_id];

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
                  <td className="integration-enabled-cell">
                    <div className="stack-form integration-enabled-stack">
                      <ToggleSwitch
                        checked={draft.enabled}
                        label={draft.enabled ? 'Enabled' : 'Disabled'}
                        disabled={isSaving}
                        onChange={nextEnabled =>
                          setIntegrationDraft(integration, current => ({
                            ...current,
                            enabled: nextEnabled
                          }))
                        }
                      />
                      {saveError ? <span className="error-notice">{saveError}</span> : null}
                    </div>
                  </td>
                  <td className="integration-actions-cell">
                    <div className="row-actions integration-actions">
                      {canDeleteIntegrations ? (
                        <button
                          type="button"
                          className="btn-danger"
                          disabled={deleteIntegrationMutation.isPending}
                          onClick={() => {
                            if (!window.confirm(`Delete integration ${integration.name} (${integration.integration_id})?`)) {
                              return;
                            }
                            clearAutosaveTimeout(integration.integration_id);
                            deleteIntegrationMutation.mutate({integrationId: integration.integration_id});
                          }}
                        >
                          Delete
                        </button>
                      ) : null}
                    </div>
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
