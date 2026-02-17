import React, {useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {OpenApiTemplateSchema, type OpenApiTemplate} from '@broker-interceptor/schemas';

import {BrokerAdminApiClient} from '../../api/client';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';

const toCsvList = (value: string) =>
  value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);

type TemplatesPanelProps = {
  api: BrokerAdminApiClient;
};

const defaultEditorState = {
  templateId: '',
  version: '1',
  provider: 'openai',
  description: '',
  allowedHosts: '',
  pathGroupId: 'responses_create',
  riskTier: 'low' as 'low' | 'medium' | 'high',
  approvalMode: 'none' as 'none' | 'required',
  method: 'POST' as 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  pathPattern: '^/v1/responses$',
  queryAllowlist: '',
  headerForwardAllowlist: 'content-type,accept',
  maxBodyBytes: '262144',
  contentTypes: 'application/json'
};

export const TemplatesPanel = ({api}: TemplatesPanelProps) => {
  const queryClient = useQueryClient();

  const [showEditor, setShowEditor] = useState(false);
  const [editorMode, setEditorMode] = useState<'new' | 'edit'>('new');

  const [templateId, setTemplateId] = useState(defaultEditorState.templateId);
  const [version, setVersion] = useState(defaultEditorState.version);
  const [provider, setProvider] = useState(defaultEditorState.provider);
  const [description, setDescription] = useState(defaultEditorState.description);
  const [allowedHosts, setAllowedHosts] = useState(defaultEditorState.allowedHosts);
  const [pathGroupId, setPathGroupId] = useState(defaultEditorState.pathGroupId);
  const [riskTier, setRiskTier] = useState<'low' | 'medium' | 'high'>(defaultEditorState.riskTier);
  const [approvalMode, setApprovalMode] = useState<'none' | 'required'>(defaultEditorState.approvalMode);
  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>(defaultEditorState.method);
  const [pathPattern, setPathPattern] = useState(defaultEditorState.pathPattern);
  const [queryAllowlist, setQueryAllowlist] = useState(defaultEditorState.queryAllowlist);
  const [headerForwardAllowlist, setHeaderForwardAllowlist] = useState(defaultEditorState.headerForwardAllowlist);
  const [maxBodyBytes, setMaxBodyBytes] = useState(defaultEditorState.maxBodyBytes);
  const [contentTypes, setContentTypes] = useState(defaultEditorState.contentTypes);

  const templatesQuery = useQuery({
    queryKey: ['templates'],
    queryFn: ({signal}) => api.listTemplates(signal)
  });

  const createTemplateMutation = useMutation({
    mutationFn: async () => {
      const payload = OpenApiTemplateSchema.parse({
        template_id: templateId.trim(),
        version: Number.parseInt(version, 10),
        provider: provider.trim(),
        ...(description.trim() ? {description: description.trim()} : {}),
        allowed_schemes: ['https'],
        allowed_ports: [443],
        allowed_hosts: toCsvList(allowedHosts),
        redirect_policy: {
          mode: 'deny'
        },
        path_groups: [
          {
            group_id: pathGroupId.trim(),
            risk_tier: riskTier,
            approval_mode: approvalMode,
            methods: [method],
            path_patterns: [pathPattern.trim()],
            query_allowlist: toCsvList(queryAllowlist),
            header_forward_allowlist: toCsvList(headerForwardAllowlist),
            body_policy: {
              max_bytes: Number.parseInt(maxBodyBytes, 10),
              content_types: toCsvList(contentTypes)
            }
          }
        ],
        network_safety: {
          deny_private_ip_ranges: true,
          deny_link_local: true,
          deny_loopback: true,
          deny_metadata_ranges: true,
          dns_resolution_required: true
        }
      });

      return api.createTemplate({payload});
    },
    onSuccess: async () => {
      setShowEditor(false);
      await queryClient.invalidateQueries({queryKey: ['templates']});
    }
  });

  const resetEditor = () => {
    setTemplateId(defaultEditorState.templateId);
    setVersion(defaultEditorState.version);
    setProvider(defaultEditorState.provider);
    setDescription(defaultEditorState.description);
    setAllowedHosts(defaultEditorState.allowedHosts);
    setPathGroupId(defaultEditorState.pathGroupId);
    setRiskTier(defaultEditorState.riskTier);
    setApprovalMode(defaultEditorState.approvalMode);
    setMethod(defaultEditorState.method);
    setPathPattern(defaultEditorState.pathPattern);
    setQueryAllowlist(defaultEditorState.queryAllowlist);
    setHeaderForwardAllowlist(defaultEditorState.headerForwardAllowlist);
    setMaxBodyBytes(defaultEditorState.maxBodyBytes);
    setContentTypes(defaultEditorState.contentTypes);
  };

  const openNewEditor = () => {
    setEditorMode('new');
    resetEditor();
    setShowEditor(true);
  };

  const openEditEditor = (template: OpenApiTemplate) => {
    const firstPathGroup = template.path_groups[0];
    const firstMethod = firstPathGroup?.methods[0] ?? 'POST';
    const firstPathPattern = firstPathGroup?.path_patterns[0] ?? '^/v1/responses$';

    setEditorMode('edit');
    setTemplateId(template.template_id);
    setVersion(String(template.version + 1));
    setProvider(template.provider);
    setDescription(template.description ?? '');
    setAllowedHosts(template.allowed_hosts.join(', '));
    setPathGroupId(firstPathGroup?.group_id ?? 'responses_create');
    setRiskTier(firstPathGroup?.risk_tier ?? 'low');
    setApprovalMode(firstPathGroup?.approval_mode ?? 'none');
    setMethod(firstMethod);
    setPathPattern(firstPathPattern);
    setQueryAllowlist(firstPathGroup?.query_allowlist.join(', ') ?? '');
    setHeaderForwardAllowlist(firstPathGroup?.header_forward_allowlist.join(', ') ?? '');
    setMaxBodyBytes(String(firstPathGroup?.body_policy.max_bytes ?? 262144));
    setContentTypes(firstPathGroup?.body_policy.content_types.join(', ') ?? 'application/json');
    setShowEditor(true);
  };

  return (
    <Panel
      title="Templates"
      subtitle="List templates and publish immutable new versions when needed."
      action={
        <button type="button" onClick={openNewEditor}>
          New template
        </button>
      }
    >
      {showEditor ? (
        <form
          className="stack-form"
          onSubmit={event => {
            event.preventDefault();
            createTemplateMutation.mutate();
          }}
        >
          <h3>{editorMode === 'new' ? 'Create template' : 'Publish template update'}</h3>

          <div className="inline-form">
            <label className="field">
              <span>Template ID</span>
              <input value={templateId} onChange={event => setTemplateId(event.currentTarget.value)} />
            </label>

            <label className="field">
              <span>Version</span>
              <input value={version} onChange={event => setVersion(event.currentTarget.value)} inputMode="numeric" />
            </label>

            <label className="field">
              <span>Provider</span>
              <input value={provider} onChange={event => setProvider(event.currentTarget.value)} />
            </label>

            <label className="field wide">
              <span>Description (optional)</span>
              <input value={description} onChange={event => setDescription(event.currentTarget.value)} />
            </label>

            <label className="field wide">
              <span>Allowed hosts (comma-separated)</span>
              <input value={allowedHosts} onChange={event => setAllowedHosts(event.currentTarget.value)} />
            </label>

            <label className="field">
              <span>Path group ID</span>
              <input value={pathGroupId} onChange={event => setPathGroupId(event.currentTarget.value)} />
            </label>

            <label className="field">
              <span>Risk tier</span>
              <select value={riskTier} onChange={event => setRiskTier(event.currentTarget.value as typeof riskTier)}>
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
              </select>
            </label>

            <label className="field">
              <span>Approval mode</span>
              <select
                value={approvalMode}
                onChange={event => setApprovalMode(event.currentTarget.value as typeof approvalMode)}
              >
                <option value="none">none</option>
                <option value="required">required</option>
              </select>
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

            <label className="field wide">
              <span>Path regex pattern</span>
              <input value={pathPattern} onChange={event => setPathPattern(event.currentTarget.value)} />
            </label>

            <label className="field wide">
              <span>Query allowlist (comma-separated)</span>
              <input value={queryAllowlist} onChange={event => setQueryAllowlist(event.currentTarget.value)} />
            </label>

            <label className="field wide">
              <span>Forwarded headers (comma-separated)</span>
              <input
                value={headerForwardAllowlist}
                onChange={event => setHeaderForwardAllowlist(event.currentTarget.value)}
              />
            </label>

            <label className="field">
              <span>Max body bytes</span>
              <input value={maxBodyBytes} onChange={event => setMaxBodyBytes(event.currentTarget.value)} inputMode="numeric" />
            </label>

            <label className="field wide">
              <span>Allowed content types (comma-separated)</span>
              <input value={contentTypes} onChange={event => setContentTypes(event.currentTarget.value)} />
            </label>
          </div>

          <p className="helper-text">
            Templates are immutable contracts. Editing publishes a new version and keeps previous versions intact.
          </p>

          <div className="row-actions">
            <button type="submit" disabled={createTemplateMutation.isPending}>
              {editorMode === 'new' ? 'Create template' : 'Publish new version'}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                setShowEditor(false);
                resetEditor();
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <p className="helper-text">
        Delete/disable actions for templates require backend support and are not yet exposed by the Admin API.
      </p>

      <ErrorNotice error={templatesQuery.error ?? createTemplateMutation.error} />

      <div className="table-shell">
        <table className="data-table">
          <thead>
            <tr>
              <th>Template ID</th>
              <th>Version</th>
              <th>Provider</th>
              <th>Allowed hosts</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {(templatesQuery.data?.templates ?? []).map(template => (
              <tr key={`${template.template_id}:${template.version}`}>
                <td>{template.template_id}</td>
                <td>{template.version}</td>
                <td>{template.provider}</td>
                <td>{template.allowed_hosts.join(', ')}</td>
                <td>
                  <button type="button" className="btn-secondary" onClick={() => openEditEditor(template)}>
                    Edit
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
};
