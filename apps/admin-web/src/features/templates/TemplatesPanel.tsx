import React, {useEffect, useMemo, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {OpenApiTemplateSchema, type OpenApiTemplate} from '@broker-interceptor/schemas';
import {useLocation, useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from '../../api/client';
import {ApiClientError} from '../../api/errors';
import {AppIcon} from '../../components/AppIcon';
import {ErrorNotice} from '../../components/ErrorNotice';
import {MobileEntityList} from '../../components/MobileEntityList';
import {Panel} from '../../components/Panel';
import {useOverlayDismiss} from '../../components/useOverlayDismiss';
import {useAdminStore} from '../../store/adminStore';
import {
  TEMPLATE_ID_PREFIX,
  buildTemplateId,
  normalizeTemplateIdSuffix,
  splitTemplateId,
  toCsvList,
  toLineList
} from './templateHelpers';
import {
  checkTemplateCurlRequest,
  type TemplateRequestCheck
} from './pathGroupRequestCheck';
import {
  buildTemplateVersionIndex,
  getLatestTemplateVersions,
  summarizeTemplateVersionDiff
} from './templateVersioning';
import {parseTemplateDiffSummaryLine} from './templateDiffPresentation';
import {
  createEmptyTemplateUpstreamAuthDraft,
  buildTemplatePathGroupConstraints,
  getTemplateUpstreamAuthAdapter,
  resolveTemplateUpstreamAuthDraft,
  s3ListObjectsPathGroupPreset,
  templateUpstreamAuthOptions,
  type TemplateUpstreamAuthDraft,
  type TemplateUpstreamAuthMode
} from './templateUpstreamAuth';
import {TEMPLATE_DRAFT_STORAGE_KEY, type TemplateDraft} from './templateDraftRoute';

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

const httpMethods: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

type TemplatesPanelProps = {
  api: BrokerAdminApiClient;
  initialTemplateDraft?: TemplateDraft;
};

type PathGroupDraft = {
  draftId: string;
  groupId: string;
  riskTier: 'low' | 'medium' | 'high';
  approvalMode: 'none' | 'required';
  methods: HttpMethod[];
  pathPatterns: string;
  queryAllowlist: string;
  headerForwardAllowlist: string;
  maxBodyBytes: string;
  contentTypes: string;
} & TemplateUpstreamAuthDraft;

let pathGroupDraftCounter = 0;
const nextPathGroupDraftId = () => {
  pathGroupDraftCounter += 1;
  return `path-group-${pathGroupDraftCounter}`;
};

const createPathGroupDraft = (input: Partial<Omit<PathGroupDraft, 'draftId'>> = {}): PathGroupDraft => ({
  draftId: nextPathGroupDraftId(),
  groupId: input.groupId ?? 'responses_create',
  riskTier: input.riskTier ?? 'low',
  approvalMode: input.approvalMode ?? 'none',
  methods: input.methods ?? ['POST'],
  pathPatterns: input.pathPatterns ?? '^/v1/responses$',
  queryAllowlist: input.queryAllowlist ?? '',
  headerForwardAllowlist: input.headerForwardAllowlist ?? 'content-type,accept',
  maxBodyBytes: input.maxBodyBytes ?? '262144',
  contentTypes: input.contentTypes ?? 'application/json',
  ...createEmptyTemplateUpstreamAuthDraft(input.upstreamAuthMode ?? 'none'),
  ...input
});

const defaultTemplateName = 'OpenAI Core';

type TemplateRequestTesterProps = {
  pathGroups: PathGroupDraft[];
  allowedHosts: string[];
};

const TemplateRequestTester = ({pathGroups, allowedHosts}: TemplateRequestTesterProps) => {
  const [curlInput, setCurlInput] = useState('');
  const [checkResult, setCheckResult] = useState<TemplateRequestCheck | undefined>();
  const [checkError, setCheckError] = useState<string | undefined>();

  useEffect(() => {
    const normalizedCurl = curlInput.trim();
    if (!normalizedCurl) {
      return;
    }

    const debounceId = window.setTimeout(() => {
      try {
        const result = checkTemplateCurlRequest({
          curl: normalizedCurl,
          allowedHosts,
          pathGroups: pathGroups.map(pathGroup => ({
            groupId: pathGroup.groupId.trim() || 'unnamed-group',
            methods: pathGroup.methods,
            pathPatterns: toLineList(pathGroup.pathPatterns)
          }))
        });
        setCheckResult(result);
        setCheckError(undefined);
      } catch (error) {
        setCheckResult(undefined);
        setCheckError(error instanceof Error ? error.message : 'Unable to parse cURL request.');
      }
    }, 500);

    return () => {
      window.clearTimeout(debounceId);
    };
  }, [allowedHosts, curlInput, pathGroups]);

  return (
    <details className="pathgroup-request-test">
      <summary>Test template</summary>
      <div className="pathgroup-request-test-body">
        <p className="helper-text">
          Paste a cURL request to test template matching across all configured path groups. Evaluation is debounced by
          500ms.
        </p>

        <label className="field">
          <span>cURL request</span>
          <textarea
            rows={5}
            value={curlInput}
            onChange={event => {
              const nextValue = event.currentTarget.value;
              setCurlInput(nextValue);
              if (!nextValue.trim()) {
                setCheckResult(undefined);
                setCheckError(undefined);
              }
            }}
            spellCheck={false}
            placeholder={'curl -X POST "https://api.openai.com/v1/responses" -d \'{"input":"hello"}\''}
          />
        </label>

        {checkError ? <p className="error-notice">{checkError}</p> : null}

        {checkResult ? (
          <div className="pathgroup-request-test-result">
            <p className="helper-text">
              Parsed request:{' '}
              <strong>
                {checkResult.request.method} {checkResult.request.url}
              </strong>
            </p>

            <ul className="request-check-list">
              <li>Host: {checkResult.hostMatched ? 'matched' : 'not matched'}</li>
              <li>Scheme (https): {checkResult.schemeMatched ? 'matched' : 'not matched'}</li>
              <li>Port (443): {checkResult.portMatched ? 'matched' : 'not matched'}</li>
            </ul>

            <p className={`request-check-status ${checkResult.matched ? 'ok' : 'bad'}`}>
              {checkResult.matched ? 'Matched' : 'Not matched'}: {checkResult.reason}
            </p>

            {checkResult.matched ? (
              <>
                <p className="helper-text">Matched path groups:</p>
                <ul className="request-check-list">
                  {checkResult.matchedPathGroups.map(pathGroup => (
                    <li key={pathGroup.groupId}>
                      <strong>{pathGroup.groupId}</strong>
                      {pathGroup.check.matchedPattern ? ` (${pathGroup.check.matchedPattern})` : ''}:{' '}
                      {pathGroup.check.reason}
                    </li>
                  ))}
                </ul>
                {checkResult.failedPathGroups.length > 0 ? (
                  <p className="helper-text">
                    Additional non-matching path groups are hidden because at least one path group matched.
                  </p>
                ) : null}
              </>
            ) : (
              <>
                <p className="helper-text">Path group failures:</p>
                <ul className="request-check-list">
                  {checkResult.failedPathGroups.map(pathGroup => (
                    <li key={pathGroup.groupId}>
                      <strong>{pathGroup.groupId}</strong>: {pathGroup.check.reason}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        ) : null}
      </div>
    </details>
  );
};

export const TemplatesPanel = ({api, initialTemplateDraft}: TemplatesPanelProps) => {
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const adminPrincipal = useAdminStore(state => state.adminPrincipal);
  const [showEditor, setShowEditor] = useState(Boolean(initialTemplateDraft));
  const [editorMode, setEditorMode] = useState<'new' | 'edit'>('new');

  const [templateName, setTemplateName] = useState(initialTemplateDraft?.template_name ?? defaultTemplateName);
  const [templateIdSuffix, setTemplateIdSuffix] = useState(
    normalizeTemplateIdSuffix(initialTemplateDraft?.template_id_suffix ?? defaultTemplateName)
  );
  const [templateIdLocked, setTemplateIdLocked] = useState(Boolean(initialTemplateDraft));
  const [editingTemplateId, setEditingTemplateId] = useState<string | undefined>(undefined);
  const [selectedHistoryVersion, setSelectedHistoryVersion] = useState<number | undefined>(undefined);
  const [version, setVersion] = useState('1');
  const [provider, setProvider] = useState(initialTemplateDraft?.provider ?? 'openai');
  const [description, setDescription] = useState(initialTemplateDraft?.description ?? '');
  const [allowedHosts, setAllowedHosts] = useState(initialTemplateDraft?.allowed_hosts.join(', ') ?? '');
  const [pathGroups, setPathGroups] = useState<PathGroupDraft[]>(
    initialTemplateDraft?.path_groups.map(pathGroup =>
      createPathGroupDraft({
        groupId: pathGroup.group_id,
        riskTier: pathGroup.risk_tier,
        approvalMode: pathGroup.approval_mode,
        methods: pathGroup.methods,
        pathPatterns: pathGroup.path_patterns.join('\n'),
        queryAllowlist: pathGroup.query_allowlist.join(', '),
        headerForwardAllowlist: pathGroup.header_forward_allowlist.join(', '),
        maxBodyBytes: String(pathGroup.max_body_bytes),
        contentTypes: pathGroup.content_types.join(', '),
        upstreamAuthMode: pathGroup.upstream_auth?.type ?? 'none',
        upstreamAuthRegion: pathGroup.upstream_auth?.region ?? ''
      })
    ) ?? [createPathGroupDraft()]
  );

  const applyIncomingDraft = React.useCallback((draft: TemplateDraft) => {
    setEditorMode('new');
    setTemplateName(draft.template_name);
    setTemplateIdSuffix(normalizeTemplateIdSuffix(draft.template_id_suffix));
    setTemplateIdLocked(true);
    setEditingTemplateId(undefined);
    setSelectedHistoryVersion(undefined);
    setVersion('1');
    setProvider(draft.provider);
    setDescription(draft.description ?? '');
    setAllowedHosts(draft.allowed_hosts.join(', '));
    setPathGroups(
      draft.path_groups.map(pathGroup =>
        createPathGroupDraft({
          groupId: pathGroup.group_id,
          riskTier: pathGroup.risk_tier,
          approvalMode: pathGroup.approval_mode,
          methods: pathGroup.methods,
          pathPatterns: pathGroup.path_patterns.join('\n'),
          queryAllowlist: pathGroup.query_allowlist.join(', '),
          headerForwardAllowlist: pathGroup.header_forward_allowlist.join(', '),
          maxBodyBytes: String(pathGroup.max_body_bytes),
          contentTypes: pathGroup.content_types.join(', '),
          upstreamAuthMode: pathGroup.upstream_auth?.type ?? 'none',
          upstreamAuthRegion: pathGroup.upstream_auth?.region ?? ''
        })
      )
    );
    setShowEditor(true);
  }, []);

  useEffect(() => {
    if (!initialTemplateDraft || typeof window === 'undefined') {
      return;
    }

    let cancelled = false;
    window.queueMicrotask(() => {
      if (cancelled) {
        return;
      }

      applyIncomingDraft(initialTemplateDraft);
    });
    window.sessionStorage.removeItem(TEMPLATE_DRAFT_STORAGE_KEY);
    return () => {
      cancelled = true;
    };
  }, [applyIncomingDraft, initialTemplateDraft]);

  const templatesQuery = useQuery({
    queryKey: ['templates'],
    queryFn: ({signal}) => api.listTemplates(signal)
  });

  const templateVersionIndex = useMemo(
    () => buildTemplateVersionIndex(templatesQuery.data?.templates ?? []),
    [templatesQuery.data?.templates]
  );
  const latestTemplates = useMemo(() => getLatestTemplateVersions(templateVersionIndex), [templateVersionIndex]);
  const editorTemplateHistory = useMemo(() => {
    if (editorMode !== 'edit' || !editingTemplateId) {
      return [] as OpenApiTemplate[];
    }

    return templateVersionIndex.get(editingTemplateId) ?? [];
  }, [editorMode, editingTemplateId, templateVersionIndex]);
  const latestEditorTemplate = editorTemplateHistory[0];
  const selectedHistoryTemplate = useMemo(() => {
    if (editorTemplateHistory.length === 0) {
      return undefined;
    }

    if (selectedHistoryVersion === undefined) {
      return editorTemplateHistory[0];
    }

    return editorTemplateHistory.find(template => template.version === selectedHistoryVersion) ?? editorTemplateHistory[0];
  }, [editorTemplateHistory, selectedHistoryVersion]);
  const selectedHistoryPreviousTemplate = useMemo(() => {
    if (!selectedHistoryTemplate) {
      return undefined;
    }

    return editorTemplateHistory.find(template => template.version === selectedHistoryTemplate.version - 1);
  }, [editorTemplateHistory, selectedHistoryTemplate]);
  const selectedHistoryDiffSummary = useMemo(() => {
    if (!selectedHistoryTemplate || !selectedHistoryPreviousTemplate) {
      return [] as string[];
    }

    return summarizeTemplateVersionDiff(selectedHistoryPreviousTemplate, selectedHistoryTemplate);
  }, [selectedHistoryPreviousTemplate, selectedHistoryTemplate]);
  const selectedHistoryParsedDiff = useMemo(
    () => selectedHistoryDiffSummary.map(parseTemplateDiffSummaryLine),
    [selectedHistoryDiffSummary]
  );

  const resetEditor = () => {
    setTemplateName(defaultTemplateName);
    setTemplateIdSuffix(normalizeTemplateIdSuffix(defaultTemplateName));
    setTemplateIdLocked(false);
    setEditingTemplateId(undefined);
    setSelectedHistoryVersion(undefined);
    setVersion('1');
    setProvider('openai');
    setDescription('');
    setAllowedHosts('');
    setPathGroups([createPathGroupDraft()]);
  };

  const applyTemplate = (template: OpenApiTemplate, nextVersion?: number) => {
    setTemplateName(template.description?.trim() || splitTemplateId(template.template_id).replace(/_/g, ' '));
    setTemplateIdSuffix(splitTemplateId(template.template_id));
    setTemplateIdLocked(true);
    setVersion(String(nextVersion ?? template.version + 1));
    setProvider(template.provider);
    setDescription(template.description ?? '');
    setAllowedHosts(template.allowed_hosts.join(', '));
    setPathGroups(
      template.path_groups.map(pathGroup =>
        createPathGroupDraft({
          groupId: pathGroup.group_id,
          riskTier: pathGroup.risk_tier,
          approvalMode: pathGroup.approval_mode,
          methods: pathGroup.methods,
          pathPatterns: pathGroup.path_patterns.join('\n'),
          queryAllowlist: pathGroup.query_allowlist.join(', '),
          headerForwardAllowlist: pathGroup.header_forward_allowlist.join(', '),
          maxBodyBytes: String(pathGroup.body_policy.max_bytes),
          contentTypes: pathGroup.body_policy.content_types.join(', '),
          ...resolveTemplateUpstreamAuthDraft(pathGroup)
        })
      )
    );
  };

  const updatePathGroup = (draftId: string, updater: (draft: PathGroupDraft) => PathGroupDraft) => {
    setPathGroups(current => current.map(pathGroup => (pathGroup.draftId === draftId ? updater(pathGroup) : pathGroup)));
  };

  const createTemplateMutation = useMutation({
    mutationFn: async () => {
      const parsedVersion = Number.parseInt(version, 10);
      const normalizedTemplateId = buildTemplateId(templateIdSuffix);

      const payload = OpenApiTemplateSchema.parse({
        template_id: normalizedTemplateId,
        version: parsedVersion,
        provider: provider.trim(),
        ...(description.trim() ? {description: description.trim()} : {}),
        allowed_schemes: ['https'],
        allowed_ports: [443],
        allowed_hosts: toCsvList(allowedHosts),
        redirect_policy: {
          mode: 'deny'
        },
        path_groups: pathGroups.map(pathGroup => {
          const constraints = buildTemplatePathGroupConstraints({
            upstreamAuthMode: pathGroup.upstreamAuthMode,
            upstreamAuthRegion: pathGroup.upstreamAuthRegion
          });

          return {
            group_id: pathGroup.groupId.trim(),
            risk_tier: pathGroup.riskTier,
            approval_mode: pathGroup.approvalMode,
            methods: pathGroup.methods,
            path_patterns: toLineList(pathGroup.pathPatterns),
            query_allowlist: toCsvList(pathGroup.queryAllowlist),
            header_forward_allowlist: toCsvList(pathGroup.headerForwardAllowlist),
            body_policy: {
              max_bytes: Number.parseInt(pathGroup.maxBodyBytes, 10),
              content_types: toCsvList(pathGroup.contentTypes)
            },
            ...(constraints ? {constraints} : {})
          };
        }),
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
      closeEditor();
      await queryClient.invalidateQueries({queryKey: ['templates']});
    }
  });
  const deleteTemplateMutation = useMutation({
    mutationFn: (input: {templateId: string}) => api.deleteTemplate({templateId: input.templateId}),
    onSuccess: async () => {
      await queryClient.invalidateQueries({queryKey: ['templates']});
      await queryClient.invalidateQueries({queryKey: ['integrations']});
      await queryClient.invalidateQueries({queryKey: ['policies']});
    }
  });

  const openNewEditor = () => {
    setEditorMode('new');
    resetEditor();
    setShowEditor(true);
  };

  const openEditEditor = (templateId: string) => {
    const history = templateVersionIndex.get(templateId);
    if (!history || history.length === 0) {
      return;
    }

    const latestTemplate = history[0];
    const nextVersion = latestTemplate.version + 1;
    setEditorMode('edit');
    setEditingTemplateId(templateId);
    setSelectedHistoryVersion(latestTemplate.version);
    applyTemplate(latestTemplate, nextVersion);
    setShowEditor(true);
  };

  const closeEditor = () => {
    setShowEditor(false);
    resetEditor();
    if (location.search.includes('draft=')) {
      navigate('/templates', {replace: true});
    }
  };
  const templateEditorOverlay = useOverlayDismiss({
    isOpen: showEditor,
    onClose: closeEditor,
    scope: 'templates-editor',
    enableHistoryBack: !location.search.includes('draft=')
  });

  const restoreHistoricalVersion = (template: OpenApiTemplate) => {
    if (!latestEditorTemplate) {
      return;
    }

    applyTemplate(template, latestEditorTemplate.version + 1);
    setSelectedHistoryVersion(template.version);
  };

  const fullTemplateId = useMemo(() => buildTemplateId(templateIdSuffix), [templateIdSuffix]);
  const normalizedAllowedHosts = useMemo(() => toCsvList(allowedHosts), [allowedHosts]);
  const canDeleteTemplates = adminPrincipal?.roles.includes('owner') ?? false;
  const showOwnerOnlyDeleteHint = adminPrincipal ? !adminPrincipal.roles.includes('owner') : false;
  const templateDeleteBlockedByUsage =
    deleteTemplateMutation.error instanceof ApiClientError && deleteTemplateMutation.error.reason === 'template_in_use';

  return (
    <Panel
      title="Templates"
      subtitle="Manage template contracts with multiple path groups and regex patterns."
      action={
        <button type="button" className="btn-tertiary-icon" onClick={openNewEditor}>
          <AppIcon name="plus" />
          New
        </button>
      }
    >
      {showEditor ? (
        <section className="entity-screen">
          <header className="entity-screen-header">
            <button
              type="button"
              className="icon-back-button"
              aria-label="Back to templates list"
              onClick={templateEditorOverlay.requestClose}
            >
              <AppIcon name="arrow-left" />
            </button>
            <strong className="entity-screen-title">{editorMode === 'new' ? 'Create template' : 'Edit template'}</strong>
            <span className="entity-screen-spacer" aria-hidden />
          </header>
          <div className="entity-screen-content">
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
              <span>Template name (for easier ID generation)</span>
              <input
                value={templateName}
                onChange={event => {
                  const nextName = event.currentTarget.value;
                  setTemplateName(nextName);
                  if (!templateIdLocked) {
                    setTemplateIdSuffix(normalizeTemplateIdSuffix(nextName));
                  }
                }}
                placeholder="OpenAI Responses"
              />
            </label>

            <label className="field">
              <span>Template ID suffix</span>
              <div className="input-prefix-group">
                <span className="input-prefix">{TEMPLATE_ID_PREFIX}</span>
                <input
                  value={templateIdSuffix}
                  onChange={event => {
                    setTemplateIdLocked(true);
                    setTemplateIdSuffix(normalizeTemplateIdSuffix(event.currentTarget.value));
                  }}
                  placeholder="openai_core_v1"
                />
              </div>
            </label>

            <label className="field">
              <span>Version</span>
              <input
                value={version}
                onChange={event => setVersion(event.currentTarget.value)}
                inputMode="numeric"
                readOnly={editorMode === 'edit'}
              />
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
          </div>

          <div className="row-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                setTemplateIdLocked(false);
                setTemplateIdSuffix(normalizeTemplateIdSuffix(templateName));
              }}
            >
              Regenerate ID from name
            </button>
            <p className="helper-text">Final template ID: `{fullTemplateId}` (must match `tpl_[a-z0-9_]+`).</p>
            {editorMode === 'edit' ? (
              <p className="helper-text">Version is auto-set to the next publish version for this template lineage.</p>
            ) : null}
          </div>
          <div className="stack-form">
            <h3>Path groups</h3>
            {pathGroups.map((pathGroup, index) => {
              const upstreamAuthAdapter = getTemplateUpstreamAuthAdapter(pathGroup.upstreamAuthMode);

              return (
                <article key={pathGroup.draftId} className="editor-card">
                <header className="editor-card-header">
                  <h4>Path group {index + 1}</h4>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={pathGroups.length <= 1}
                    onClick={() => setPathGroups(current => current.filter(item => item.draftId !== pathGroup.draftId))}
                  >
                    Remove group
                  </button>
                </header>

                <div className="editor-grid">
                  <label className="field">
                    <span>Group ID</span>
                    <input
                      value={pathGroup.groupId}
                      onChange={event => {
                        const nextGroupId = event.currentTarget.value;
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          groupId: nextGroupId
                        }));
                      }}
                    />
                  </label>

                  <label className="field">
                    <span>Risk tier</span>
                    <select
                      value={pathGroup.riskTier}
                      onChange={event => {
                        const nextRiskTier = event.currentTarget.value as PathGroupDraft['riskTier'];
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          riskTier: nextRiskTier
                        }));
                      }}
                    >
                      <option value="low">low</option>
                      <option value="medium">medium</option>
                      <option value="high">high</option>
                    </select>
                  </label>

                  <label className="field">
                    <span>Approval mode</span>
                    <select
                      value={pathGroup.approvalMode}
                      onChange={event => {
                        const nextApprovalMode = event.currentTarget.value as PathGroupDraft['approvalMode'];
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          approvalMode: nextApprovalMode
                        }));
                      }}
                    >
                      <option value="none">none</option>
                      <option value="required">required</option>
                    </select>
                  </label>

                  <label className="field">
                    <span>Max body bytes</span>
                    <input
                      value={pathGroup.maxBodyBytes}
                      onChange={event => {
                        const nextMaxBodyBytes = event.currentTarget.value;
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          maxBodyBytes: nextMaxBodyBytes
                        }));
                      }}
                      inputMode="numeric"
                    />
                  </label>

                  <label className="field wide">
                    <span>HTTP methods</span>
                    <div className="checkbox-grid">
                      {httpMethods.map(httpMethod => {
                        const checked = pathGroup.methods.includes(httpMethod);
                        return (
                          <label key={httpMethod} className="chip-checkbox">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={event => {
                                const isChecked = event.currentTarget.checked;
                                updatePathGroup(pathGroup.draftId, current => {
                                  const nextMethods = isChecked
                                    ? [...current.methods, httpMethod]
                                    : current.methods.filter(value => value !== httpMethod);

                                  return {
                                    ...current,
                                    methods: [...new Set(nextMethods)] as HttpMethod[]
                                  };
                                });
                              }}
                            />
                            <span className="chip-label">{httpMethod}</span>
                          </label>
                        );
                      })}
                    </div>
                  </label>

                  <label className="field wide">
                    <span>Path regex patterns (one per line)</span>
                    <textarea
                      rows={4}
                      value={pathGroup.pathPatterns}
                      onChange={event => {
                        const nextPathPatterns = event.currentTarget.value;
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          pathPatterns: nextPathPatterns
                        }));
                      }}
                    />
                  </label>

                  <label className="field wide">
                    <span>Query allowlist (comma-separated)</span>
                    <input
                      value={pathGroup.queryAllowlist}
                      onChange={event => {
                        const nextQueryAllowlist = event.currentTarget.value;
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          queryAllowlist: nextQueryAllowlist
                        }));
                      }}
                    />
                  </label>

                  <label className="field wide">
                    <span>Forwarded headers (comma-separated)</span>
                    <input
                      value={pathGroup.headerForwardAllowlist}
                      onChange={event => {
                        const nextHeaderForwardAllowlist = event.currentTarget.value;
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          headerForwardAllowlist: nextHeaderForwardAllowlist
                        }));
                      }}
                    />
                  </label>

                  <label className="field wide">
                    <span>Allowed content types (comma-separated)</span>
                    <input
                      value={pathGroup.contentTypes}
                      onChange={event => {
                        const nextContentTypes = event.currentTarget.value;
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          contentTypes: nextContentTypes
                        }));
                      }}
                    />
                  </label>

                  <label className="field">
                    <span>Upstream auth</span>
                    <select
                      value={pathGroup.upstreamAuthMode}
                      onChange={event => {
                        const nextUpstreamAuthMode = event.currentTarget.value as TemplateUpstreamAuthMode;
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          upstreamAuthMode: nextUpstreamAuthMode
                        }));
                      }}
                    >
                      {templateUpstreamAuthOptions.map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </label>

                  {upstreamAuthAdapter?.fields.map(field => (
                    <label key={field.key} className="field">
                      <span>{field.label}</span>
                      <input
                        value={pathGroup[field.key]}
                        onChange={event => {
                          const nextValue = event.currentTarget.value;
                          updatePathGroup(pathGroup.draftId, current => ({
                            ...current,
                            [field.key]: nextValue
                          }));
                        }}
                        placeholder={field.placeholder}
                      />
                    </label>
                  ))}
                </div>
                {upstreamAuthAdapter?.helpText ? <p className="helper-text">{upstreamAuthAdapter.helpText}</p> : null}
                </article>
              );
            })}

            <div className="row-actions">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setPathGroups(current => [...current, createPathGroupDraft()])}
              >
                Add path group
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() =>
                  setPathGroups(current => [
                    ...current,
                    createPathGroupDraft({
                      groupId: s3ListObjectsPathGroupPreset.groupId,
                      methods: [...s3ListObjectsPathGroupPreset.methods],
                      pathPatterns: s3ListObjectsPathGroupPreset.pathPatterns,
                      queryAllowlist: s3ListObjectsPathGroupPreset.queryAllowlist,
                      headerForwardAllowlist: s3ListObjectsPathGroupPreset.headerForwardAllowlist,
                      maxBodyBytes: s3ListObjectsPathGroupPreset.maxBodyBytes,
                      contentTypes: s3ListObjectsPathGroupPreset.contentTypes,
                      upstreamAuthMode: s3ListObjectsPathGroupPreset.upstreamAuthMode,
                      upstreamAuthRegion: s3ListObjectsPathGroupPreset.upstreamAuthRegion
                    })
                  ])
                }
              >
                Add S3 list path group
              </button>
            </div>
            <p className="helper-text">
              Backup workload requires a bucket-root list path group such as `GET ^/$` with query keys like
              `list-type`, `prefix`, and `continuation-token`, plus `upstream_auth = aws_sigv4` for S3 signing. For
              non-AWS or custom S3-compatible hosts, set an explicit SigV4 region override.
            </p>
          </div>

          <TemplateRequestTester pathGroups={pathGroups} allowedHosts={normalizedAllowedHosts} />

          {editorMode === 'edit' && latestEditorTemplate ? (
            <section className="editor-card version-history-card" aria-label="Template version history">
              <header className="editor-card-header">
                <h4>Version history for {latestEditorTemplate.template_id}</h4>
              </header>
              <p className="helper-text">
                List view shows only the latest version. Select any historical version, review its diff against the
                previous version, then restore it as a new forward version.
              </p>

              <div className="table-shell">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Version</th>
                      <th>Allowed hosts</th>
                      <th>Path groups</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {editorTemplateHistory.map(template => {
                      const isSelected = selectedHistoryTemplate?.version === template.version;
                      return (
                        <tr
                          key={`${template.template_id}:${template.version}`}
                          className={isSelected ? 'selected-row' : ''}
                        >
                          <td>
                            v{template.version}
                            {template.version === latestEditorTemplate.version ? ' (latest)' : ''}
                          </td>
                          <td>{template.allowed_hosts.join(', ') || '(none)'}</td>
                          <td>{template.path_groups.length}</td>
                          <td>
                            <div className="row-actions">
                              <button
                                type="button"
                                className="btn-secondary"
                                onClick={() => setSelectedHistoryVersion(template.version)}
                              >
                                View diff
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {selectedHistoryTemplate ? (
                <div className="version-diff">
                  <h4>
                    Diff for v{selectedHistoryTemplate.version}
                    {selectedHistoryPreviousTemplate ? ` vs v${selectedHistoryPreviousTemplate.version}` : ''}
                  </h4>
                  {selectedHistoryPreviousTemplate ? (
                    <ul className="request-check-list version-diff-list">
                      {selectedHistoryParsedDiff.map((line, index) => (
                        <li key={`${selectedHistoryTemplate.version}:${index}`}>
                          {line.kind === 'list' ? (
                            <p className="version-diff-line">
                              <span className="version-diff-label">{line.label}:</span>
                              {line.removed.map(value => (
                                <span key={`removed:${value}`} className="diff-pill removed">
                                  - {value}
                                </span>
                              ))}
                              {line.added.map(value => (
                                <span key={`added:${value}`} className="diff-pill added">
                                  + {value}
                                </span>
                              ))}
                            </p>
                          ) : null}
                          {line.kind === 'change' ? (
                            <p className="version-diff-line">
                              <span className="version-diff-label">{line.label}:</span>
                              <span className="diff-pill removed">- {line.before}</span>
                              <span className="diff-pill added">+ {line.after}</span>
                            </p>
                          ) : null}
                          {line.kind === 'plain' ? <p className="version-diff-line">{line.text}</p> : null}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="helper-text">
                      v{selectedHistoryTemplate.version} is the first published version and has no previous version to
                      diff against.
                    </p>
                  )}
                  <p className="helper-text">
                    Restoring publishes the selected state as a new version (v{latestEditorTemplate.version + 1}).
                  </p>
                  {selectedHistoryTemplate.version !== latestEditorTemplate.version ? (
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => restoreHistoricalVersion(selectedHistoryTemplate)}
                    >
                      Restore this as v{latestEditorTemplate.version + 1}
                    </button>
                  ) : (
                    <p className="helper-text">Latest version is already selected; there is nothing to restore.</p>
                  )}
                </div>
              ) : null}
            </section>
          ) : null}

          <p className="helper-text">
            Templates are immutable contracts. Editing publishes a new version and keeps previous versions intact.
          </p>

          <ErrorNotice error={createTemplateMutation.error} />

          <div className="row-actions">
            <button type="submit" disabled={createTemplateMutation.isPending}>
              {editorMode === 'new' ? 'Create template' : 'Publish new version'}
            </button>
                <button type="button" className="btn-secondary" onClick={templateEditorOverlay.requestClose}>
                  Cancel
                </button>
          </div>
            </form>
          </div>
        </section>
      ) : null}

      {!showEditor ? (
        <>
          <ErrorNotice error={templatesQuery.error} />
          <ErrorNotice error={deleteTemplateMutation.error} />
          {templateDeleteBlockedByUsage ? (
            <p className="helper-text">Template cannot be deleted while it is referenced by active integrations or policies.</p>
          ) : null}
          {showOwnerOnlyDeleteHint ? <p className="helper-text">Only owner role can delete templates.</p> : null}

          <MobileEntityList
        ariaLabel="Template list"
        items={latestTemplates}
        emptyState="No templates published."
        getItemKey={template => template.template_id}
        getSummary={template => {
          return {
            title: template.template_id,
            subtitle: `v${template.version} • ${template.provider}`,
            meta: [{label: 'Allowed hosts', value: template.allowed_hosts.join(', ') || '-'}]
          };
        }}
        renderDetail={(template, controls) => {
          const historySize = templateVersionIndex.get(template.template_id)?.length ?? 1;
          return (
            <div className="stack-form">
              <label className="field">
                <span>Template ID</span>
                <input value={template.template_id} readOnly />
              </label>
              <label className="field">
                <span>Version</span>
                <input value={`v${template.version}`} readOnly />
              </label>
              <label className="field">
                <span>Provider</span>
                <input value={template.provider} readOnly />
              </label>
              <label className="field wide">
                <span>Allowed hosts</span>
                <input value={template.allowed_hosts.join(', ')} readOnly />
              </label>
              <label className="field wide">
                <span>Path groups</span>
                <input
                  value={`${template.path_groups.length} groups / ${template.path_groups.reduce((count, pathGroup) => count + pathGroup.path_patterns.length, 0)} patterns`}
                  readOnly
                />
              </label>
              <label className="field">
                <span>History</span>
                <input value={`${historySize} version(s)`} readOnly />
              </label>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  openEditEditor(template.template_id);
                  controls.close();
                }}
              >
                Edit template
              </button>
              {canDeleteTemplates ? (
                <button
                  type="button"
                  className="btn-danger"
                  disabled={deleteTemplateMutation.isPending}
                  onClick={() => {
                    if (!window.confirm(`Delete template ${template.template_id}?`)) {
                      return;
                    }
                    deleteTemplateMutation.mutate({templateId: template.template_id});
                    controls.close();
                  }}
                >
                  Delete template
                </button>
              ) : null}
            </div>
          );
        }}
          />

          <div className="table-shell desktop-table-shell">
            <table className="data-table">
          <thead>
            <tr>
              <th>Template ID</th>
              <th>Latest version</th>
              <th>Provider</th>
              <th>Allowed hosts</th>
              <th>Path groups</th>
              <th>History</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {latestTemplates.map(template => {
              const patternCount = template.path_groups.reduce(
                (count, pathGroup) => count + pathGroup.path_patterns.length,
                0
              );
              const historySize = templateVersionIndex.get(template.template_id)?.length ?? 1;

              return (
                <tr key={`${template.template_id}:${template.version}`}>
                  <td>
                    <button
                      type="button"
                      className="table-link-button"
                      onClick={() => openEditEditor(template.template_id)}
                    >
                      {template.template_id}
                    </button>
                  </td>
                  <td>v{template.version}</td>
                  <td>{template.provider}</td>
                  <td>{template.allowed_hosts.join(', ')}</td>
                  <td>
                    {template.path_groups.length} groups / {patternCount} patterns
                  </td>
                  <td>{historySize} version(s)</td>
                  <td>
                    <div className="row-actions">
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => openEditEditor(template.template_id)}
                      >
                        Edit
                      </button>
                      {canDeleteTemplates ? (
                        <button
                          type="button"
                          className="btn-danger"
                          disabled={deleteTemplateMutation.isPending}
                          onClick={() => {
                            if (!window.confirm(`Delete template ${template.template_id}?`)) {
                              return;
                            }
                            deleteTemplateMutation.mutate({templateId: template.template_id});
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
        </>
      ) : null}
    </Panel>
  );
};
