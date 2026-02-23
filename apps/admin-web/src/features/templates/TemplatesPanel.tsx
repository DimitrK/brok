import React, {useEffect, useMemo, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {OpenApiTemplateSchema, type OpenApiTemplate} from '@broker-interceptor/schemas';
import {z} from 'zod';

import {BrokerAdminApiClient} from '../../api/client';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';
import {TEMPLATE_DRAFT_STORAGE_KEY} from '../audit/templateSuggestion';
import {
  TEMPLATE_ID_PREFIX,
  buildTemplateId,
  normalizeTemplateIdSuffix,
  splitTemplateId,
  toCsvList,
  toLineList
} from './templateHelpers';
import {
  checkPathGroupCurlRequest,
  checkTemplateCurlRequest,
  type PathGroupRequestCheck,
  type TemplateRequestCheck
} from './pathGroupRequestCheck';

const httpMethodSchema = z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const templateDraftRouteSchema = z
  .object({
    templateDraft: z
      .object({
        source: z.literal('audit'),
        provider: z.string(),
        template_name: z.string(),
        template_id_suffix: z.string().min(1),
        description: z.string().optional(),
        allowed_hosts: z.array(z.string().min(1)).min(1),
        path_groups: z
          .array(
            z
              .object({
                group_id: z.string(),
                risk_tier: z.enum(['low', 'medium', 'high']),
                approval_mode: z.enum(['none', 'required']),
                methods: z.array(httpMethodSchema).min(1),
                path_patterns: z.array(z.string().min(1)).min(1),
                query_allowlist: z.array(z.string()),
                header_forward_allowlist: z.array(z.string()),
                max_body_bytes: z.number().int().min(0),
                content_types: z.array(z.string())
              })
              .strict()
          )
          .min(1)
      })
      .strict()
  })
  .strict();

type HttpMethod = z.infer<typeof httpMethodSchema>;

const httpMethods: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

type TemplatesPanelProps = {
  api: BrokerAdminApiClient;
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
};

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
  contentTypes: input.contentTypes ?? 'application/json'
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

export const TemplatesPanel = ({api}: TemplatesPanelProps) => {
  const queryClient = useQueryClient();

  const readTemplateDraftFromStorage = () => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    const rawValue = window.sessionStorage.getItem(TEMPLATE_DRAFT_STORAGE_KEY);
    if (!rawValue) {
      return undefined;
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawValue);
    } catch {
      return undefined;
    }

    const parsed = templateDraftRouteSchema.safeParse(parsedJson);
    if (!parsed.success) {
      return undefined;
    }

    return parsed.data.templateDraft;
  };

  const [initialTemplateDraft] = useState(() => readTemplateDraftFromStorage());

  const [showEditor, setShowEditor] = useState(Boolean(initialTemplateDraft));
  const [editorMode, setEditorMode] = useState<'new' | 'edit'>('new');

  const [templateName, setTemplateName] = useState(initialTemplateDraft?.template_name ?? defaultTemplateName);
  const [templateIdSuffix, setTemplateIdSuffix] = useState(
    normalizeTemplateIdSuffix(initialTemplateDraft?.template_id_suffix ?? defaultTemplateName)
  );
  const [templateIdLocked, setTemplateIdLocked] = useState(Boolean(initialTemplateDraft));
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
        contentTypes: pathGroup.content_types.join(', ')
      })
    ) ?? [createPathGroupDraft()]
  );

  useEffect(() => {
    if (!initialTemplateDraft || typeof window === 'undefined') {
      return;
    }

    window.sessionStorage.removeItem(TEMPLATE_DRAFT_STORAGE_KEY);
  }, [initialTemplateDraft]);

  const templatesQuery = useQuery({
    queryKey: ['templates'],
    queryFn: ({signal}) => api.listTemplates(signal)
  });

  const resetEditor = () => {
    setTemplateName(defaultTemplateName);
    setTemplateIdSuffix(normalizeTemplateIdSuffix(defaultTemplateName));
    setTemplateIdLocked(false);
    setVersion('1');
    setProvider('openai');
    setDescription('');
    setAllowedHosts('');
    setPathGroups([createPathGroupDraft()]);
  };

  const applyTemplate = (template: OpenApiTemplate) => {
    setTemplateName(template.description?.trim() || splitTemplateId(template.template_id).replace(/_/g, ' '));
    setTemplateIdSuffix(splitTemplateId(template.template_id));
    setTemplateIdLocked(true);
    setVersion(String(template.version + 1));
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
          contentTypes: pathGroup.body_policy.content_types.join(', ')
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
        path_groups: pathGroups.map(pathGroup => ({
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
          }
        })),
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

  const openNewEditor = () => {
    setEditorMode('new');
    resetEditor();
    setShowEditor(true);
  };

  const openEditEditor = (template: OpenApiTemplate) => {
    setEditorMode('edit');
    applyTemplate(template);
    setShowEditor(true);
  };

  const fullTemplateId = useMemo(() => buildTemplateId(templateIdSuffix), [templateIdSuffix]);
  const normalizedAllowedHosts = useMemo(() => toCsvList(allowedHosts), [allowedHosts]);

  return (
    <Panel
      title="Templates"
      subtitle="Manage template contracts with multiple path groups and regex patterns."
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
          </div>

          <div className="stack-form">
            <h3>Path groups</h3>
            {pathGroups.map((pathGroup, index) => (
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
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          groupId: event.currentTarget.value
                        }))
                      }
                    />
                  </label>

                  <label className="field">
                    <span>Risk tier</span>
                    <select
                      value={pathGroup.riskTier}
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          riskTier: event.currentTarget.value as PathGroupDraft['riskTier']
                        }))
                      }
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
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          approvalMode: event.currentTarget.value as PathGroupDraft['approvalMode']
                        }))
                      }
                    >
                      <option value="none">none</option>
                      <option value="required">required</option>
                    </select>
                  </label>

                  <label className="field">
                    <span>Max body bytes</span>
                    <input
                      value={pathGroup.maxBodyBytes}
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          maxBodyBytes: event.currentTarget.value
                        }))
                      }
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
                              onChange={event =>
                                updatePathGroup(pathGroup.draftId, current => {
                                  const nextMethods = event.currentTarget.checked
                                    ? [...current.methods, httpMethod]
                                    : current.methods.filter(value => value !== httpMethod);

                                  return {
                                    ...current,
                                    methods: [...new Set(nextMethods)] as HttpMethod[]
                                  };
                                })
                              }
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
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          pathPatterns: event.currentTarget.value
                        }))
                      }
                    />
                  </label>

                  <label className="field wide">
                    <span>Query allowlist (comma-separated)</span>
                    <input
                      value={pathGroup.queryAllowlist}
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          queryAllowlist: event.currentTarget.value
                        }))
                      }
                    />
                  </label>

                  <label className="field wide">
                    <span>Forwarded headers (comma-separated)</span>
                    <input
                      value={pathGroup.headerForwardAllowlist}
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          headerForwardAllowlist: event.currentTarget.value
                        }))
                      }
                    />
                  </label>

                  <label className="field wide">
                    <span>Allowed content types (comma-separated)</span>
                    <input
                      value={pathGroup.contentTypes}
                      onChange={event =>
                        updatePathGroup(pathGroup.draftId, current => ({
                          ...current,
                          contentTypes: event.currentTarget.value
                        }))
                      }
                    />
                  </label>
                </div>
              </article>
            ))}

            <button
              type="button"
              className="btn-secondary"
              onClick={() => setPathGroups(current => [...current, createPathGroupDraft()])}
            >
              Add path group
            </button>
          </div>

          <TemplateRequestTester pathGroups={pathGroups} allowedHosts={normalizedAllowedHosts} />

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

      <ErrorNotice error={templatesQuery.error ?? createTemplateMutation.error} />

      <div className="table-shell">
        <table className="data-table">
          <thead>
            <tr>
              <th>Template ID</th>
              <th>Version</th>
              <th>Provider</th>
              <th>Allowed hosts</th>
              <th>Path groups</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {(templatesQuery.data?.templates ?? []).map(template => {
              const patternCount = template.path_groups.reduce(
                (count, pathGroup) => count + pathGroup.path_patterns.length,
                0
              );

              return (
                <tr key={`${template.template_id}:${template.version}`}>
                  <td>{template.template_id}</td>
                  <td>{template.version}</td>
                  <td>{template.provider}</td>
                  <td>{template.allowed_hosts.join(', ')}</td>
                  <td>
                    {template.path_groups.length} groups / {patternCount} patterns
                  </td>
                  <td>
                    <div className="row-actions">
                      <button type="button" className="btn-secondary" onClick={() => openEditEditor(template)}>
                        Edit
                      </button>
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
