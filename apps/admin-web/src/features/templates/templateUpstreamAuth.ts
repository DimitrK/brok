import {
  TemplatePathGroupConstraintsSchema,
  UpstreamAuthTypeSchema,
  type OpenApiTemplate,
  type TemplatePathGroupConstraints,
  type UpstreamAuthType
} from '@broker-interceptor/schemas';

type TemplatePathGroup = OpenApiTemplate['path_groups'][number];

export type TemplateUpstreamAuthMode = 'none' | UpstreamAuthType;

export type TemplateUpstreamAuthFieldKey = 'upstreamAuthRegion';

type TemplateUpstreamAuthFieldValues = Record<TemplateUpstreamAuthFieldKey, string>;

export type TemplateUpstreamAuthDraft = {
  upstreamAuthMode: TemplateUpstreamAuthMode;
} & TemplateUpstreamAuthFieldValues;

export type TemplateUpstreamAuthFieldDefinition = {
  key: TemplateUpstreamAuthFieldKey;
  label: string;
  placeholder: string;
};

type TemplateUpstreamAuthAdapter = {
  type: UpstreamAuthType;
  label: string;
  helpText?: string;
  fields: readonly TemplateUpstreamAuthFieldDefinition[];
  resolveDraft: (pathGroup: Pick<TemplatePathGroup, 'constraints'>) => Partial<TemplateUpstreamAuthFieldValues>;
  buildConstraints: (draft: TemplateUpstreamAuthDraft) => TemplatePathGroupConstraints;
};

const emptyTemplateUpstreamAuthFieldValues: TemplateUpstreamAuthFieldValues = {
  upstreamAuthRegion: ''
};

const templateUpstreamAuthAdapterRegistry: Record<UpstreamAuthType, TemplateUpstreamAuthAdapter> = {
  aws_sigv4: {
    type: 'aws_sigv4',
    label: 'AWS SigV4 (S3)',
    helpText:
      'For non-AWS or custom S3-compatible hosts, set an explicit SigV4 region override that matches the upstream signer configuration.',
    fields: [
      {
        key: 'upstreamAuthRegion',
        label: 'SigV4 region override',
        placeholder: 'eu-west-1'
      }
    ],
    resolveDraft: pathGroup => ({
      upstreamAuthRegion: pathGroup.constraints?.upstream_auth?.region ?? ''
    }),
    buildConstraints: draft => {
      const normalizedRegion = draft.upstreamAuthRegion.trim();
      return TemplatePathGroupConstraintsSchema.parse({
        upstream_auth: {
          type: 'aws_sigv4',
          service: 's3',
          ...(normalizedRegion ? {region: normalizedRegion} : {})
        }
      });
    }
  }
};

export const templateUpstreamAuthAdapters = Object.freeze(templateUpstreamAuthAdapterRegistry);

export const templateUpstreamAuthOptions = [
  {value: 'none' as const, label: 'none'},
  ...UpstreamAuthTypeSchema.options.map(upstreamAuthType => ({
    value: upstreamAuthType,
    label: templateUpstreamAuthAdapterRegistry[upstreamAuthType].label
  }))
];

export const getTemplateUpstreamAuthAdapter = (mode: TemplateUpstreamAuthMode) =>
  mode === 'none' ? undefined : templateUpstreamAuthAdapterRegistry[mode];

export const createEmptyTemplateUpstreamAuthDraft = (
  mode: TemplateUpstreamAuthMode = 'none'
): TemplateUpstreamAuthDraft => ({
  upstreamAuthMode: mode,
  ...emptyTemplateUpstreamAuthFieldValues
});

export const resolveTemplateUpstreamAuthDraft = (
  pathGroup: Pick<TemplatePathGroup, 'constraints'>
): TemplateUpstreamAuthDraft => {
  const upstreamAuthType = pathGroup.constraints?.upstream_auth?.type;
  if (!upstreamAuthType) {
    return createEmptyTemplateUpstreamAuthDraft();
  }

  const adapter = templateUpstreamAuthAdapterRegistry[upstreamAuthType];
  return {
    ...createEmptyTemplateUpstreamAuthDraft(upstreamAuthType),
    ...adapter.resolveDraft(pathGroup)
  };
};

export const buildTemplatePathGroupConstraints = (draft: TemplateUpstreamAuthDraft) => {
  const adapter = getTemplateUpstreamAuthAdapter(draft.upstreamAuthMode);
  return adapter ? adapter.buildConstraints(draft) : undefined;
};

export const s3ListObjectsPathGroupPreset = {
  groupId: 's3_list_objects_v2',
  methods: ['GET'] as const,
  pathPatterns: '^/$',
  queryAllowlist: 'list-type,prefix,continuation-token,max-keys,start-after,delimiter',
  headerForwardAllowlist: '',
  maxBodyBytes: '0',
  contentTypes: '',
  upstreamAuthMode: 'aws_sigv4' as const,
  upstreamAuthRegion: ''
};
