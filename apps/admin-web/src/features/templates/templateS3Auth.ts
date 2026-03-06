import type {OpenApiTemplate} from '@broker-interceptor/schemas';

type TemplatePathGroup = OpenApiTemplate['path_groups'][number];

export type TemplateUpstreamAuthMode = 'none' | 'aws_sigv4';

export const resolveTemplateUpstreamAuthMode = (pathGroup: Pick<TemplatePathGroup, 'constraints'>): TemplateUpstreamAuthMode =>
  pathGroup.constraints?.upstream_auth?.type === 'aws_sigv4' ? 'aws_sigv4' : 'none';

export const resolveTemplateUpstreamAuthRegion = (pathGroup: Pick<TemplatePathGroup, 'constraints'>) =>
  pathGroup.constraints?.upstream_auth?.region ?? '';

export const buildTemplatePathGroupConstraints = (input: {
  upstreamAuthMode: TemplateUpstreamAuthMode;
  upstreamAuthRegion: string;
}) => {
  if (input.upstreamAuthMode !== 'aws_sigv4') {
    return undefined;
  }

  const normalizedRegion = input.upstreamAuthRegion.trim();
  return {
    upstream_auth: {
      type: 'aws_sigv4' as const,
      service: 's3' as const,
      ...(normalizedRegion ? {region: normalizedRegion} : {})
    }
  };
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
