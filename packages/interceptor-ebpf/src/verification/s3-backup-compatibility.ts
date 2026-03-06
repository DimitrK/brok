import {z} from 'zod';
import {
  OpenApiIntegrationSecretMaterialWriteSchema,
  type OpenApiIntegrationSecretMaterialWrite,
  TemplatePathGroupConstraintsSchema
} from '../../../schemas/dist/index.js';

const AwsSigV4SecretMaterialSchema = OpenApiIntegrationSecretMaterialWriteSchema.refine(
  (value: OpenApiIntegrationSecretMaterialWrite) => value.type === 'aws_sigv4',
  {
    message: 'secret_material must be aws_sigv4'
  }
);

const AwsSigV4UpstreamAuthSchema = TemplatePathGroupConstraintsSchema.refine(
  value => value.upstream_auth?.type === 'aws_sigv4' && value.upstream_auth.service === 's3',
  {
    message: 'constraints.upstream_auth must be aws_sigv4 for service=s3'
  }
);

export const BackupWorkloadS3RequestSchema = z
  .object({
    method: z.enum(['GET', 'PUT']),
    url: z.string().url()
  })
  .strict()
  .superRefine((value, ctx) => {
    const parsed = new URL(value.url);

    if (parsed.protocol !== 'https:') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'backup-workload S3 compatibility verification only supports https URLs'
      });
    }

    if (value.method === 'GET' && parsed.pathname === '/') {
      if (parsed.searchParams.get('list-type') !== '2') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'bucket-root list requests must include list-type=2'
        });
      }

      if (!parsed.searchParams.has('prefix')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'bucket-root list requests must include prefix'
        });
      }
    }

    if (value.method === 'PUT' && parsed.pathname === '/') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'object write requests must target an object path'
      });
    }
  });

export type BackupWorkloadS3Request = z.infer<typeof BackupWorkloadS3RequestSchema>;

export const EbpfS3BackupCompatibilityInputSchema = z
  .object({
    secret_material: AwsSigV4SecretMaterialSchema,
    constraints: AwsSigV4UpstreamAuthSchema,
    request: BackupWorkloadS3RequestSchema
  })
  .strict();

export type EbpfS3BackupCompatibilityInput = z.infer<typeof EbpfS3BackupCompatibilityInputSchema>;

export const EbpfS3BackupCompatibilityResultSchema = z
  .object({
    compatible: z.literal(true),
    request_kind: z.enum(['bucket_list', 'object_read', 'object_write']),
    transport: z.literal('tcp'),
    network_protocol: z.literal('https'),
    required_hooks: z.array(z.enum(['connect4', 'connect6'])).length(2),
    http_shape_affects_socket_matching: z.literal(false),
    reason: z.string().min(1)
  })
  .strict();

export type EbpfS3BackupCompatibilityResult = z.infer<typeof EbpfS3BackupCompatibilityResultSchema>;

const detectRequestKind = (request: BackupWorkloadS3Request): EbpfS3BackupCompatibilityResult['request_kind'] => {
  const parsed = new URL(request.url);

  if (request.method === 'GET' && parsed.pathname === '/') {
    return 'bucket_list';
  }

  if (request.method === 'GET') {
    return 'object_read';
  }

  return 'object_write';
};

export function verifyS3BackupEbpfCompatibility(
  rawInput: unknown
): EbpfS3BackupCompatibilityResult {
  const input = EbpfS3BackupCompatibilityInputSchema.parse(rawInput);
  const requestKind = detectRequestKind(input.request);

  const reason =
    requestKind === 'bucket_list'
      ? 'Bucket-root list requests remain eBPF-compatible because socket interception depends on destination host/port over HTTPS, not on HTTP query shape.'
      : 'Object operations remain eBPF-compatible because the interceptor attaches at the HTTPS socket layer, so object path depth does not change connect-hook semantics.';

  return EbpfS3BackupCompatibilityResultSchema.parse({
    compatible: true,
    request_kind: requestKind,
    transport: 'tcp',
    network_protocol: 'https',
    required_hooks: ['connect4', 'connect6'],
    http_shape_affects_socket_matching: false,
    reason
  });
}
