import {z} from 'zod';

import {
  CanonicalRequestDescriptorSchema,
  OpenApiExecuteRequestSchema,
  TemplateSchema,
  type CanonicalRequestDescriptor,
  type OpenApiExecuteRequest,
  type Template
} from '@broker-interceptor/schemas';

const NonEmptyIdentifierSchema = z.string().trim().min(1);

export const CanonicalizationContextSchema = z
  .object({
    tenant_id: NonEmptyIdentifierSchema,
    workload_id: NonEmptyIdentifierSchema,
    integration_id: NonEmptyIdentifierSchema
  })
  .strict();

export const BodyDigestModeSchema = z.enum(['never', 'high_risk_only', 'always']);

export const CanonicalizeExecuteRequestInputSchema = z
  .object({
    context: CanonicalizationContextSchema,
    template: TemplateSchema,
    execute_request: OpenApiExecuteRequestSchema,
    body_digest_mode: BodyDigestModeSchema.optional()
  })
  .strict();

export type CanonicalizationContext = z.infer<typeof CanonicalizationContextSchema>;
export type BodyDigestMode = z.infer<typeof BodyDigestModeSchema>;
export type CanonicalizeExecuteRequestInput = z.infer<typeof CanonicalizeExecuteRequestInputSchema>;

export type CanonicalRequestDescriptorContract = CanonicalRequestDescriptor;
export type OpenApiExecuteRequestContract = OpenApiExecuteRequest;
export type TemplateContract = Template;
export type TemplatePathGroupContract = TemplateContract['path_groups'][number];
export type HttpMethodContract = OpenApiExecuteRequestContract['request']['method'];

export {
  CanonicalRequestDescriptorSchema,
  OpenApiExecuteRequestSchema,
  TemplateSchema,
  type CanonicalRequestDescriptor,
  type OpenApiExecuteRequest,
  type Template
};
