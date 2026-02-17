import {z} from 'zod';

import {
  OpenApiExecuteRequestSchema,
  OpenApiExecuteResponseExecutedSchema,
  OpenApiHeaderListSchema,
  TemplateSchema,
  type OpenApiExecuteRequest,
  type OpenApiExecuteResponseExecuted,
  type OpenApiHeaderList,
  type Template
} from '@broker-interceptor/schemas';

const NonEmptyStringSchema = z.string().trim().min(1);

export const ForwarderTimeoutsSchema = z
  .object({
    total_timeout_ms: z.number().int().min(100).max(120_000).default(15_000)
  })
  .strict();

export const ForwarderLimitsSchema = z
  .object({
    max_response_bytes: z.number().int().min(1).max(10 * 1024 * 1024).default(2 * 1024 * 1024),
    max_request_body_bytes: z.number().int().min(0).max(10 * 1024 * 1024).default(2 * 1024 * 1024)
  })
  .strict();

export const ForwardExecuteRequestInputSchema = z
  .object({
    execute_request: OpenApiExecuteRequestSchema,
    template: TemplateSchema,
    matched_path_group_id: NonEmptyStringSchema,
    injected_headers: OpenApiHeaderListSchema.optional(),
    response_header_allowlist: z.array(NonEmptyStringSchema).optional(),
    correlation_id: NonEmptyStringSchema.optional(),
    timeouts: ForwarderTimeoutsSchema.optional(),
    limits: ForwarderLimitsSchema.optional()
  })
  .strict();

export type ForwarderTimeouts = z.infer<typeof ForwarderTimeoutsSchema>;
export type ForwarderLimits = z.infer<typeof ForwarderLimitsSchema>;
export type ForwardExecuteRequestInput = z.infer<typeof ForwardExecuteRequestInputSchema>;

export const DEFAULT_FORWARDER_TIMEOUTS = ForwarderTimeoutsSchema.parse({});
export const DEFAULT_FORWARDER_LIMITS = ForwarderLimitsSchema.parse({});

export type FetchLike = (...args: Parameters<typeof fetch>) => ReturnType<typeof fetch>;

export type OpenApiExecuteRequestContract = OpenApiExecuteRequest;
export type OpenApiExecuteResponseExecutedContract = OpenApiExecuteResponseExecuted;
export type OpenApiHeaderListContract = OpenApiHeaderList;
export type TemplateContract = Template;
export type ForwardExecuteRequestOutput = OpenApiExecuteResponseExecutedContract;

export {OpenApiExecuteResponseExecutedSchema};
