import {z} from 'zod';

import {
  OpenApiExecuteRequestSchema,
  OpenApiHeaderListSchema,
  TemplateSchema,
  type OpenApiExecuteRequest,
  type OpenApiHeaderList,
  type Template
} from '@broker-interceptor/schemas';

const NonEmptyStringSchema = z.string().trim().min(1);

export const DnsResolutionConfigSchema = z
  .object({
    timeout_ms: z.number().int().min(100).max(10_000).default(2_000)
  })
  .strict();

export const GuardExecuteRequestInputSchema = z
  .object({
    execute_request: OpenApiExecuteRequestSchema,
    template: TemplateSchema
  })
  .strict();

export const GuardExecuteRequestOutputSchema = z
  .object({
    destination: z
      .object({
        scheme: NonEmptyStringSchema,
        host: NonEmptyStringSchema,
        port: z.number().int().min(1).max(65_535),
        pathname: z.string()
      })
      .strict(),
    resolved_ips: z.array(NonEmptyStringSchema).min(1)
  })
  .strict();

export const GuardUpstreamResponseInputSchema = z
  .object({
    template: TemplateSchema,
    upstream_status_code: z.number().int().gte(100).lte(599),
    upstream_headers: OpenApiHeaderListSchema.optional()
  })
  .strict();

export type DnsResolutionConfig = z.infer<typeof DnsResolutionConfigSchema>;
export type GuardExecuteRequestInput = z.infer<typeof GuardExecuteRequestInputSchema>;
export type GuardExecuteRequestOutput = z.infer<typeof GuardExecuteRequestOutputSchema>;
export type GuardUpstreamResponseInput = z.infer<typeof GuardUpstreamResponseInputSchema>;

export const DEFAULT_DNS_RESOLUTION_CONFIG = DnsResolutionConfigSchema.parse({});

export type DnsResolver = (input: {hostname: string}) => Promise<string[]> | string[];

export type GuardExecuteRequestOptions = {
  dns_resolver?: DnsResolver;
  dns_resolution?: DnsResolutionConfig;
};

export type OpenApiExecuteRequestContract = OpenApiExecuteRequest;
export type OpenApiHeaderListContract = OpenApiHeaderList;
export type TemplateContract = Template;
