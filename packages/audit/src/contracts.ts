import {
  OpenApiAuditEventListResponseSchema,
  OpenApiAuditEventSchema,
  type OpenApiAuditEvent,
  type OpenApiAuditEventListResponse
} from '@broker-interceptor/schemas'
import {z} from 'zod'

export const AuditSearchDecisionSchema = z.enum([
  'allowed',
  'denied',
  'approval_required',
  'throttled'
])
export type AuditSearchDecision = z.infer<typeof AuditSearchDecisionSchema>

export const AuditEventSearchQuerySchema = z
  .object({
    time_min: z.string().datetime({offset: true}).optional(),
    time_max: z.string().datetime({offset: true}).optional(),
    tenant_id: z.string().optional(),
    workload_id: z.string().optional(),
    integration_id: z.string().optional(),
    action_group: z.string().optional(),
    decision: AuditSearchDecisionSchema.optional()
  })
  .strict()
export type AuditEventSearchQuery = z.infer<typeof AuditEventSearchQuerySchema>

export const AuditEventSearchFilterSchema = z
  .object({
    time_min: z.date().optional(),
    time_max: z.date().optional(),
    tenant_id: z.string().optional(),
    workload_id: z.string().optional(),
    integration_id: z.string().optional(),
    action_group: z.string().optional(),
    decision: AuditSearchDecisionSchema.optional()
  })
  .strict()
export type AuditEventSearchFilter = z.infer<typeof AuditEventSearchFilterSchema>

export const RedactionActionSchema = z.enum(['keep', 'mask', 'hash', 'drop'])
export type RedactionAction = z.infer<typeof RedactionActionSchema>

const RedactionRegexPatternSchema = z
  .string()
  .min(1)
  .refine(pattern => {
    try {
      // eslint-disable-next-line security/detect-non-literal-regexp -- Pattern is validated at runtime and scoped to redaction matching.
      new RegExp(pattern, 'iu')
      return true
    } catch {
      return false
    }
  }, 'Invalid regex pattern')

export const AuditRedactionRulesSchema = z
  .object({
    message_action: RedactionActionSchema,
    metadata_default_action: RedactionActionSchema,
    metadata_key_actions: z.record(z.string(), RedactionActionSchema),
    metadata_allow_keys: z.array(z.string()),
    sensitive_key_patterns: z.array(RedactionRegexPatternSchema).min(1),
    canonical_header_value_action: RedactionActionSchema,
    policy_identifier_action: RedactionActionSchema,
    max_depth: z.number().int().gte(1).lte(8),
    max_collection_size: z.number().int().gte(1).lte(500),
    max_string_length: z.number().int().gte(64).lte(4096),
    hash_salt: z.string().optional()
  })
  .strict()
export type AuditRedactionRules = z.infer<typeof AuditRedactionRulesSchema>

export const AuditRedactionProfileSchema = z
  .object({
    tenant_id: z.string(),
    profile_id: z.string(),
    rules: AuditRedactionRulesSchema
  })
  .strict()
export type AuditRedactionProfile = z.infer<typeof AuditRedactionProfileSchema>

export const AuditAppendEventInputSchema = z
  .object({
    event: OpenApiAuditEventSchema
  })
  .strict()
export type AuditAppendEventInput = z.infer<typeof AuditAppendEventInputSchema>

export const AuditDeliveryStatusSchema = z.enum(['stored'])
export type AuditDeliveryStatus = z.infer<typeof AuditDeliveryStatusSchema>

export const AuditStructuredLogRecordSchema = z.record(z.string(), z.unknown())
export type AuditStructuredLogRecord = z.infer<typeof AuditStructuredLogRecordSchema>

export const AuditAppendEventResultSchema = z
  .object({
    event: OpenApiAuditEventSchema,
    profile_id: z.string(),
    delivery_status: AuditDeliveryStatusSchema,
    structured_log: AuditStructuredLogRecordSchema
  })
  .strict()
export type AuditAppendEventResult = z.infer<typeof AuditAppendEventResultSchema>

export const AuditQueryEventsInputSchema = z
  .object({
    query: AuditEventSearchQuerySchema
  })
  .strict()
export type AuditQueryEventsInput = z.infer<typeof AuditQueryEventsInputSchema>

export const AuditQueryEventsResultSchema = OpenApiAuditEventListResponseSchema
export type AuditQueryEventsResult = OpenApiAuditEventListResponse

export type AuditEventContract = OpenApiAuditEvent

export {
  OpenApiAuditEventListResponseSchema,
  OpenApiAuditEventSchema,
  type OpenApiAuditEvent,
  type OpenApiAuditEventListResponse
}
