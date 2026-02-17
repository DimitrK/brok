import {
  CanonicalRequestDescriptorSchema,
  PolicyRuleSchema,
  TemplateSchema
} from '@broker-interceptor/schemas'
import {z} from 'zod'

export const DecisionSchema = z.enum(['allowed', 'denied', 'approval_required', 'throttled'])
export type Decision = z.infer<typeof DecisionSchema>

export const RuleMatchTypeSchema = z.enum(['exact', 'scoped'])
export type RuleMatchType = z.infer<typeof RuleMatchTypeSchema>

export const DecisionReasonCodeSchema = z.enum([
  'no_matching_group',
  'invalid_path_pattern',
  'template_scope_mismatch',
  'descriptor_group_mismatch',
  'policy_deny',
  'policy_allow',
  'policy_approval_required',
  'template_approval_required',
  'policy_default_deny',
  'policy_rate_limited',
  'rate_limit_checker_missing',
  'rate_limit_check_failed',
  'invalid_rate_limit_rule'
])
export type DecisionReasonCode = z.infer<typeof DecisionReasonCodeSchema>

export const PathGroupClassificationSchema = z
  .object({
    group_id: z.string(),
    risk_tier: z.enum(['low', 'medium', 'high']),
    approval_mode: z.enum(['none', 'required']),
    matched_pattern: z.string()
  })
  .strict()
export type PathGroupClassification = z.infer<typeof PathGroupClassificationSchema>

export const ClassificationReasonCodeSchema = z.enum(['no_matching_group', 'invalid_path_pattern'])
export type ClassificationReasonCode = z.infer<typeof ClassificationReasonCodeSchema>

export const PathGroupClassificationResultSchema = z.discriminatedUnion('matched', [
  z
    .object({
      matched: z.literal(true),
      path_group: PathGroupClassificationSchema
    })
    .strict(),
  z
    .object({
      matched: z.literal(false),
      reason_code: ClassificationReasonCodeSchema
    })
    .strict()
])
export type PathGroupClassificationResult = z.infer<typeof PathGroupClassificationResultSchema>

export const ClassifyPathGroupInputSchema = z
  .object({
    template: TemplateSchema,
    method: CanonicalRequestDescriptorSchema.shape.method,
    canonical_url: CanonicalRequestDescriptorSchema.shape.canonical_url
  })
  .strict()
export type ClassifyPathGroupInput = z.infer<typeof ClassifyPathGroupInputSchema>

export const CanonicalDescriptorInputSchema = CanonicalRequestDescriptorSchema.omit({
  matched_path_group_id: true
})
export type CanonicalDescriptorInput = z.infer<typeof CanonicalDescriptorInputSchema>

export const BuildCanonicalDescriptorInputSchema = z
  .object({
    descriptor: CanonicalDescriptorInputSchema,
    template: TemplateSchema
  })
  .strict()
export type BuildCanonicalDescriptorInput = z.infer<typeof BuildCanonicalDescriptorInputSchema>

export const BuildCanonicalDescriptorResultSchema = z.discriminatedUnion('ok', [
  z
    .object({
      ok: z.literal(true),
      descriptor: CanonicalRequestDescriptorSchema,
      path_group: PathGroupClassificationSchema
    })
    .strict(),
  z
    .object({
      ok: z.literal(false),
      reason_code: ClassificationReasonCodeSchema
    })
    .strict()
])
export type BuildCanonicalDescriptorResult = z.infer<typeof BuildCanonicalDescriptorResultSchema>

export const PolicyDecisionPolicyMatchSchema = z
  .object({
    policy_id: z.string().nullable().optional(),
    rule_type: PolicyRuleSchema.shape.rule_type,
    match_type: RuleMatchTypeSchema
  })
  .strict()
export type PolicyDecisionPolicyMatch = z.infer<typeof PolicyDecisionPolicyMatchSchema>

export const PolicyDecisionRateLimitSchema = z
  .object({
    policy_id: z.string().nullable().optional(),
    key: z.string(),
    max_requests: z.number().int().gte(1),
    interval_seconds: z.number().int().gte(1)
  })
  .strict()
export type PolicyDecisionRateLimit = z.infer<typeof PolicyDecisionRateLimitSchema>

export const PolicyDecisionTraceEntrySchema = z
  .object({
    stage: z.enum(['classification', 'policy', 'rate_limit']),
    outcome: z.enum([
      'matched',
      'not_matched',
      'selected',
      'allowed',
      'denied',
      'approval_required',
      'throttled',
      'error',
      'skipped'
    ]),
    detail: z.string(),
    policy_id: z.string().nullable().optional(),
    rule_type: PolicyRuleSchema.shape.rule_type.optional()
  })
  .strict()
export type PolicyDecisionTraceEntry = z.infer<typeof PolicyDecisionTraceEntrySchema>

export const PolicyDecisionSchema = z
  .object({
    decision: DecisionSchema,
    reason_code: DecisionReasonCodeSchema,
    action_group: z.string(),
    risk_tier: z.enum(['low', 'medium', 'high']),
    policy_match: PolicyDecisionPolicyMatchSchema.optional(),
    rate_limit: PolicyDecisionRateLimitSchema.optional(),
    trace: z.array(PolicyDecisionTraceEntrySchema)
  })
  .strict()
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>

export const EvaluatePolicyInputSchema = z
  .object({
    descriptor: CanonicalRequestDescriptorSchema,
    template: TemplateSchema,
    policies: z.array(PolicyRuleSchema)
  })
  .strict()
export type EvaluatePolicyInput = z.infer<typeof EvaluatePolicyInputSchema>
