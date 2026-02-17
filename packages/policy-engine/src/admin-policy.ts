import {
  CanonicalRequestDescriptorSchema,
  OpenApiCanonicalRequestDescriptorSchema,
  PolicyConstraintsSchema,
  OpenApiPolicyRuleSchema,
  type PolicyConstraints,
  type OpenApiCanonicalRequestDescriptor,
  type OpenApiPolicyRule
} from '@broker-interceptor/schemas'
import {z} from 'zod'

type ValidatePolicyRuleErrorCode =
  | 'policy_rule_invalid'
  | 'policy_scope_invalid'
  | 'policy_host_invalid'
  | 'policy_method_invalid'
  | 'policy_query_keys_invalid'
  | 'policy_rate_limit_invalid'

type DerivePolicyFromApprovalDecisionErrorCode =
  | 'approval_decision_invalid'
  | 'descriptor_invalid'
  | 'derived_policy_invalid'

type NormalizePolicyScopeResult =
  | {
      ok: true
      scope: OpenApiPolicyRule['scope']
    }
  | {
      ok: false
      error: {
        code:
          | 'policy_scope_invalid'
          | 'policy_host_invalid'
          | 'policy_method_invalid'
          | 'policy_query_keys_invalid'
        message: string
      }
    }

type NormalizePolicyRateLimitResult =
  | {
      ok: true
      rate_limit: OpenApiPolicyRule['rate_limit']
    }
  | {
      ok: false
      error: {
        code: 'policy_rate_limit_invalid'
        message: string
      }
    }

type NormalizePolicyConstraintsResult =
  | {
      ok: true
      constraints?: PolicyConstraints
    }
  | {
      ok: false
      message: string
    }

type BuildDerivedRuleScopeResult =
  | {
      ok: true
      scope: OpenApiPolicyRule['scope']
    }
  | {
      ok: false
      error: {
        code: 'descriptor_invalid'
        message: string
      }
    }

const ValidatePolicyRuleInputSchema = z
  .object({
    policy: OpenApiPolicyRuleSchema
  })
  .strict()

export type ValidatePolicyRuleInput = z.infer<typeof ValidatePolicyRuleInputSchema>

export type ValidatePolicyRuleResult =
  | {
      ok: true
      value: OpenApiPolicyRule
    }
  | {
      ok: false
      error: {
        code: ValidatePolicyRuleErrorCode
        message: string
      }
    }

const DerivePolicyFromApprovalDecisionInputSchema = z
  .object({
    approval_status: z.enum(['approved', 'denied']),
    approval_mode: z.enum(['once', 'rule']),
    descriptor: z.unknown(),
    constraints: PolicyConstraintsSchema.optional(),
    policy_id: z.string()
  })
  .strict()

export type DerivePolicyFromApprovalDecisionInput = {
  approval_status: 'approved' | 'denied'
  approval_mode: 'once' | 'rule'
  descriptor: OpenApiCanonicalRequestDescriptor
  constraints?: PolicyConstraints
  policy_id: string
}

export type DerivePolicyFromApprovalDecisionResult =
  | {
      ok: true
      value: OpenApiPolicyRule | null
    }
  | {
      ok: false
      error: {
        code: DerivePolicyFromApprovalDecisionErrorCode
        message: string
      }
    }

const isBlank = (value: string) => value.trim().length === 0

const normalizeIdentifierField = ({
  value,
  fieldName
}: {
  value: string
  fieldName: string
}) => {
  const trimmed = value.trim()
  if (trimmed.length === 0) {
    return {
      ok: false as const,
      error: {
        code: 'policy_scope_invalid' as const,
        message: `Policy scope field ${fieldName} cannot be empty`
      }
    }
  }

  return {
    ok: true as const,
    value: trimmed
  }
}

const normalizeMethod = (rawMethod: string) => {
  const method = rawMethod.trim().toUpperCase()
  const parseResult = CanonicalRequestDescriptorSchema.shape.method.safeParse(method)
  if (!parseResult.success) {
    return {
      ok: false as const,
      error: {
        code: 'policy_method_invalid' as const,
        message: `Policy method "${rawMethod}" is invalid`
      }
    }
  }

  return {
    ok: true as const,
    value: parseResult.data
  }
}

const normalizeHost = (rawHost: string) => {
  const trimmed = rawHost.trim()
  if (trimmed.length === 0) {
    return {
      ok: false as const,
      error: {
        code: 'policy_host_invalid' as const,
        message: 'Policy host cannot be empty'
      }
    }
  }

  if (
    trimmed.includes('*') ||
    trimmed.includes('://') ||
    trimmed.includes('/') ||
    trimmed.includes('?') ||
    trimmed.includes('#') ||
    trimmed.includes('@')
  ) {
    return {
      ok: false as const,
      error: {
        code: 'policy_host_invalid' as const,
        message:
          `Policy host "${rawHost}" must be an exact bare host without wildcards, ` +
          'scheme, path, query, fragment, or userinfo'
      }
    }
  }

  let parsedHost: URL
  try {
    parsedHost = new URL(`https://${trimmed}`)
  } catch {
    return {
      ok: false as const,
      error: {
        code: 'policy_host_invalid' as const,
        message: `Policy host "${rawHost}" is invalid`
      }
    }
  }

  if (parsedHost.username || parsedHost.password || parsedHost.port || parsedHost.pathname !== '/') {
    return {
      ok: false as const,
      error: {
        code: 'policy_host_invalid' as const,
        message: `Policy host "${rawHost}" must not include credentials, port, or path`
      }
    }
  }

  const normalizedHost = parsedHost.hostname.toLowerCase()
  if (normalizedHost.length === 0 || normalizedHost.endsWith('.')) {
    return {
      ok: false as const,
      error: {
        code: 'policy_host_invalid' as const,
        message: `Policy host "${rawHost}" is invalid`
      }
    }
  }

  return {
    ok: true as const,
    value: normalizedHost
  }
}

const normalizeQueryKeys = (queryKeys: string[]) => {
  const seenQueryKeys = new Set<string>()
  const normalizedQueryKeys: string[] = []

  for (const key of queryKeys) {
    const normalizedKey = key.trim()
    if (normalizedKey.length === 0) {
      return {
        ok: false as const,
        error: {
          code: 'policy_query_keys_invalid' as const,
          message: 'Policy query_keys cannot contain empty values'
        }
      }
    }

    if (seenQueryKeys.has(normalizedKey)) {
      return {
        ok: false as const,
        error: {
          code: 'policy_query_keys_invalid' as const,
          message: `Duplicate query key "${normalizedKey}" is not allowed`
        }
      }
    }

    seenQueryKeys.add(normalizedKey)
    normalizedQueryKeys.push(normalizedKey)
  }

  normalizedQueryKeys.sort()
  return {
    ok: true as const,
    value: normalizedQueryKeys
  }
}

const normalizeConstraintStringList = ({
  values,
  fieldName,
  toCanonical
}: {
  values: string[]
  fieldName: string
  toCanonical?: (value: string) => string
}) => {
  const seen = new Set<string>()
  const normalizedValues: string[] = []

  for (const value of values) {
    const trimmed = value.trim()
    if (trimmed.length === 0) {
      return {
        ok: false as const,
        message: `Constraint ${fieldName} cannot contain empty values`
      }
    }

    const canonicalValue = toCanonical ? toCanonical(trimmed) : trimmed
    if (seen.has(canonicalValue)) {
      return {
        ok: false as const,
        message: `Constraint ${fieldName} cannot contain duplicates`
      }
    }

    seen.add(canonicalValue)
    normalizedValues.push(canonicalValue)
  }

  normalizedValues.sort()
  return {
    ok: true as const,
    value: normalizedValues
  }
}

const normalizePolicyConstraints = (
  constraints: OpenApiPolicyRule['constraints']
): NormalizePolicyConstraintsResult => {
  if (!constraints) {
    return {
      ok: true,
      constraints: undefined
    }
  }

  const normalizedConstraints: PolicyConstraints = {...constraints}

  if (constraints.allowed_query_keys) {
    const normalizedQueryKeyResult = normalizeQueryKeys(constraints.allowed_query_keys)
    if (!normalizedQueryKeyResult.ok) {
      return {
        ok: false,
        message: normalizedQueryKeyResult.error.message
      }
    }

    normalizedConstraints.allowed_query_keys = normalizedQueryKeyResult.value
  }

  if (constraints.recipient_allowlist) {
    const normalizedRecipientAllowlistResult = normalizeConstraintStringList({
      values: constraints.recipient_allowlist,
      fieldName: 'recipient_allowlist'
    })
    if (!normalizedRecipientAllowlistResult.ok) {
      return {
        ok: false,
        message: normalizedRecipientAllowlistResult.message
      }
    }

    normalizedConstraints.recipient_allowlist = normalizedRecipientAllowlistResult.value
  }

  if (constraints.recipient_domain_allowlist) {
    const normalizedDomainAllowlistResult = normalizeConstraintStringList({
      values: constraints.recipient_domain_allowlist,
      fieldName: 'recipient_domain_allowlist',
      toCanonical: value => value.toLowerCase()
    })
    if (!normalizedDomainAllowlistResult.ok) {
      return {
        ok: false,
        message: normalizedDomainAllowlistResult.message
      }
    }

    normalizedConstraints.recipient_domain_allowlist = normalizedDomainAllowlistResult.value
  }

  const parsedConstraints = PolicyConstraintsSchema.safeParse(normalizedConstraints)
  if (!parsedConstraints.success) {
    return {
      ok: false,
      message: 'Policy constraints failed schema validation'
    }
  }

  return {
    ok: true,
    constraints: parsedConstraints.data
  }
}

const normalizePolicyScope = (scope: OpenApiPolicyRule['scope']): NormalizePolicyScopeResult => {
  const normalizedTenantResult = normalizeIdentifierField({
    value: scope.tenant_id,
    fieldName: 'tenant_id'
  })
  if (!normalizedTenantResult.ok) {
    return {
      ok: false,
      error: normalizedTenantResult.error
    }
  }

  const normalizedIntegrationResult = normalizeIdentifierField({
    value: scope.integration_id,
    fieldName: 'integration_id'
  })
  if (!normalizedIntegrationResult.ok) {
    return {
      ok: false,
      error: normalizedIntegrationResult.error
    }
  }

  const normalizedActionGroupResult = normalizeIdentifierField({
    value: scope.action_group,
    fieldName: 'action_group'
  })
  if (!normalizedActionGroupResult.ok) {
    return {
      ok: false,
      error: normalizedActionGroupResult.error
    }
  }

  let normalizedWorkloadId = scope.workload_id
  if (scope.workload_id !== null && scope.workload_id !== undefined) {
    const normalizedWorkloadResult = normalizeIdentifierField({
      value: scope.workload_id,
      fieldName: 'workload_id'
    })
    if (!normalizedWorkloadResult.ok) {
      return {
        ok: false,
        error: normalizedWorkloadResult.error
      }
    }
    normalizedWorkloadId = normalizedWorkloadResult.value
  }

  let normalizedTemplateId = scope.template_id
  if (scope.template_id !== null && scope.template_id !== undefined) {
    const normalizedTemplateIdResult = normalizeIdentifierField({
      value: scope.template_id,
      fieldName: 'template_id'
    })
    if (!normalizedTemplateIdResult.ok) {
      return {
        ok: false,
        error: normalizedTemplateIdResult.error
      }
    }
    normalizedTemplateId = normalizedTemplateIdResult.value
  }

  const normalizedMethodResult = normalizeMethod(scope.method)
  if (!normalizedMethodResult.ok) {
    return {
      ok: false,
      error: normalizedMethodResult.error
    }
  }

  const normalizedHostResult = normalizeHost(scope.host)
  if (!normalizedHostResult.ok) {
    return {
      ok: false,
      error: normalizedHostResult.error
    }
  }

  const normalizedQueryKeyResult =
    scope.query_keys === undefined ? null : normalizeQueryKeys(scope.query_keys)
  if (normalizedQueryKeyResult && !normalizedQueryKeyResult.ok) {
    return {
      ok: false,
      error: normalizedQueryKeyResult.error
    }
  }

  const normalizedScope: OpenApiPolicyRule['scope'] = {
    ...scope,
    tenant_id: normalizedTenantResult.value,
    integration_id: normalizedIntegrationResult.value,
    action_group: normalizedActionGroupResult.value,
    workload_id: normalizedWorkloadId,
    template_id: normalizedTemplateId,
    method: normalizedMethodResult.value,
    host: normalizedHostResult.value,
    ...(normalizedQueryKeyResult ? {query_keys: normalizedQueryKeyResult.value} : {})
  }

  if (scope.template_version !== undefined && scope.template_version !== null && scope.template_version < 1) {
    return {
      ok: false,
      error: {
        code: 'policy_scope_invalid',
        message: 'Policy template_version must be >= 1 when provided'
      }
    }
  }

  return {
    ok: true,
    scope: normalizedScope
  }
}

const normalizeRateLimitForPolicy = ({
  ruleType,
  rateLimit
}: {
  ruleType: OpenApiPolicyRule['rule_type']
  rateLimit: OpenApiPolicyRule['rate_limit']
}): NormalizePolicyRateLimitResult => {
  if (ruleType === 'rate_limit') {
    if (rateLimit === null || rateLimit === undefined) {
      return {
        ok: false,
        error: {
          code: 'policy_rate_limit_invalid',
          message: 'rate_limit rules must include a non-null rate_limit payload'
        }
      }
    }

    return {
      ok: true,
      rate_limit: rateLimit
    }
  }

  if (rateLimit !== null && rateLimit !== undefined) {
    return {
      ok: false,
      error: {
        code: 'policy_rate_limit_invalid',
        message: `${ruleType} rules must not include a rate_limit payload`
      }
    }
  }

  return {
    ok: true,
    rate_limit: null
  }
}

const toPolicyRuleInvalid = (message: string): ValidatePolicyRuleResult => ({
  ok: false,
  error: {
    code: 'policy_rule_invalid',
    message
  }
})

export const validatePolicyRule = (rawInput: ValidatePolicyRuleInput): ValidatePolicyRuleResult => {
  const parsedInput = ValidatePolicyRuleInputSchema.safeParse(rawInput)
  if (!parsedInput.success) {
    return toPolicyRuleInvalid('Policy payload failed schema validation')
  }

  const normalizedScopeResult = normalizePolicyScope(parsedInput.data.policy.scope)
  if (!normalizedScopeResult.ok) {
    return {
      ok: false,
      error: normalizedScopeResult.error
    }
  }

  const normalizedRateLimitResult = normalizeRateLimitForPolicy({
    ruleType: parsedInput.data.policy.rule_type,
    rateLimit: parsedInput.data.policy.rate_limit
  })
  if (!normalizedRateLimitResult.ok) {
    return {
      ok: false,
      error: normalizedRateLimitResult.error
    }
  }

  const normalizedConstraintsResult = normalizePolicyConstraints(parsedInput.data.policy.constraints)
  if (!normalizedConstraintsResult.ok) {
    return toPolicyRuleInvalid(normalizedConstraintsResult.message)
  }

  const normalizedPolicyParseResult = OpenApiPolicyRuleSchema.safeParse({
    ...parsedInput.data.policy,
    scope: normalizedScopeResult.scope,
    constraints: normalizedConstraintsResult.constraints,
    rate_limit: normalizedRateLimitResult.rate_limit
  })

  if (!normalizedPolicyParseResult.success) {
    return toPolicyRuleInvalid('Normalized policy payload failed schema validation')
  }

  return {
    ok: true,
    value: normalizedPolicyParseResult.data
  }
}

const isNormalizedDescriptorSafe = (descriptor: OpenApiCanonicalRequestDescriptor) => {
  if (isBlank(descriptor.tenant_id)) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor field tenant_id cannot be empty'
      }
    }
  }

  if (isBlank(descriptor.workload_id)) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor field workload_id cannot be empty'
      }
    }
  }

  if (isBlank(descriptor.integration_id)) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor field integration_id cannot be empty'
      }
    }
  }

  if (isBlank(descriptor.template_id)) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor field template_id cannot be empty'
      }
    }
  }

  if (isBlank(descriptor.matched_path_group_id)) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor field matched_path_group_id cannot be empty'
      }
    }
  }

  const queryKeyResult = normalizeQueryKeys(descriptor.query_keys)
  if (!queryKeyResult.ok) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: queryKeyResult.error.message
      }
    }
  }

  let destinationUrl: URL
  try {
    destinationUrl = new URL(descriptor.canonical_url)
  } catch {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor canonical_url is invalid'
      }
    }
  }

  if (destinationUrl.username || destinationUrl.password || destinationUrl.hash) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor canonical_url must not include credentials or fragment'
      }
    }
  }

  if (destinationUrl.hostname.trim().length === 0 || destinationUrl.hostname.endsWith('.')) {
    return {
      ok: false as const,
      error: {
        code: 'descriptor_invalid' as const,
        message: 'Descriptor canonical_url host is invalid'
      }
    }
  }

  return {
    ok: true as const,
    value: {
      descriptor,
      normalizedHost: destinationUrl.hostname.toLowerCase(),
      normalizedQueryKeys: queryKeyResult.value
    }
  }
}

const buildDerivedRuleScope = (
  descriptor: OpenApiCanonicalRequestDescriptor
): BuildDerivedRuleScopeResult => {
  const descriptorSafetyResult = isNormalizedDescriptorSafe(descriptor)
  if (!descriptorSafetyResult.ok) {
    return {
      ok: false,
      error: descriptorSafetyResult.error
    }
  }

  return {
    ok: true,
    scope: {
      tenant_id: descriptor.tenant_id.trim(),
      workload_id: descriptor.workload_id.trim(),
      integration_id: descriptor.integration_id.trim(),
      template_id: descriptor.template_id.trim(),
      template_version: descriptor.template_version,
      action_group: descriptor.matched_path_group_id.trim(),
      method: descriptor.method,
      host: descriptorSafetyResult.value.normalizedHost,
      query_keys: descriptorSafetyResult.value.normalizedQueryKeys
    }
  }
}

export const derivePolicyFromApprovalDecision = (
  rawInput: DerivePolicyFromApprovalDecisionInput
): DerivePolicyFromApprovalDecisionResult => {
  const parsedInput = DerivePolicyFromApprovalDecisionInputSchema.safeParse(rawInput)
  if (!parsedInput.success) {
    return {
      ok: false,
      error: {
        code: 'approval_decision_invalid',
        message: 'Approval decision payload failed schema validation'
      }
    }
  }

  const policyId = parsedInput.data.policy_id.trim()
  if (policyId.length === 0) {
    return {
      ok: false,
      error: {
        code: 'approval_decision_invalid',
        message: 'policy_id must be a non-empty string'
      }
    }
  }

  const parsedDescriptor = OpenApiCanonicalRequestDescriptorSchema.safeParse(parsedInput.data.descriptor)
  if (!parsedDescriptor.success) {
    return {
      ok: false,
      error: {
        code: 'descriptor_invalid',
        message: 'Descriptor payload failed schema validation'
      }
    }
  }

  const derivedScopeResult = buildDerivedRuleScope(parsedDescriptor.data)
  if (!derivedScopeResult.ok) {
    return {
      ok: false,
      error: derivedScopeResult.error
    }
  }

  if (parsedInput.data.approval_status === 'approved' && parsedInput.data.approval_mode === 'once') {
    return {
      ok: true,
      value: null
    }
  }

  const derivedRuleType: OpenApiPolicyRule['rule_type'] =
    parsedInput.data.approval_status === 'approved' ? 'allow' : 'deny'

  const normalizedConstraintsResult = normalizePolicyConstraints(parsedInput.data.constraints)
  if (!normalizedConstraintsResult.ok) {
    return {
      ok: false,
      error: {
        code: 'approval_decision_invalid',
        message: normalizedConstraintsResult.message
      }
    }
  }

  const derivedPolicyCandidate: OpenApiPolicyRule = {
    policy_id: policyId,
    rule_type: derivedRuleType,
    scope: derivedScopeResult.scope,
    ...(normalizedConstraintsResult.constraints
      ? {constraints: normalizedConstraintsResult.constraints}
      : {}),
    rate_limit: null
  }

  const normalizedDerivedPolicy = validatePolicyRule({
    policy: derivedPolicyCandidate
  })
  if (!normalizedDerivedPolicy.ok) {
    return {
      ok: false,
      error: {
        code: 'derived_policy_invalid',
        message: `Derived policy failed validation: ${normalizedDerivedPolicy.error.code}`
      }
    }
  }

  return {
    ok: true,
    value: normalizedDerivedPolicy.value
  }
}
