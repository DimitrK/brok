import type {CanonicalRequestDescriptor, PolicyRule, Template} from '@broker-interceptor/schemas'

import {classifyPathGroup} from './classification'
import {
  EvaluatePolicyInputSchema,
  PolicyDecisionSchema,
  type EvaluatePolicyInput,
  type PolicyDecision,
  type PolicyDecisionTraceEntry,
  type RuleMatchType
} from './contracts'

type MatchedRule = {
  index: number
  rule: PolicyRule
  match_type: RuleMatchType
  specificity: number
}

type MatchedRulesByType = {
  deny: MatchedRule[]
  allow: MatchedRule[]
  approval_required: MatchedRule[]
  rate_limit: MatchedRule[]
}

export type RateLimitCheckInput = {
  descriptor: CanonicalRequestDescriptor
  rule: PolicyRule
  key: string
  now: Date
}

export type RateLimitCheckResult = {
  allowed: boolean
}

export type RateLimiter = (
  input: RateLimitCheckInput
) => Promise<RateLimitCheckResult> | RateLimitCheckResult

export type RateLimitKeyBuilder = (input: {
  descriptor: CanonicalRequestDescriptor
  rule: PolicyRule
}) => string

export type EvaluatePolicyDecisionInput = EvaluatePolicyInput & {
  rateLimiter?: RateLimiter
  buildRateLimitKey?: RateLimitKeyBuilder
  now?: Date
}

const DEFAULT_RISK_TIER: 'low' | 'medium' | 'high' = 'medium'
const DEFAULT_ACTION_GROUP = 'unclassified'
const MAX_OPTIONAL_SCOPE_FIELDS = 4

const normalizeHost = (host: string) => host.toLowerCase()
const normalizeMethod = (method: string) => method.toUpperCase()

const normalizeQueryKeys = (queryKeys: string[]) => {
  const queryKeySet = new Set(queryKeys)
  return [...queryKeySet].sort()
}

const stringifyQueryKeys = (queryKeys: string[]) => normalizeQueryKeys(queryKeys).join(',')

const queryKeysExactlyMatch = (left: string[], right: string[]) => {
  return stringifyQueryKeys(left) === stringifyQueryKeys(right)
}

const toComparablePolicyId = (policyId: string | null | undefined) => policyId ?? ''

const comparePolicyId = (left: string | null | undefined, right: string | null | undefined) => {
  const leftId = toComparablePolicyId(left)
  const rightId = toComparablePolicyId(right)

  if (leftId === rightId) {
    return 0
  }

  return leftId < rightId ? -1 : 1
}

const sortMatchedRules = (matchedRules: MatchedRule[]) =>
  [...matchedRules].sort((left, right) => {
    if (left.specificity !== right.specificity) {
      return right.specificity - left.specificity
    }

    const policyIdComparison = comparePolicyId(left.rule.policy_id, right.rule.policy_id)
    if (policyIdComparison !== 0) {
      return policyIdComparison
    }

    return left.index - right.index
  })

const splitRuleSpecificity = (matchedRules: MatchedRule[]) => {
  const sorted = sortMatchedRules(matchedRules)
  return {
    exact: sorted.filter(rule => rule.match_type === 'exact'),
    scoped: sorted.filter(rule => rule.match_type === 'scoped')
  }
}

const selectBySpecificity = (matchedRules: MatchedRule[]) => {
  const {exact, scoped} = splitRuleSpecificity(matchedRules)
  return exact[0] ?? scoped[0]
}

const isOptionalScopeFieldPresent = (value: unknown) => value !== null && value !== undefined

const isExactMatch = (scope: PolicyRule['scope']) => {
  const hasWorkload = isOptionalScopeFieldPresent(scope.workload_id)
  const hasTemplateId = isOptionalScopeFieldPresent(scope.template_id)
  const hasTemplateVersion = isOptionalScopeFieldPresent(scope.template_version)
  const hasQueryKeys = scope.query_keys !== undefined

  return hasWorkload && hasTemplateId && hasTemplateVersion && hasQueryKeys
}

const countSpecificity = (scope: PolicyRule['scope']) => {
  const fields = [
    scope.workload_id,
    scope.template_id,
    scope.template_version,
    scope.query_keys
  ].filter(isOptionalScopeFieldPresent)

  return Math.min(MAX_OPTIONAL_SCOPE_FIELDS, fields.length)
}

const toMatchType = (scope: PolicyRule['scope']): RuleMatchType =>
  isExactMatch(scope) ? 'exact' : 'scoped'

const matchesRuleScope = ({
  descriptor,
  host,
  rule
}: {
  descriptor: CanonicalRequestDescriptor
  host: string
  rule: PolicyRule
}) => {
  if (rule.scope.tenant_id !== descriptor.tenant_id) {
    return false
  }

  if (rule.scope.integration_id !== descriptor.integration_id) {
    return false
  }

  if (rule.scope.action_group !== descriptor.matched_path_group_id) {
    return false
  }

  if (normalizeMethod(rule.scope.method) !== normalizeMethod(descriptor.method)) {
    return false
  }

  if (normalizeHost(rule.scope.host) !== host) {
    return false
  }

  if (isOptionalScopeFieldPresent(rule.scope.workload_id) && rule.scope.workload_id !== descriptor.workload_id) {
    return false
  }

  if (isOptionalScopeFieldPresent(rule.scope.template_id) && rule.scope.template_id !== descriptor.template_id) {
    return false
  }

  if (
    isOptionalScopeFieldPresent(rule.scope.template_version) &&
    rule.scope.template_version !== descriptor.template_version
  ) {
    return false
  }

  if (rule.scope.query_keys !== undefined && !queryKeysExactlyMatch(rule.scope.query_keys, descriptor.query_keys)) {
    return false
  }

  return true
}

const groupMatchedRulesByType = ({
  descriptor,
  host,
  policies
}: {
  descriptor: CanonicalRequestDescriptor
  host: string
  policies: PolicyRule[]
}): MatchedRulesByType => {
  const matchedRules: MatchedRulesByType = {
    deny: [],
    allow: [],
    approval_required: [],
    rate_limit: []
  }

  for (const [index, policy] of policies.entries()) {
    if (!matchesRuleScope({descriptor, host, rule: policy})) {
      continue
    }

    const matchedRule: MatchedRule = {
      index,
      rule: policy,
      match_type: toMatchType(policy.scope),
      specificity: countSpecificity(policy.scope)
    }

    switch (policy.rule_type) {
      case 'deny':
        matchedRules.deny.push(matchedRule)
        break
      case 'allow':
        matchedRules.allow.push(matchedRule)
        break
      case 'approval_required':
        matchedRules.approval_required.push(matchedRule)
        break
      case 'rate_limit':
        matchedRules.rate_limit.push(matchedRule)
        break
      default:
        break
    }
  }

  return matchedRules
}

const buildDefaultRateLimitKey: RateLimitKeyBuilder = ({descriptor}) => {
  const descriptorHost = extractHostFromCanonicalUrl(descriptor.canonical_url)
  const segments = [
    `tenant:${descriptor.tenant_id}`,
    `workload:${descriptor.workload_id}`,
    `integration:${descriptor.integration_id}`,
    `action_group:${descriptor.matched_path_group_id}`,
    `method:${normalizeMethod(descriptor.method)}`,
    `host:${descriptorHost}`
  ]

  segments.push(`template:${descriptor.template_id}`)
  segments.push(`template_version:${descriptor.template_version}`)
  segments.push(`query_keys:${stringifyQueryKeys(descriptor.query_keys)}`)

  return segments.join('|')
}

const resolveActionGroup = (actionGroup: string | undefined) => {
  if (!actionGroup) {
    return DEFAULT_ACTION_GROUP
  }

  const trimmed = actionGroup.trim()
  return trimmed.length === 0 ? DEFAULT_ACTION_GROUP : trimmed
}

const findPathGroupById = ({
  template,
  groupId
}: {
  template: Template
  groupId: string
}) => template.path_groups.find(pathGroup => pathGroup.group_id === groupId)

const resolveRiskTier = ({
  template,
  actionGroup
}: {
  template: Template
  actionGroup: string
}) => findPathGroupById({template, groupId: actionGroup})?.risk_tier ?? DEFAULT_RISK_TIER

const buildDecision = (decision: PolicyDecision): PolicyDecision => PolicyDecisionSchema.parse(decision)

const appendTrace = (
  trace: PolicyDecisionTraceEntry[],
  entry: PolicyDecisionTraceEntry
): PolicyDecisionTraceEntry[] => [...trace, entry]

const extractHostFromCanonicalUrl = (canonicalUrl: string) => normalizeHost(new URL(canonicalUrl).hostname)

export const evaluatePolicyDecision = async (
  rawInput: EvaluatePolicyDecisionInput
): Promise<PolicyDecision> => {
  const input = EvaluatePolicyInputSchema.parse({
    descriptor: rawInput.descriptor,
    template: rawInput.template,
    policies: rawInput.policies
  })
  const rateLimiter = rawInput.rateLimiter
  const buildRateLimitKey = rawInput.buildRateLimitKey ?? buildDefaultRateLimitKey
  const now = rawInput.now ?? new Date()
  const initialActionGroup = resolveActionGroup(input.descriptor.matched_path_group_id)
  const initialRiskTier = resolveRiskTier({
    template: input.template,
    actionGroup: initialActionGroup
  })
  let trace: PolicyDecisionTraceEntry[] = []

  if (
    input.descriptor.template_id !== input.template.template_id ||
    input.descriptor.template_version !== input.template.version
  ) {
    trace = appendTrace(trace, {
      stage: 'policy',
      outcome: 'denied',
      detail: 'Descriptor template scope does not match evaluation template'
    })

    return buildDecision({
      decision: 'denied',
      reason_code: 'template_scope_mismatch',
      action_group: initialActionGroup,
      risk_tier: initialRiskTier,
      trace
    })
  }

  const classification = classifyPathGroup({
    template: input.template,
    method: input.descriptor.method,
    canonical_url: input.descriptor.canonical_url
  })

  if (!classification.matched) {
    trace = appendTrace(trace, {
      stage: 'classification',
      outcome: 'not_matched',
      detail: `No path group matched for ${input.descriptor.method} ${input.descriptor.canonical_url}`
    })

    return buildDecision({
      decision: 'denied',
      reason_code: classification.reason_code,
      action_group: initialActionGroup,
      risk_tier: initialRiskTier,
      trace
    })
  }

  const actionGroup = classification.path_group.group_id
  const riskTier = classification.path_group.risk_tier
  trace = appendTrace(trace, {
    stage: 'classification',
    outcome: 'matched',
    detail: `Matched path group ${actionGroup} with pattern ${classification.path_group.matched_pattern}`
  })

  if (input.descriptor.matched_path_group_id !== actionGroup) {
    trace = appendTrace(trace, {
      stage: 'classification',
      outcome: 'error',
      detail: 'Descriptor matched_path_group_id does not match computed path group'
    })

    return buildDecision({
      decision: 'denied',
      reason_code: 'descriptor_group_mismatch',
      action_group: actionGroup,
      risk_tier: riskTier,
      trace
    })
  }

  const host = extractHostFromCanonicalUrl(input.descriptor.canonical_url)
  const matchedRules = groupMatchedRulesByType({
    descriptor: input.descriptor,
    host,
    policies: input.policies
  })

  const selectedDenyRule = selectBySpecificity(matchedRules.deny)
  if (selectedDenyRule) {
    trace = appendTrace(trace, {
      stage: 'policy',
      outcome: 'selected',
      detail: `Deny rule selected with precedence (${selectedDenyRule.match_type})`,
      policy_id: selectedDenyRule.rule.policy_id ?? null,
      rule_type: selectedDenyRule.rule.rule_type
    })

    return buildDecision({
      decision: 'denied',
      reason_code: 'policy_deny',
      action_group: actionGroup,
      risk_tier: riskTier,
      policy_match: {
        policy_id: selectedDenyRule.rule.policy_id ?? null,
        rule_type: selectedDenyRule.rule.rule_type,
        match_type: selectedDenyRule.match_type
      },
      trace
    })
  }

  const selectedAllowRule = selectBySpecificity(matchedRules.allow)
  const selectedApprovalRule = selectBySpecificity(matchedRules.approval_required)

  if (!selectedAllowRule) {
    if (selectedApprovalRule) {
      trace = appendTrace(trace, {
        stage: 'policy',
        outcome: 'approval_required',
        detail: `Approval rule selected (${selectedApprovalRule.match_type})`,
        policy_id: selectedApprovalRule.rule.policy_id ?? null,
        rule_type: selectedApprovalRule.rule.rule_type
      })

      return buildDecision({
        decision: 'approval_required',
        reason_code: 'policy_approval_required',
        action_group: actionGroup,
        risk_tier: riskTier,
        policy_match: {
          policy_id: selectedApprovalRule.rule.policy_id ?? null,
          rule_type: selectedApprovalRule.rule.rule_type,
          match_type: selectedApprovalRule.match_type
        },
        trace
      })
    }

    if (classification.path_group.approval_mode === 'required') {
      trace = appendTrace(trace, {
        stage: 'policy',
        outcome: 'approval_required',
        detail: 'Template approval mode requires approval for this path group'
      })

      return buildDecision({
        decision: 'approval_required',
        reason_code: 'template_approval_required',
        action_group: actionGroup,
        risk_tier: riskTier,
        trace
      })
    }

    trace = appendTrace(trace, {
      stage: 'policy',
      outcome: 'denied',
      detail: 'No allow rule matched; default deny applied'
    })

    return buildDecision({
      decision: 'denied',
      reason_code: 'policy_default_deny',
      action_group: actionGroup,
      risk_tier: riskTier,
      trace
    })
  }

  trace = appendTrace(trace, {
    stage: 'policy',
    outcome: 'allowed',
    detail: `Allow rule selected (${selectedAllowRule.match_type})`,
    policy_id: selectedAllowRule.rule.policy_id ?? null,
    rule_type: selectedAllowRule.rule.rule_type
  })

  const rateLimitRules = sortMatchedRules(matchedRules.rate_limit)
  if (rateLimitRules.length === 0) {
    return buildDecision({
      decision: 'allowed',
      reason_code: 'policy_allow',
      action_group: actionGroup,
      risk_tier: riskTier,
      policy_match: {
        policy_id: selectedAllowRule.rule.policy_id ?? null,
        rule_type: selectedAllowRule.rule.rule_type,
        match_type: selectedAllowRule.match_type
      },
      trace
    })
  }

  if (!rateLimiter) {
    trace = appendTrace(trace, {
      stage: 'rate_limit',
      outcome: 'error',
      detail: 'Rate limit rules matched but no rate limiter is configured'
    })

    return buildDecision({
      decision: 'denied',
      reason_code: 'rate_limit_checker_missing',
      action_group: actionGroup,
      risk_tier: riskTier,
      policy_match: {
        policy_id: selectedAllowRule.rule.policy_id ?? null,
        rule_type: selectedAllowRule.rule.rule_type,
        match_type: selectedAllowRule.match_type
      },
      trace
    })
  }

  for (const matchedRateLimitRule of rateLimitRules) {
    const rateLimitConfig = matchedRateLimitRule.rule.rate_limit
    if (!rateLimitConfig) {
      trace = appendTrace(trace, {
        stage: 'rate_limit',
        outcome: 'error',
        detail: 'Rate limit rule is missing required rate_limit payload',
        policy_id: matchedRateLimitRule.rule.policy_id ?? null,
        rule_type: matchedRateLimitRule.rule.rule_type
      })

      return buildDecision({
        decision: 'denied',
        reason_code: 'invalid_rate_limit_rule',
        action_group: actionGroup,
        risk_tier: riskTier,
        policy_match: {
          policy_id: selectedAllowRule.rule.policy_id ?? null,
          rule_type: selectedAllowRule.rule.rule_type,
          match_type: selectedAllowRule.match_type
        },
        trace
      })
    }

    const rateLimitKey = buildRateLimitKey({
      descriptor: input.descriptor,
      rule: matchedRateLimitRule.rule
    })

    let rateLimitOutcome: RateLimitCheckResult
    try {
      rateLimitOutcome = await rateLimiter({
        descriptor: input.descriptor,
        rule: matchedRateLimitRule.rule,
        key: rateLimitKey,
        now
      })
    } catch {
      trace = appendTrace(trace, {
        stage: 'rate_limit',
        outcome: 'error',
        detail: 'Rate limiter failed while evaluating policy',
        policy_id: matchedRateLimitRule.rule.policy_id ?? null,
        rule_type: matchedRateLimitRule.rule.rule_type
      })

      return buildDecision({
        decision: 'denied',
        reason_code: 'rate_limit_check_failed',
        action_group: actionGroup,
        risk_tier: riskTier,
        policy_match: {
          policy_id: selectedAllowRule.rule.policy_id ?? null,
          rule_type: selectedAllowRule.rule.rule_type,
          match_type: selectedAllowRule.match_type
        },
        trace
      })
    }

    if (!rateLimitOutcome.allowed) {
      trace = appendTrace(trace, {
        stage: 'rate_limit',
        outcome: 'throttled',
        detail: 'Rate limit exceeded',
        policy_id: matchedRateLimitRule.rule.policy_id ?? null,
        rule_type: matchedRateLimitRule.rule.rule_type
      })

      return buildDecision({
        decision: 'throttled',
        reason_code: 'policy_rate_limited',
        action_group: actionGroup,
        risk_tier: riskTier,
        policy_match: {
          policy_id: selectedAllowRule.rule.policy_id ?? null,
          rule_type: selectedAllowRule.rule.rule_type,
          match_type: selectedAllowRule.match_type
        },
        rate_limit: {
          policy_id: matchedRateLimitRule.rule.policy_id ?? null,
          key: rateLimitKey,
          max_requests: rateLimitConfig.max_requests,
          interval_seconds: rateLimitConfig.interval_seconds
        },
        trace
      })
    }
  }

  trace = appendTrace(trace, {
    stage: 'rate_limit',
    outcome: 'allowed',
    detail: 'Rate limit checks passed'
  })

  return buildDecision({
    decision: 'allowed',
    reason_code: 'policy_allow',
    action_group: actionGroup,
    risk_tier: riskTier,
    policy_match: {
      policy_id: selectedAllowRule.rule.policy_id ?? null,
      rule_type: selectedAllowRule.rule.rule_type,
      match_type: selectedAllowRule.match_type
    },
    trace
  })
}
