import {
  CanonicalRequestDescriptorSchema,
  OpenApiPolicyRuleSchema,
  PolicyConstraintsSchema,
  type CanonicalRequestDescriptor,
  type PolicyRule
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient, RepositoryOperationContext} from '../types.js'
import {
  createDomainId,
  normalizeHost,
  normalizeMethod,
  normalizeUniqueStringList,
  resolveRepositoryDbClient
} from '../utils.js'

const normalizePolicyConstraints = (constraints: PolicyRule['constraints']): PolicyRule['constraints'] => {
  if (!constraints) {
    return undefined
  }

  const parsed = PolicyConstraintsSchema.parse(constraints)
  return {
    ...(parsed.recipient_allowlist
      ? {
          recipient_allowlist: normalizeUniqueStringList(parsed.recipient_allowlist)
        }
      : {}),
    ...(parsed.recipient_domain_allowlist
      ? {
          recipient_domain_allowlist: normalizeUniqueStringList(
            parsed.recipient_domain_allowlist.map(domain => domain.toLowerCase())
          )
        }
      : {}),
    ...(parsed.allowed_query_keys
      ? {
          allowed_query_keys: normalizeUniqueStringList(parsed.allowed_query_keys)
        }
      : {}),
    ...(parsed.require_mfa_approval !== undefined
      ? {require_mfa_approval: parsed.require_mfa_approval}
      : {}),
    ...(parsed.max_body_bytes !== undefined ? {max_body_bytes: parsed.max_body_bytes} : {})
  }
}

const normalizePolicyScope = (scope: PolicyRule['scope']): PolicyRule['scope'] => {
  const tenantId = scope.tenant_id.trim()
  const integrationId = scope.integration_id.trim()
  const actionGroup = scope.action_group.trim()

  if (tenantId.length === 0 || integrationId.length === 0 || actionGroup.length === 0) {
    throw new DbRepositoryError('validation_error', 'Policy scope identifiers cannot be empty')
  }

  const normalizedScope: PolicyRule['scope'] = {
    tenant_id: tenantId,
    integration_id: integrationId,
    action_group: actionGroup,
    method: normalizeMethod(scope.method),
    host: normalizeHost(scope.host)
  }

  if (scope.workload_id) {
    const workloadId = scope.workload_id.trim()
    if (workloadId.length === 0) {
      throw new DbRepositoryError('validation_error', 'scope.workload_id cannot be empty when provided')
    }

    normalizedScope.workload_id = workloadId
  }

  if (scope.template_id) {
    const templateId = scope.template_id.trim()
    if (templateId.length === 0) {
      throw new DbRepositoryError('validation_error', 'scope.template_id cannot be empty when provided')
    }

    normalizedScope.template_id = templateId
  }

  if (scope.template_version !== undefined && scope.template_version !== null) {
    if (!Number.isInteger(scope.template_version) || scope.template_version < 1) {
      throw new DbRepositoryError('validation_error', 'scope.template_version must be an integer >= 1')
    }

    normalizedScope.template_version = scope.template_version
  }

  if (scope.query_keys) {
    normalizedScope.query_keys = normalizeUniqueStringList(scope.query_keys)
  }

  return normalizedScope
}

const normalizePolicyRule = (policy: PolicyRule): PolicyRule => {
  const parsedPolicy = OpenApiPolicyRuleSchema.parse(policy)
  const normalizedScope = normalizePolicyScope(parsedPolicy.scope)
  const normalizedConstraints = normalizePolicyConstraints(parsedPolicy.constraints)

  if (parsedPolicy.rule_type === 'rate_limit') {
    if (!parsedPolicy.rate_limit) {
      throw new DbRepositoryError('validation_error', 'rate_limit policy must include rate_limit payload')
    }

    if (
      !Number.isInteger(parsedPolicy.rate_limit.max_requests) ||
      parsedPolicy.rate_limit.max_requests < 1 ||
      !Number.isInteger(parsedPolicy.rate_limit.interval_seconds) ||
      parsedPolicy.rate_limit.interval_seconds < 1
    ) {
      throw new DbRepositoryError('validation_error', 'Invalid rate_limit policy values')
    }
  } else if (parsedPolicy.rate_limit !== null && parsedPolicy.rate_limit !== undefined) {
    throw new DbRepositoryError('validation_error', 'Only rate_limit rules can define rate_limit payload')
  }

  return OpenApiPolicyRuleSchema.parse({
    ...parsedPolicy,
    scope: normalizedScope,
    ...(normalizedConstraints ? {constraints: normalizedConstraints} : {}),
    ...(parsedPolicy.rule_type === 'rate_limit' ? {rate_limit: parsedPolicy.rate_limit} : {rate_limit: null})
  })
}

const toPolicyRule = (value: unknown): PolicyRule => OpenApiPolicyRuleSchema.parse(value)

const descriptorHost = (descriptor: CanonicalRequestDescriptor): string =>
  normalizeHost(new URL(descriptor.canonical_url).hostname)

const sortPoliciesDeterministically = (policies: PolicyRule[]): PolicyRule[] => {
  const specificity = (policy: PolicyRule): number => {
    let count = 0

    if (policy.scope.workload_id) {
      count += 1
    }

    if (policy.scope.template_id) {
      count += 1
    }

    if (policy.scope.template_version !== undefined && policy.scope.template_version !== null) {
      count += 1
    }

    if (policy.scope.query_keys && policy.scope.query_keys.length > 0) {
      count += 1
    }

    return count
  }

  return [...policies].sort((left, right) => {
    const specificityDelta = specificity(right) - specificity(left)
    if (specificityDelta !== 0) {
      return specificityDelta
    }

    const leftId = left.policy_id ?? ''
    const rightId = right.policy_id ?? ''
    if (leftId !== rightId) {
      return leftId.localeCompare(rightId)
    }

    return 0
  })
}

const scopeMatchesDescriptor = ({
  policy,
  descriptor,
  host
}: {
  policy: PolicyRule
  descriptor: CanonicalRequestDescriptor
  host: string
}): boolean => {
  if (policy.scope.tenant_id !== descriptor.tenant_id) {
    return false
  }

  if (policy.scope.integration_id !== descriptor.integration_id) {
    return false
  }

  if (policy.scope.action_group !== descriptor.matched_path_group_id) {
    return false
  }

  if (normalizeMethod(policy.scope.method) !== normalizeMethod(descriptor.method)) {
    return false
  }

  if (normalizeHost(policy.scope.host) !== host) {
    return false
  }

  if (policy.scope.workload_id && policy.scope.workload_id !== descriptor.workload_id) {
    return false
  }

  if (policy.scope.template_id && policy.scope.template_id !== descriptor.template_id) {
    return false
  }

  if (
    policy.scope.template_version !== undefined &&
    policy.scope.template_version !== null &&
    policy.scope.template_version !== descriptor.template_version
  ) {
    return false
  }

  if (policy.scope.query_keys) {
    const left = normalizeUniqueStringList(policy.scope.query_keys)
    const right = normalizeUniqueStringList(descriptor.query_keys)

    if (left.join(',') !== right.join(',')) {
      return false
    }
  }

  return true
}

export class PolicyRuleRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async createPolicyRule(input: {policy: PolicyRule; created_by?: string}): Promise<PolicyRule> {
    const normalizedPolicy = normalizePolicyRule(input.policy)
    const policyId = normalizedPolicy.policy_id ?? createDomainId('pol_')

    try {
      const created = await this.db.policyRule.create({
        data: {
          policyId,
          tenantId: normalizedPolicy.scope.tenant_id,
          enabled: true,
          ruleType: normalizedPolicy.rule_type,
          workloadId: normalizedPolicy.scope.workload_id,
          integrationId: normalizedPolicy.scope.integration_id,
          templateId: normalizedPolicy.scope.template_id,
          templateVersion: normalizedPolicy.scope.template_version,
          actionGroup: normalizedPolicy.scope.action_group,
          method: normalizeMethod(normalizedPolicy.scope.method),
          host: normalizeHost(normalizedPolicy.scope.host),
          queryKeys: normalizedPolicy.scope.query_keys ?? [],
          constraintsJson: normalizedPolicy.constraints ?? null,
          rateLimitMaxRequests: normalizedPolicy.rate_limit?.max_requests ?? null,
          rateLimitIntervalSeconds: normalizedPolicy.rate_limit?.interval_seconds ?? null,
          policyJson: {
            ...normalizedPolicy,
            policy_id: policyId
          },
          createdBy: input.created_by
        }
      })

      return toPolicyRule(created.policyJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getPolicyRuleById(input: {policy_id: string}): Promise<PolicyRule | null> {
    const policyId = input.policy_id.trim()
    if (policyId.length === 0) {
      throw new DbRepositoryError('validation_error', 'policy_id cannot be empty')
    }

    try {
      const record = await this.db.policyRule.findUnique({
        where: {
          policyId
        },
        select: {
          policyJson: true,
          enabled: true
        }
      })

      if (!record || !record.enabled) {
        return null
      }

      return toPolicyRule(record.policyJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async disablePolicyRule(input: {policy_id: string}): Promise<void> {
    const policyId = input.policy_id.trim()
    if (policyId.length === 0) {
      throw new DbRepositoryError('validation_error', 'policy_id cannot be empty')
    }

    try {
      await this.db.policyRule.update({
        where: {
          policyId
        },
        data: {
          enabled: false
        }
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listPolicyRulesForDescriptorScope(input: {
    descriptor: CanonicalRequestDescriptor
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }, context?: RepositoryOperationContext): Promise<PolicyRule[]> {
    const operationContext =
      input.context ?? context ?? (input.transaction_client !== undefined
        ? {
            transaction_client: input.transaction_client
          }
        : undefined)
    const descriptor = CanonicalRequestDescriptorSchema.parse(input.descriptor)
    const host = descriptorHost(descriptor)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'policyRule',
          method: 'findMany'
        }
      ])

      const records = await dbClient.policyRule.findMany({
        where: {
          enabled: true,
          tenantId: descriptor.tenant_id,
          integrationId: descriptor.integration_id,
          actionGroup: descriptor.matched_path_group_id,
          method: normalizeMethod(descriptor.method),
          host
        },
        select: {
          policyJson: true
        }
      })

      const matched = records
        .map(record => toPolicyRule(record.policyJson))
        .filter(policy =>
          scopeMatchesDescriptor({
            policy,
            descriptor,
            host
          })
        )

      return sortPoliciesDeterministically(matched)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
