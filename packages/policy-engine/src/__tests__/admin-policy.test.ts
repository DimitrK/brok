import {
  OpenApiCanonicalRequestDescriptorSchema,
  OpenApiPolicyRuleSchema,
  type OpenApiCanonicalRequestDescriptor,
  type OpenApiPolicyRule
} from '@broker-interceptor/schemas'
import {describe, expect, it} from 'vitest'

import {derivePolicyFromApprovalDecision, validatePolicyRule} from '../admin-policy'

const basePolicy = OpenApiPolicyRuleSchema.parse({
  policy_id: 'pol_base',
  rule_type: 'allow',
  scope: {
    tenant_id: 'tenant-1',
    workload_id: 'workload-1',
    integration_id: 'integration-1',
    template_id: 'tpl_gmail_safe',
    template_version: 1,
    action_group: 'gmail_send',
    method: 'POST',
    host: 'gmail.googleapis.com',
    query_keys: ['q', 'pageToken']
  },
  rate_limit: null
})

const createPolicy = (overrides: Partial<OpenApiPolicyRule> = {}): OpenApiPolicyRule =>
  OpenApiPolicyRuleSchema.parse({
    ...basePolicy,
    ...overrides
  })

const baseDescriptor = OpenApiCanonicalRequestDescriptorSchema.parse({
  tenant_id: 'tenant-1',
  workload_id: 'workload-1',
  integration_id: 'integration-1',
  template_id: 'tpl_gmail_safe',
  template_version: 1,
  method: 'POST',
  canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
  matched_path_group_id: 'gmail_send',
  normalized_headers: [],
  query_keys: ['q', 'pageToken']
})

const createDescriptor = (
  overrides: Partial<OpenApiCanonicalRequestDescriptor> = {}
): OpenApiCanonicalRequestDescriptor =>
  OpenApiCanonicalRequestDescriptorSchema.parse({
    ...baseDescriptor,
    ...overrides
  })

describe('validatePolicyRule', () => {
  it('normalizes method, host, query_keys, and non-rate-limit payloads', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        rule_type: 'allow',
        scope: {
          ...basePolicy.scope,
          method: ' post ',
          host: 'GMAIL.GOOGLEAPIS.COM',
          query_keys: ['z', ' a ', 'm']
        },
        rate_limit: undefined
      })
    })

    expect(result.ok).toBe(true)
    if (!result.ok) {
      return
    }

    expect(result.value.scope.method).toBe('POST')
    expect(result.value.scope.host).toBe('gmail.googleapis.com')
    expect(result.value.scope.query_keys).toEqual(['a', 'm', 'z'])
    expect(result.value.rate_limit).toBeNull()
  })

  it('rejects invalid policy method', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        scope: {
          ...basePolicy.scope,
          method: 'TRACE'
        }
      })
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'policy_method_invalid',
        message: 'Policy method "TRACE" is invalid'
      }
    })
  })

  it('rejects invalid policy host formats', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        scope: {
          ...basePolicy.scope,
          host: 'https://gmail.googleapis.com'
        }
      })
    })

    expect(result.ok).toBe(false)
    if (result.ok) {
      return
    }

    expect(result.error.code).toBe('policy_host_invalid')
  })

  it('rejects wildcard policy host scopes', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        scope: {
          ...basePolicy.scope,
          host: '*.googleapis.com'
        }
      })
    })

    expect(result.ok).toBe(false)
    if (result.ok) {
      return
    }

    expect(result.error.code).toBe('policy_host_invalid')
  })

  it('rejects duplicate query_keys after normalization', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        scope: {
          ...basePolicy.scope,
          query_keys: ['q', ' q ']
        }
      })
    })

    expect(result.ok).toBe(false)
    if (result.ok) {
      return
    }

    expect(result.error.code).toBe('policy_query_keys_invalid')
  })

  it('rejects empty required scope fields', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        scope: {
          ...basePolicy.scope,
          tenant_id: '   '
        }
      })
    })

    expect(result.ok).toBe(false)
    if (result.ok) {
      return
    }

    expect(result.error.code).toBe('policy_scope_invalid')
  })

  it('rejects missing rate_limit payload for rate_limit rules', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        rule_type: 'rate_limit',
        rate_limit: null
      })
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'policy_rate_limit_invalid',
        message: 'rate_limit rules must include a non-null rate_limit payload'
      }
    })
  })

  it('rejects non-rate-limit rules carrying rate_limit payload', () => {
    const result = validatePolicyRule({
      policy: createPolicy({
        rule_type: 'allow',
        rate_limit: {
          max_requests: 10,
          interval_seconds: 60
        }
      })
    })

    expect(result.ok).toBe(false)
    if (result.ok) {
      return
    }

    expect(result.error.code).toBe('policy_rate_limit_invalid')
  })

  it('rejects invalid top-level policy shape', () => {
    const result = validatePolicyRule({
      policy: {} as OpenApiPolicyRule
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'policy_rule_invalid',
        message: 'Policy payload failed schema validation'
      }
    })
  })

  it('rejects policy constraints outside bounded schema', () => {
    const result = validatePolicyRule({
      policy: {
        ...basePolicy,
        constraints: {
          unexpected: true
        }
      } as unknown as OpenApiPolicyRule
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'policy_rule_invalid',
        message: 'Policy payload failed schema validation'
      }
    })
  })

  it('rejects duplicate bounded constraint values for deterministic behavior', () => {
    const result = validatePolicyRule({
      policy: {
        ...basePolicy,
        constraints: {
          allowed_query_keys: ['status', 'status']
        }
      } as unknown as OpenApiPolicyRule
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'policy_rule_invalid',
        message: 'Duplicate query key "status" is not allowed'
      }
    })
  })
})

describe('derivePolicyFromApprovalDecision', () => {
  it('derives allow rule for approved rule-mode decisions', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'approved',
      approval_mode: 'rule',
      descriptor: createDescriptor({
        canonical_url: 'https://GMAIL.GOOGLEAPIS.COM/gmail/v1/users/me/messages/send',
        query_keys: ['z', 'q']
      }),
      constraints: {
        require_mfa_approval: true,
        allowed_query_keys: ['z', 'a'],
        recipient_domain_allowlist: ['Example.COM', 'api.example.com']
      },
      policy_id: 'pol_from_approval'
    })

    expect(result.ok).toBe(true)
    if (!result.ok) {
      return
    }

    expect(result.value).not.toBeNull()
    expect(result.value?.rule_type).toBe('allow')
    expect(result.value?.scope).toEqual({
      tenant_id: 'tenant-1',
      workload_id: 'workload-1',
      integration_id: 'integration-1',
      template_id: 'tpl_gmail_safe',
      template_version: 1,
      action_group: 'gmail_send',
      method: 'POST',
      host: 'gmail.googleapis.com',
      query_keys: ['q', 'z']
    })
    expect(result.value?.rate_limit).toBeNull()
    expect(result.value?.constraints).toEqual({
      require_mfa_approval: true,
      allowed_query_keys: ['a', 'z'],
      recipient_domain_allowlist: ['api.example.com', 'example.com']
    })
  })

  it('returns null for approved once-mode decisions', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'approved',
      approval_mode: 'once',
      descriptor: createDescriptor(),
      policy_id: 'pol_unused'
    })

    expect(result).toEqual({
      ok: true,
      value: null
    })
  })

  it('always derives deny rule for denied decisions', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'denied',
      approval_mode: 'once',
      descriptor: createDescriptor(),
      policy_id: 'pol_deny_from_approval'
    })

    expect(result.ok).toBe(true)
    if (!result.ok || !result.value) {
      return
    }

    expect(result.value.rule_type).toBe('deny')
    expect(result.value.scope.method).toBe('POST')
    expect(result.value.scope.host).toBe('gmail.googleapis.com')
  })

  it('rejects invalid approval decision payload', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'approved',
      approval_mode: 'rule',
      descriptor: createDescriptor(),
      policy_id: '   '
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'approval_decision_invalid',
        message: 'policy_id must be a non-empty string'
      }
    })
  })

  it('rejects approval constraints outside bounded schema', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'approved',
      approval_mode: 'rule',
      descriptor: createDescriptor(),
      policy_id: 'pol_invalid_constraints',
      constraints: {
        ad_hoc_rule: true
      } as unknown as Record<string, unknown>
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'approval_decision_invalid',
        message: 'Approval decision payload failed schema validation'
      }
    })
  })

  it('rejects duplicate approval constraints at boundary normalization', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'approved',
      approval_mode: 'rule',
      descriptor: createDescriptor(),
      policy_id: 'pol_invalid_constraints_dupes',
      constraints: {
        allowed_query_keys: ['status', 'status']
      } as unknown as Record<string, unknown>
    })

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'approval_decision_invalid',
        message: 'Duplicate query key "status" is not allowed'
      }
    })
  })

  it('rejects invalid descriptor query_keys for deterministic derivation', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'approved',
      approval_mode: 'rule',
      descriptor: createDescriptor({
        query_keys: ['q', ' q ']
      }),
      policy_id: 'pol_invalid_descriptor'
    })

    expect(result.ok).toBe(false)
    if (result.ok) {
      return
    }

    expect(result.error.code).toBe('descriptor_invalid')
  })

  it('rejects descriptor canonical_url with fragment', () => {
    const result = derivePolicyFromApprovalDecision({
      approval_status: 'approved',
      approval_mode: 'rule',
      descriptor: createDescriptor({
        canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send#fragment'
      }),
      policy_id: 'pol_invalid_descriptor'
    })

    expect(result.ok).toBe(false)
    if (result.ok) {
      return
    }

    expect(result.error.code).toBe('descriptor_invalid')
  })
})
