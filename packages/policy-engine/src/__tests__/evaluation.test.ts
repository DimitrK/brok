import {
  CanonicalRequestDescriptorSchema,
  PolicyRuleSchema,
  TemplateSchema,
  type PolicyRule
} from '@broker-interceptor/schemas'
import {describe, expect, it, vi} from 'vitest'

import {evaluatePolicyDecision, type RateLimitCheckInput} from '../evaluation'

const template = TemplateSchema.parse({
  template_id: 'tpl_gmail_safe',
  version: 1,
  provider: 'google_gmail',
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: ['gmail.googleapis.com'],
  redirect_policy: {
    mode: 'deny'
  },
  path_groups: [
    {
      group_id: 'gmail_read',
      risk_tier: 'low',
      approval_mode: 'none',
      methods: ['GET'],
      path_patterns: ['^/gmail/v1/users/[^/]+/messages$', '^/gmail/v1/users/[^/]+/messages/[^/]+$'],
      query_allowlist: ['q', 'pageToken'],
      header_forward_allowlist: ['accept'],
      body_policy: {
        max_bytes: 0,
        content_types: []
      }
    },
    {
      group_id: 'gmail_send',
      risk_tier: 'high',
      approval_mode: 'required',
      methods: ['POST'],
      path_patterns: ['^/gmail/v1/users/[^/]+/messages/send$'],
      query_allowlist: [],
      header_forward_allowlist: ['accept', 'content-type'],
      body_policy: {
        max_bytes: 1048576,
        content_types: ['application/json']
      }
    }
  ],
  network_safety: {
    deny_private_ip_ranges: true,
    deny_link_local: true,
    deny_loopback: true,
    deny_metadata_ranges: true,
    dns_resolution_required: true
  }
})

const baseDescriptor = CanonicalRequestDescriptorSchema.parse({
  tenant_id: 'tenant-1',
  workload_id: 'workload-1',
  integration_id: 'integration-1',
  template_id: template.template_id,
  template_version: template.version,
  method: 'POST',
  canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
  matched_path_group_id: 'gmail_send',
  normalized_headers: [
    {
      name: 'accept',
      value: 'application/json'
    }
  ],
  query_keys: []
})

const createDescriptor = (
  overrides: Partial<typeof baseDescriptor> = {}
): typeof baseDescriptor => CanonicalRequestDescriptorSchema.parse({...baseDescriptor, ...overrides})

const createRule = (rule: PolicyRule): PolicyRule => PolicyRuleSchema.parse(rule)

describe('evaluatePolicyDecision', () => {
  it('applies deny exact before allow exact', async () => {
    const allowExact = createRule({
      policy_id: 'pol_allow_exact',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        workload_id: 'workload-1',
        integration_id: 'integration-1',
        template_id: template.template_id,
        template_version: template.version,
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com',
        query_keys: []
      }
    })
    const denyExact = createRule({
      policy_id: 'pol_deny_exact',
      rule_type: 'deny',
      scope: {
        tenant_id: 'tenant-1',
        workload_id: 'workload-1',
        integration_id: 'integration-1',
        template_id: template.template_id,
        template_version: template.version,
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com',
        query_keys: []
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowExact, denyExact]
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('policy_deny')
    expect(decision.policy_match).toEqual({
      policy_id: 'pol_deny_exact',
      rule_type: 'deny',
      match_type: 'exact'
    })
  })

  it('denies when descriptor template scope does not match evaluation template', async () => {
    const mismatchedTemplateDescriptor = createDescriptor({
      template_id: 'tpl_mismatch',
      template_version: 2
    })

    const decision = await evaluatePolicyDecision({
      descriptor: mismatchedTemplateDescriptor,
      template,
      policies: []
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('template_scope_mismatch')
  })

  it('applies deny scoped before allow exact', async () => {
    const allowExact = createRule({
      policy_id: 'pol_allow_exact',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        workload_id: 'workload-1',
        integration_id: 'integration-1',
        template_id: template.template_id,
        template_version: template.version,
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com',
        query_keys: []
      }
    })
    const denyScoped = createRule({
      policy_id: 'pol_deny_scoped',
      rule_type: 'deny',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowExact, denyScoped]
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('policy_deny')
    expect(decision.policy_match).toEqual({
      policy_id: 'pol_deny_scoped',
      rule_type: 'deny',
      match_type: 'scoped'
    })
  })

  it('prefers allow exact over allow scoped', async () => {
    const allowScoped = createRule({
      policy_id: 'pol_allow_scoped',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const allowExact = createRule({
      policy_id: 'pol_allow_exact',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        workload_id: 'workload-1',
        integration_id: 'integration-1',
        template_id: template.template_id,
        template_version: template.version,
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com',
        query_keys: []
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowScoped, allowExact]
    })

    expect(decision.decision).toBe('allowed')
    expect(decision.reason_code).toBe('policy_allow')
    expect(decision.policy_match).toEqual({
      policy_id: 'pol_allow_exact',
      rule_type: 'allow',
      match_type: 'exact'
    })
  })

  it('selects deterministic allow rule by policy_id when specificity ties', async () => {
    const allowRuleZ = createRule({
      policy_id: 'z-rule',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const allowRuleA = createRule({
      policy_id: 'a-rule',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowRuleZ, allowRuleA]
    })

    expect(decision.decision).toBe('allowed')
    expect(decision.policy_match?.policy_id).toBe('a-rule')
  })

  it('uses insertion order when policy_id tie-breakers are equal', async () => {
    const firstAllowRuleWithoutId = createRule({
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const secondAllowRuleWithoutId = createRule({
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [firstAllowRuleWithoutId, secondAllowRuleWithoutId]
    })

    expect(decision.decision).toBe('allowed')
    expect(decision.policy_match?.policy_id).toBeNull()
    expect(decision.trace.some(entry => entry.detail.includes('Allow rule selected'))).toBe(true)
  })

  it('returns approval_required when approval rule matches and no allow rule exists', async () => {
    const approvalRule = createRule({
      policy_id: 'pol_approval_required',
      rule_type: 'approval_required',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [approvalRule]
    })

    expect(decision.decision).toBe('approval_required')
    expect(decision.reason_code).toBe('policy_approval_required')
  })

  it('ignores non-matching scoped policies and applies template approval requirement', async () => {
    const policyWithWrongTenant = createRule({
      policy_id: 'wrong-tenant',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-2',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [policyWithWrongTenant]
    })

    expect(decision.decision).toBe('approval_required')
    expect(decision.reason_code).toBe('template_approval_required')
  })

  it('evaluates all scope guards before matching a rule', async () => {
    const baseScope = {
      tenant_id: 'tenant-1',
      integration_id: 'integration-1',
      action_group: 'gmail_send',
      method: 'POST',
      host: 'gmail.googleapis.com'
    } as const

    const mismatchPolicies: PolicyRule[] = [
      createRule({
        policy_id: 'mismatch-tenant',
        rule_type: 'allow',
        scope: {...baseScope, tenant_id: 'tenant-x'}
      }),
      createRule({
        policy_id: 'mismatch-integration',
        rule_type: 'allow',
        scope: {...baseScope, integration_id: 'integration-x'}
      }),
      createRule({
        policy_id: 'mismatch-group',
        rule_type: 'allow',
        scope: {...baseScope, action_group: 'gmail_read'}
      }),
      createRule({
        policy_id: 'mismatch-method',
        rule_type: 'allow',
        scope: {...baseScope, method: 'GET'}
      }),
      createRule({
        policy_id: 'mismatch-host',
        rule_type: 'allow',
        scope: {...baseScope, host: 'api.openai.com'}
      }),
      createRule({
        policy_id: 'mismatch-workload',
        rule_type: 'allow',
        scope: {...baseScope, workload_id: 'workload-x'}
      }),
      createRule({
        policy_id: 'mismatch-template-id',
        rule_type: 'allow',
        scope: {...baseScope, template_id: 'tpl_other'}
      }),
      createRule({
        policy_id: 'mismatch-template-version',
        rule_type: 'allow',
        scope: {...baseScope, template_version: 99}
      }),
      createRule({
        policy_id: 'mismatch-query',
        rule_type: 'allow',
        scope: {...baseScope, query_keys: ['q']}
      })
    ]
    const matchingAllowRule = createRule({
      policy_id: 'allow-final',
      rule_type: 'allow',
      scope: baseScope
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [...mismatchPolicies, matchingAllowRule]
    })

    expect(decision.decision).toBe('allowed')
    expect(decision.policy_match?.policy_id).toBe('allow-final')
  })

  it('returns template_approval_required when group requires approval and no rule allows', async () => {
    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: []
    })

    expect(decision.decision).toBe('approval_required')
    expect(decision.reason_code).toBe('template_approval_required')
  })

  it('returns invalid_path_pattern when template contains an invalid path pattern', async () => {
    const invalidTemplate = TemplateSchema.parse({
      ...template,
      path_groups: [
        {
          ...template.path_groups[0],
          path_patterns: ['^/gmail/v1/users/(messages$']
        },
        template.path_groups[1]
      ]
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template: invalidTemplate,
      policies: []
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('invalid_path_pattern')
  })

  it('falls back to unclassified action group when descriptor action group is empty', async () => {
    const descriptorWithEmptyGroup = createDescriptor({
      matched_path_group_id: '',
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/threads'
    })

    const decision = await evaluatePolicyDecision({
      descriptor: descriptorWithEmptyGroup,
      template,
      policies: []
    })

    expect(decision.decision).toBe('denied')
    expect(decision.action_group).toBe('unclassified')
  })

  it('returns default deny when no policy allows and template does not require approval', async () => {
    const readDescriptor = createDescriptor({
      method: 'GET',
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages',
      matched_path_group_id: 'gmail_read'
    })

    const decision = await evaluatePolicyDecision({
      descriptor: readDescriptor,
      template,
      policies: []
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('policy_default_deny')
  })

  it('returns no_matching_group when classification fails', async () => {
    const descriptor = createDescriptor({
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/threads/send'
    })

    const decision = await evaluatePolicyDecision({
      descriptor,
      template,
      policies: []
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('no_matching_group')
  })

  it('returns descriptor_group_mismatch when descriptor and classifier disagree', async () => {
    const mismatchedDescriptor = createDescriptor({
      matched_path_group_id: 'gmail_read'
    })
    const allowRule = createRule({
      policy_id: 'pol_allow_send',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: mismatchedDescriptor,
      template,
      policies: [allowRule]
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('descriptor_group_mismatch')
  })

  it('returns throttled when rate limit rule rejects request', async () => {
    const allowRule = createRule({
      policy_id: 'pol_allow_send',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const rateLimitRule = createRule({
      policy_id: 'pol_rate_send',
      rule_type: 'rate_limit',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      },
      rate_limit: {
        max_requests: 5,
        interval_seconds: 60
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowRule, rateLimitRule],
      rateLimiter: () => ({allowed: false})
    })

    expect(decision.decision).toBe('throttled')
    expect(decision.reason_code).toBe('policy_rate_limited')
    expect(decision.rate_limit?.policy_id).toBe('pol_rate_send')
  })

  it('builds default rate-limit keys with workload scope even for scoped rules', async () => {
    const allowRule = createRule({
      policy_id: 'pol_allow_send',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const rateLimitRule = createRule({
      policy_id: 'pol_rate_send',
      rule_type: 'rate_limit',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      },
      rate_limit: {
        max_requests: 5,
        interval_seconds: 60
      }
    })

    const observedKeys: string[] = []
    const rateLimiter = vi.fn((input: RateLimitCheckInput) => {
      observedKeys.push(input.key)
      return {allowed: true}
    })

    await evaluatePolicyDecision({
      descriptor: createDescriptor({workload_id: 'workload-a'}),
      template,
      policies: [allowRule, rateLimitRule],
      rateLimiter
    })
    await evaluatePolicyDecision({
      descriptor: createDescriptor({workload_id: 'workload-b'}),
      template,
      policies: [allowRule, rateLimitRule],
      rateLimiter
    })

    expect(observedKeys).toHaveLength(2)
    expect(observedKeys[0]).not.toEqual(observedKeys[1])
    expect(observedKeys[0]).toContain('workload:workload-a')
    expect(observedKeys[1]).toContain('workload:workload-b')
  })

  it('fails closed when rate limit checker is missing', async () => {
    const allowRule = createRule({
      policy_id: 'pol_allow_send',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const rateLimitRule = createRule({
      policy_id: 'pol_rate_send',
      rule_type: 'rate_limit',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      },
      rate_limit: {
        max_requests: 5,
        interval_seconds: 60
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowRule, rateLimitRule]
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('rate_limit_checker_missing')
  })

  it('fails closed when rate limiter throws', async () => {
    const allowRule = createRule({
      policy_id: 'pol_allow_send',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const rateLimitRule = createRule({
      policy_id: 'pol_rate_send',
      rule_type: 'rate_limit',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      },
      rate_limit: {
        max_requests: 5,
        interval_seconds: 60
      }
    })
    const throwingLimiter = vi.fn(() => {
      throw new Error('store unavailable')
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowRule, rateLimitRule],
      rateLimiter: throwingLimiter
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('rate_limit_check_failed')
  })

  it('fails closed for malformed rate_limit rule payload', async () => {
    const allowRule = createRule({
      policy_id: 'pol_allow_send',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      }
    })
    const malformedRateLimitRule = PolicyRuleSchema.parse({
      policy_id: 'pol_rate_send',
      rule_type: 'rate_limit',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-1',
        action_group: 'gmail_send',
        method: 'POST',
        host: 'gmail.googleapis.com'
      },
      rate_limit: null
    })

    const decision = await evaluatePolicyDecision({
      descriptor: createDescriptor(),
      template,
      policies: [allowRule, malformedRateLimitRule],
      rateLimiter: () => ({allowed: true})
    })

    expect(decision.decision).toBe('denied')
    expect(decision.reason_code).toBe('invalid_rate_limit_rule')
  })

  it('allows S3 bucket-root list requests when a matching allow rule exists', async () => {
    const s3Template = TemplateSchema.parse({
      template_id: 'tpl_backup_s3',
      version: 1,
      provider: 'aws_s3',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['backup-bucket.s3.eu-west-1.amazonaws.com'],
      redirect_policy: {
        mode: 'deny'
      },
      path_groups: [
        {
          group_id: 'bucket-objects',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['GET', 'PUT'],
          path_patterns: ['/', '/backups/**'],
          query_allowlist: ['list-type', 'prefix', 'continuation-token'],
          header_forward_allowlist: ['content-type', 'range'],
          body_policy: {
            max_bytes: 1048576,
            content_types: ['application/octet-stream', 'application/json']
          }
        }
      ],
      network_safety: {
        deny_private_ip_ranges: true,
        deny_link_local: true,
        deny_loopback: true,
        deny_metadata_ranges: true,
        dns_resolution_required: true
      }
    })
    const descriptor = CanonicalRequestDescriptorSchema.parse({
      tenant_id: 'tenant-1',
      workload_id: 'workload-1',
      integration_id: 'integration-s3',
      template_id: s3Template.template_id,
      template_version: s3Template.version,
      method: 'GET',
      canonical_url:
        'https://backup-bucket.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=backups%2Fbroker%2F',
      matched_path_group_id: 'bucket-objects',
      normalized_headers: [],
      query_keys: ['list-type', 'prefix']
    })
    const allowRule = createRule({
      policy_id: 's3-list-allow',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        workload_id: 'workload-1',
        integration_id: 'integration-s3',
        template_id: s3Template.template_id,
        template_version: s3Template.version,
        action_group: 'bucket-objects',
        method: 'GET',
        host: 'backup-bucket.s3.eu-west-1.amazonaws.com',
        query_keys: ['prefix', 'list-type']
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor,
      template: s3Template,
      policies: [allowRule]
    })

    expect(decision.decision).toBe('allowed')
    expect(decision.reason_code).toBe('policy_allow')
    expect(decision.action_group).toBe('bucket-objects')
  })

  it('allows S3 object operations when a matching allow rule exists', async () => {
    const s3Template = TemplateSchema.parse({
      template_id: 'tpl_backup_s3',
      version: 1,
      provider: 'aws_s3',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['backup-bucket.s3.eu-west-1.amazonaws.com'],
      redirect_policy: {
        mode: 'deny'
      },
      path_groups: [
        {
          group_id: 'bucket-objects',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['GET', 'PUT'],
          path_patterns: ['/', '/backups/**'],
          query_allowlist: ['list-type', 'prefix', 'continuation-token'],
          header_forward_allowlist: ['content-type', 'range'],
          body_policy: {
            max_bytes: 1048576,
            content_types: ['application/octet-stream', 'application/json']
          }
        }
      ],
      network_safety: {
        deny_private_ip_ranges: true,
        deny_link_local: true,
        deny_loopback: true,
        deny_metadata_ranges: true,
        dns_resolution_required: true
      }
    })
    const descriptor = CanonicalRequestDescriptorSchema.parse({
      tenant_id: 'tenant-1',
      workload_id: 'workload-1',
      integration_id: 'integration-s3',
      template_id: s3Template.template_id,
      template_version: s3Template.version,
      method: 'PUT',
      canonical_url:
        'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/broker/v000001-20260228T120000Z/chunks/chunk-000001.bin',
      matched_path_group_id: 'bucket-objects',
      normalized_headers: [],
      query_keys: []
    })
    const allowRule = createRule({
      policy_id: 's3-object-allow',
      rule_type: 'allow',
      scope: {
        tenant_id: 'tenant-1',
        integration_id: 'integration-s3',
        action_group: 'bucket-objects',
        method: 'PUT',
        host: 'backup-bucket.s3.eu-west-1.amazonaws.com'
      }
    })

    const decision = await evaluatePolicyDecision({
      descriptor,
      template: s3Template,
      policies: [allowRule]
    })

    expect(decision.decision).toBe('allowed')
    expect(decision.reason_code).toBe('policy_allow')
    expect(decision.action_group).toBe('bucket-objects')
  })
})
