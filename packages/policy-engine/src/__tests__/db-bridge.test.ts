import {
  CanonicalRequestDescriptorSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateSchema,
  type CanonicalRequestDescriptor,
  type OpenApiPolicyRule
} from '@broker-interceptor/schemas'
import {describe, expect, it, vi} from 'vitest'

import {
  appendPolicyDecisionAuditEvent_INCOMPLETE,
  checkAndConsumePolicyRateLimit_INCOMPLETE,
  createPolicyEngineDbBridge,
  createPolicyEngineDbBridgeFromDbPackage,
  createPolicyEngineDbBridge_INCOMPLETE,
  getIntegrationTemplateForPolicyEvaluation_INCOMPLETE,
  listPolicyRulesForDescriptorScope,
  listPolicyRulesForDescriptorScope_INCOMPLETE,
  publishPolicyEngineInvalidation_INCOMPLETE,
  subscribePolicyEngineInvalidation,
  subscribePolicyEngineInvalidation_INCOMPLETE,
  validatePolicyDecisionForAuditFromDb,
  validateTemplateReadModelFromDb
} from '../db-bridge'
import {PolicyDecisionSchema} from '../contracts'

const descriptor = CanonicalRequestDescriptorSchema.parse({
  tenant_id: 'tenant-1',
  workload_id: 'workload-1',
  integration_id: 'integration-1',
  template_id: 'tpl_gmail_safe',
  template_version: 1,
  method: 'POST',
  canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
  matched_path_group_id: 'gmail_send',
  normalized_headers: [],
  query_keys: []
})

const policyRule = OpenApiPolicyRuleSchema.parse({
  policy_id: 'pol_1',
  rule_type: 'allow',
  scope: {
    tenant_id: 'tenant-1',
    integration_id: 'integration-1',
    action_group: 'gmail_send',
    method: 'POST',
    host: 'gmail.googleapis.com'
  },
  rate_limit: null
})

const rateLimitPolicyRule = OpenApiPolicyRuleSchema.parse({
  policy_id: 'pol_rl_1',
  rule_type: 'rate_limit',
  scope: {
    tenant_id: 'tenant-1',
    integration_id: 'integration-1',
    action_group: 'gmail_send',
    method: 'POST',
    host: 'gmail.googleapis.com'
  },
  rate_limit: {
    max_requests: 10,
    interval_seconds: 60
  }
})

const template = OpenApiTemplateSchema.parse({
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
      group_id: 'gmail_send',
      risk_tier: 'high',
      approval_mode: 'required',
      methods: ['POST'],
      path_patterns: ['^/gmail/v1/users/[^/]+/messages/send$'],
      query_allowlist: [],
      header_forward_allowlist: ['accept'],
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

const decision = PolicyDecisionSchema.parse({
  decision: 'approval_required',
  reason_code: 'policy_approval_required',
  action_group: 'gmail_send',
  risk_tier: 'high',
  trace: []
})

describe('db bridge placeholders', () => {
  it('fails closed for list policy rules dependency', async () => {
    await expect(
      listPolicyRulesForDescriptorScope_INCOMPLETE({
        descriptor
      })
    ).rejects.toThrow(
      'policy_engine_db_integration_incomplete:listPolicyRulesForDescriptorScope_INCOMPLETE'
    )
  })

  it('fails closed for template lookup dependency', async () => {
    await expect(
      getIntegrationTemplateForPolicyEvaluation_INCOMPLETE({
        tenant_id: 'tenant-1',
        workload_id: 'workload-1',
        integration_id: 'integration-1'
      })
    ).rejects.toThrow(
      'policy_engine_db_integration_incomplete:getIntegrationTemplateForPolicyEvaluation_INCOMPLETE'
    )
  })

  it('fails closed for rate limit dependency', async () => {
    await expect(
      checkAndConsumePolicyRateLimit_INCOMPLETE({
        descriptor,
        rule: policyRule,
        key: 'rate-limit-key',
        now: new Date()
      })
    ).rejects.toThrow(
      'policy_engine_db_integration_incomplete:checkAndConsumePolicyRateLimit_INCOMPLETE'
    )
  })

  it('fails closed for policy decision audit dependency', async () => {
    await expect(
      appendPolicyDecisionAuditEvent_INCOMPLETE({
        descriptor,
        decision,
        correlation_id: 'corr-1',
        timestamp: new Date().toISOString()
      })
    ).rejects.toThrow(
      'policy_engine_db_integration_incomplete:appendPolicyDecisionAuditEvent_INCOMPLETE'
    )
  })

  it('fails closed for invalidation publisher dependency', async () => {
    await expect(
      publishPolicyEngineInvalidation_INCOMPLETE({
        tenant_id: 'tenant-1',
        entity_type: 'policy_rule',
        entity_id: 'pol_1',
        updated_at: new Date().toISOString()
      })
    ).rejects.toThrow(
      'policy_engine_db_integration_incomplete:publishPolicyEngineInvalidation_INCOMPLETE'
    )
  })

  it('fails closed for invalidation subscriber dependency', () => {
    expect(() =>
      subscribePolicyEngineInvalidation_INCOMPLETE({
        onEvent: () => undefined
      })
    ).toThrow('policy_engine_db_integration_incomplete:subscribePolicyEngineInvalidation_INCOMPLETE')
  })

  it('validates template read models from db payloads', () => {
    const parsedTemplate = validateTemplateReadModelFromDb(template)
    expect(parsedTemplate.template_id).toBe('tpl_gmail_safe')
  })

  it('validates policy decisions before audit persistence', () => {
    const parsedDecision = validatePolicyDecisionForAuditFromDb(decision)
    expect(parsedDecision.reason_code).toBe('policy_approval_required')
  })
})

describe('db bridge complete API defaults', () => {
  it('fails closed by default when complete bridge is not configured', async () => {
    await expect(
      listPolicyRulesForDescriptorScope({
        descriptor
      })
    ).rejects.toThrow(
      'policy_engine_db_dependency_missing:listPolicyRulesForDescriptorScope_INCOMPLETE:policyRuleStore'
    )
  })

  it('fails closed for default complete invalidation subscriber without dependencies', () => {
    expect(() =>
      subscribePolicyEngineInvalidation({
        onEvent: () => undefined
      })
    ).toThrow(
      'policy_engine_db_dependency_missing:subscribePolicyEngineInvalidation_INCOMPLETE:invalidationBus'
    )
  })
})

describe('db bridge complete wiring', () => {
  it('exposes complete bridge method names over the dependency-injected implementation', async () => {
    const bridge = createPolicyEngineDbBridge({
      clients: {
        postgres: {connection: 'app-owned-postgres'},
        redis: {connection: 'app-owned-redis'}
      },
      repositories: {
        policyRuleStore: {
          listPolicyRulesForDescriptorScope: () => Promise.resolve([policyRule])
        }
      }
    })

    const policies = await bridge.listPolicyRulesForDescriptorScope({
      descriptor
    })

    expect(policies).toEqual([policyRule])
  })

  it('wires to db package repositories and redis adapters', async () => {
    let auditCreateCount = 0
    let publishedMessage: string | null = null
    type InvalidationListener = (event: {
      tenant_id: string
      entity_type: 'policy_rule' | 'template_binding' | 'template_version'
      entity_id: string
      updated_at: string
    }) => void

    let subscribedHandler: InvalidationListener | undefined

    const dbBindings: Parameters<typeof createPolicyEngineDbBridgeFromDbPackage>[0]['db'] = {
      policy_rule_repository: {
        listPolicyRulesForDescriptorScope: () => Promise.resolve([policyRule])
      },
      integration_repository: {
        getIntegrationTemplateForPolicyEvaluation: () =>
          Promise.resolve({
            integration_enabled: true,
            template
          })
      },
      audit_event_repository: {
        appendPolicyDecisionAuditEvent: () => {
          auditCreateCount += 1
          return Promise.resolve()
        }
      },
      rate_limit_store: {
        checkAndConsumePolicyRateLimit: () =>
          Promise.resolve({
            allowed: true,
            remaining: 9,
            reset_at: '2026-02-12T00:01:00.000Z'
          })
      },
      invalidation_bus: {
        publishPolicyEngineInvalidation: ({event}) => {
          publishedMessage = JSON.stringify(event)
          return Promise.resolve()
        },
        subscribePolicyEngineInvalidation: ({onEvent}) => {
          subscribedHandler = onEvent
          return () => {
            subscribedHandler = undefined
          }
        }
      }
    }

    const clients: Parameters<typeof createPolicyEngineDbBridgeFromDbPackage>[0]['clients'] = {
      postgres: {connection: 'app-owned-postgres'},
      redis: {connection: 'app-owned-redis'}
    }

    const bridge = createPolicyEngineDbBridgeFromDbPackage({
      clients,
      db: dbBindings
    })

    const policies = await bridge.listPolicyRulesForDescriptorScope({
      descriptor
    })
    expect(policies).toEqual([policyRule])

    const templateResult = await bridge.getIntegrationTemplateForPolicyEvaluation({
      tenant_id: 'tenant-1',
      workload_id: 'workload-1',
      integration_id: 'integration-1'
    })
    expect(templateResult.integration_enabled).toBe(true)
    expect(templateResult.template.template_id).toBe('tpl_gmail_safe')

    const rateLimitResult = await bridge.checkAndConsumePolicyRateLimit({
      descriptor,
      rule: rateLimitPolicyRule,
      key: 'tenant-1|workload-1|integration-1|gmail_send',
      now: new Date('2026-02-12T00:00:00.000Z')
    })
    expect(rateLimitResult.allowed).toBe(true)

    await bridge.appendPolicyDecisionAuditEvent({
      descriptor,
      decision,
      correlation_id: 'corr-1',
      timestamp: '2026-02-12T00:00:00.000Z'
    })
    expect(auditCreateCount).toBe(1)

    await bridge.publishPolicyEngineInvalidation({
      tenant_id: 'tenant-1',
      entity_type: 'policy_rule',
      entity_id: 'pol_1',
      updated_at: '2026-02-12T00:00:00.000Z'
    })
    expect(publishedMessage).toBeTruthy()

    const onEvent = vi.fn()
    const unsubscribe = bridge.subscribePolicyEngineInvalidation({
      onEvent
    })
    expect(typeof unsubscribe).toBe('function')

    const listener = subscribedHandler
    if (!listener) {
      throw new Error('redis subscription handler was not captured')
    }

    listener({
      tenant_id: 'tenant-1',
      entity_type: 'policy_rule',
      entity_id: 'pol_1',
      updated_at: '2026-02-12T00:00:00.000Z'
    })

    expect(onEvent).toHaveBeenCalledWith({
      tenant_id: 'tenant-1',
      entity_type: 'policy_rule',
      entity_id: 'pol_1',
      updated_at: '2026-02-12T00:00:00.000Z'
    })
  })
})

describe('db bridge factory dependency injection', () => {
  it('passes app-owned clients and transaction client into postgres-backed rule retrieval', async () => {
    type ListPoliciesInput = {
      descriptor: CanonicalRequestDescriptor
      context: {
        clients: {
          postgres?: unknown
          redis?: unknown
        }
        transaction_client?: unknown
      }
    }

    let capturedInput: ListPoliciesInput | null = null
    const policyRuleStore = {
      listPolicyRulesForDescriptorScope: (input: ListPoliciesInput) => {
        capturedInput = input
        return Promise.resolve([policyRule])
      }
    }

    const bridge = createPolicyEngineDbBridge_INCOMPLETE({
      clients: {
        postgres: {connection: 'app-owned-postgres'},
        redis: {connection: 'app-owned-redis'}
      },
      repositories: {
        policyRuleStore
      }
    })

    const txClient = {transaction: 'tx-client'}

    const policies = await bridge.listPolicyRulesForDescriptorScope_INCOMPLETE(
      {
        descriptor
      },
      {
        transaction_client: txClient
      }
    )

    expect(policies).toEqual([policyRule])
    expect(capturedInput).toEqual({
      descriptor,
      context: {
        clients: {
          postgres: {connection: 'app-owned-postgres'},
          redis: {connection: 'app-owned-redis'}
        },
        transaction_client: txClient
      }
    })
  })

  it('rejects postgres-backed calls when neither process client nor transaction client is provided', async () => {
    const bridge = createPolicyEngineDbBridge_INCOMPLETE({
      repositories: {
        policyRuleStore: {
          listPolicyRulesForDescriptorScope: () => Promise.resolve([policyRule])
        }
      }
    })

    await expect(
      bridge.listPolicyRulesForDescriptorScope_INCOMPLETE({
        descriptor
      })
    ).rejects.toThrow(
      'policy_engine_db_client_missing:listPolicyRulesForDescriptorScope_INCOMPLETE:postgres'
    )
  })

  it('routes rate-limit checks through app-provided store with redis client context', async () => {
    type RateLimitInput = {
      descriptor: CanonicalRequestDescriptor
      rule: OpenApiPolicyRule
      key: string
      now: Date
      context: {
        clients: {
          redis?: unknown
        }
      }
    }

    let capturedInput: RateLimitInput = {
      descriptor,
      rule: policyRule,
      key: '__unset__',
      now: new Date(0),
      context: {
        clients: {}
      }
    }
    const rateLimitStore = {
      checkAndConsumePolicyRateLimit: (input: RateLimitInput) => {
        capturedInput = input
        return Promise.resolve({
          allowed: true,
          remaining: 3,
          reset_at: new Date().toISOString()
        })
      }
    }

    const bridge = createPolicyEngineDbBridge_INCOMPLETE({
      clients: {
        redis: {connection: 'app-owned-redis'}
      },
      repositories: {
        rateLimitStore
      }
    })

    const rateLimitResult = await bridge.checkAndConsumePolicyRateLimit_INCOMPLETE({
      descriptor,
      rule: policyRule,
      key: 'rate-limit-key',
      now: new Date()
    })

    expect(rateLimitResult.allowed).toBe(true)
    expect(capturedInput.descriptor).toEqual(descriptor)
    expect(capturedInput.rule).toEqual(policyRule)
    expect(capturedInput.key).toBe('rate-limit-key')
    expect(capturedInput.now instanceof Date).toBe(true)
    expect(capturedInput.context).toEqual({
      clients: {
        redis: {connection: 'app-owned-redis'}
      }
    })
  })

  it('wires invalidation subscribe/publish through app-provided redis bus', async () => {
    let publishedCount = 0
    let subscribedCount = 0
    let observedEvent: {
      tenant_id: string
      entity_type: 'policy_rule' | 'template_binding' | 'template_version'
      entity_id: string
      updated_at: string
    } = {
      tenant_id: '__unset__',
      entity_type: 'policy_rule',
      entity_id: '__unset__',
      updated_at: new Date(0).toISOString()
    }

    const publishPolicyEngineInvalidation = () => {
      publishedCount += 1
      return Promise.resolve()
    }
    const subscribePolicyEngineInvalidation = ({
      onEvent: emit
    }: {
      onEvent: (event: {
        tenant_id: string
        entity_type: 'policy_rule' | 'template_binding' | 'template_version'
        entity_id: string
        updated_at: string
      }) => void
    }) => {
      subscribedCount += 1
      emit({
        tenant_id: 'tenant-1',
        entity_type: 'policy_rule',
        entity_id: 'pol_1',
        updated_at: new Date().toISOString()
      })
      return () => undefined
    }

    const bridge = createPolicyEngineDbBridge_INCOMPLETE({
      clients: {
        redis: {connection: 'app-owned-redis'}
      },
      repositories: {
        invalidationBus: {
          publishPolicyEngineInvalidation,
          subscribePolicyEngineInvalidation
        }
      }
    })

    await bridge.publishPolicyEngineInvalidation_INCOMPLETE({
      tenant_id: 'tenant-1',
      entity_type: 'policy_rule',
      entity_id: 'pol_1',
      updated_at: new Date().toISOString()
    })

    const unsubscribe = bridge.subscribePolicyEngineInvalidation_INCOMPLETE({
      onEvent: event => {
        observedEvent = event
      }
    })

    expect(typeof unsubscribe).toBe('function')
    expect(observedEvent.tenant_id).toBe('tenant-1')
    expect(observedEvent.entity_type).toBe('policy_rule')
    expect(observedEvent.entity_id).toBe('pol_1')
    expect(typeof observedEvent.updated_at).toBe('string')
    expect(subscribedCount).toBe(1)
    expect(publishedCount).toBe(1)
  })

  it('rejects invalidation subscriptions when dependency returns async unsubscribe', () => {
    const bridge = createPolicyEngineDbBridge_INCOMPLETE({
      clients: {
        redis: {connection: 'app-owned-redis'}
      },
      repositories: {
        invalidationBus: {
          publishPolicyEngineInvalidation: () => Promise.resolve(),
          subscribePolicyEngineInvalidation: () => Promise.resolve(() => undefined)
        }
      }
    })

    expect(() =>
      bridge.subscribePolicyEngineInvalidation_INCOMPLETE({
        onEvent: () => undefined
      })
    ).toThrow('policy_engine_db_subscription_not_supported:async_unsubscribe_not_supported')
  })
})
