import {randomUUID} from 'node:crypto'
import {
  CanonicalRequestDescriptorSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateSchema,
  type OpenApiPolicyRule,
  type OpenApiTemplate
} from '@broker-interceptor/schemas'
import {z} from 'zod'

import {PolicyDecisionSchema, type PolicyDecision} from './contracts'

const ListPolicyRulesForDescriptorScopeInputSchema = z
  .object({
    descriptor: CanonicalRequestDescriptorSchema
  })
  .strict()

const GetIntegrationTemplateForPolicyEvaluationInputSchema = z
  .object({
    tenant_id: z.string().min(1),
    workload_id: z.string().min(1),
    integration_id: z.string().min(1)
  })
  .strict()

const CheckAndConsumePolicyRateLimitInputSchema = z
  .object({
    descriptor: CanonicalRequestDescriptorSchema,
    rule: OpenApiPolicyRuleSchema,
    key: z.string().min(1),
    now: z.date()
  })
  .strict()

const AppendPolicyDecisionAuditEventInputSchema = z
  .object({
    descriptor: CanonicalRequestDescriptorSchema,
    decision: PolicyDecisionSchema,
    correlation_id: z.string().min(1),
    timestamp: z.string().datetime({offset: true})
  })
  .strict()

const PolicyEngineInvalidationEventSchema = z
  .object({
    tenant_id: z.string().min(1),
    entity_type: z.enum(['policy_rule', 'template_binding', 'template_version']),
    entity_id: z.string().min(1),
    updated_at: z.string().datetime({offset: true})
  })
  .strict()

const CheckAndConsumePolicyRateLimitOutputSchema = z
  .object({
    allowed: z.boolean(),
    remaining: z.number().int().gte(0).optional(),
    reset_at: z.string().datetime({offset: true}).optional()
  })
  .strict()

const GetIntegrationTemplateForPolicyEvaluationOutputSchema = z
  .object({
    integration_enabled: z.boolean(),
    template: OpenApiTemplateSchema
  })
  .strict()

const PolicyEngineDbMethodOptionsSchema = z
  .object({
    transaction_client: z.unknown().optional()
  })
  .strict()

export type ListPolicyRulesForDescriptorScopeInput = z.infer<
  typeof ListPolicyRulesForDescriptorScopeInputSchema
>
export type GetIntegrationTemplateForPolicyEvaluationInput = z.infer<
  typeof GetIntegrationTemplateForPolicyEvaluationInputSchema
>
export type CheckAndConsumePolicyRateLimitInput = z.infer<
  typeof CheckAndConsumePolicyRateLimitInputSchema
>
export type AppendPolicyDecisionAuditEventInput = z.infer<
  typeof AppendPolicyDecisionAuditEventInputSchema
>
export type PolicyEngineInvalidationEvent = z.infer<typeof PolicyEngineInvalidationEventSchema>
export type PolicyEngineDbMethodOptions_INCOMPLETE = z.infer<typeof PolicyEngineDbMethodOptionsSchema>
export type CheckAndConsumePolicyRateLimitOutput = z.infer<
  typeof CheckAndConsumePolicyRateLimitOutputSchema
>
export type GetIntegrationTemplateForPolicyEvaluationOutput = z.infer<
  typeof GetIntegrationTemplateForPolicyEvaluationOutputSchema
>

export type PolicyEnginePostgresClient_INCOMPLETE = unknown
export type PolicyEngineRedisClient_INCOMPLETE = unknown
export type PolicyEnginePostgresTransactionClient_INCOMPLETE = unknown

export type PolicyEngineDbClients_INCOMPLETE = {
  postgres?: PolicyEnginePostgresClient_INCOMPLETE
  redis?: PolicyEngineRedisClient_INCOMPLETE
}

export type PolicyEngineDbExecutionContext_INCOMPLETE = {
  clients: PolicyEngineDbClients_INCOMPLETE
  transaction_client?: PolicyEnginePostgresTransactionClient_INCOMPLETE
}

export type PolicyEnginePolicyRuleStoreAdapter_INCOMPLETE = {
  listPolicyRulesForDescriptorScope: (input: {
    descriptor: ListPolicyRulesForDescriptorScopeInput['descriptor']
    context: PolicyEngineDbExecutionContext_INCOMPLETE
  }) => Promise<unknown>
}

export type PolicyEngineTemplateStoreAdapter_INCOMPLETE = {
  getIntegrationTemplateForPolicyEvaluation: (input: {
    tenant_id: string
    workload_id: string
    integration_id: string
    context: PolicyEngineDbExecutionContext_INCOMPLETE
  }) => Promise<unknown>
}

export type PolicyEngineRateLimitStoreAdapter_INCOMPLETE = {
  checkAndConsumePolicyRateLimit: (input: {
    descriptor: CheckAndConsumePolicyRateLimitInput['descriptor']
    rule: CheckAndConsumePolicyRateLimitInput['rule']
    key: string
    now: Date
    context: PolicyEngineDbExecutionContext_INCOMPLETE
  }) => Promise<unknown>
}

export type PolicyEngineAuditStoreAdapter_INCOMPLETE = {
  appendPolicyDecisionAuditEvent: (input: {
    descriptor: AppendPolicyDecisionAuditEventInput['descriptor']
    decision: AppendPolicyDecisionAuditEventInput['decision']
    correlation_id: string
    timestamp: string
    context: PolicyEngineDbExecutionContext_INCOMPLETE
  }) => Promise<void> | void
}

export type PolicyEngineInvalidationBusAdapter_INCOMPLETE = {
  publishPolicyEngineInvalidation: (input: {
    event: PolicyEngineInvalidationEvent
    context: PolicyEngineDbExecutionContext_INCOMPLETE
  }) => Promise<void> | void
  subscribePolicyEngineInvalidation: (input: {
    onEvent: (event: PolicyEngineInvalidationEvent) => void
    context: PolicyEngineDbExecutionContext_INCOMPLETE
  }) => (() => void) | Promise<() => void>
}

export type PolicyEngineDbRepositories_INCOMPLETE = {
  policyRuleStore?: PolicyEnginePolicyRuleStoreAdapter_INCOMPLETE
  templateStore?: PolicyEngineTemplateStoreAdapter_INCOMPLETE
  rateLimitStore?: PolicyEngineRateLimitStoreAdapter_INCOMPLETE
  auditStore?: PolicyEngineAuditStoreAdapter_INCOMPLETE
  invalidationBus?: PolicyEngineInvalidationBusAdapter_INCOMPLETE
}

export type PolicyEngineDbBridgeDependencies_INCOMPLETE = {
  clients?: PolicyEngineDbClients_INCOMPLETE
  repositories?: PolicyEngineDbRepositories_INCOMPLETE
}

export type PolicyEngineDbBridgeScope_INCOMPLETE = {
  listPolicyRulesForDescriptorScope_INCOMPLETE: (
    rawInput: ListPolicyRulesForDescriptorScopeInput,
    rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
  ) => Promise<OpenApiPolicyRule[]>
  getIntegrationTemplateForPolicyEvaluation_INCOMPLETE: (
    rawInput: GetIntegrationTemplateForPolicyEvaluationInput,
    rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
  ) => Promise<GetIntegrationTemplateForPolicyEvaluationOutput>
  checkAndConsumePolicyRateLimit_INCOMPLETE: (
    rawInput: CheckAndConsumePolicyRateLimitInput,
    rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
  ) => Promise<CheckAndConsumePolicyRateLimitOutput>
  appendPolicyDecisionAuditEvent_INCOMPLETE: (
    rawInput: AppendPolicyDecisionAuditEventInput,
    rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
  ) => Promise<void>
  publishPolicyEngineInvalidation_INCOMPLETE: (rawInput: PolicyEngineInvalidationEvent) => Promise<void>
  subscribePolicyEngineInvalidation_INCOMPLETE: (input: {
    onEvent: (event: PolicyEngineInvalidationEvent) => void
  }) => (() => void)
}

export type PolicyEngineDbMethodOptions = PolicyEngineDbMethodOptions_INCOMPLETE
export type PolicyEnginePostgresClient = PolicyEnginePostgresClient_INCOMPLETE
export type PolicyEngineRedisClient = PolicyEngineRedisClient_INCOMPLETE
export type PolicyEnginePostgresTransactionClient = PolicyEnginePostgresTransactionClient_INCOMPLETE
export type PolicyEngineDbClients = PolicyEngineDbClients_INCOMPLETE
export type PolicyEngineDbExecutionContext = PolicyEngineDbExecutionContext_INCOMPLETE
export type PolicyEnginePolicyRuleStoreAdapter = PolicyEnginePolicyRuleStoreAdapter_INCOMPLETE
export type PolicyEngineTemplateStoreAdapter = PolicyEngineTemplateStoreAdapter_INCOMPLETE
export type PolicyEngineRateLimitStoreAdapter = PolicyEngineRateLimitStoreAdapter_INCOMPLETE
export type PolicyEngineAuditStoreAdapter = PolicyEngineAuditStoreAdapter_INCOMPLETE
export type PolicyEngineInvalidationBusAdapter = PolicyEngineInvalidationBusAdapter_INCOMPLETE
export type PolicyEngineDbRepositories = PolicyEngineDbRepositories_INCOMPLETE
export type PolicyEngineDbBridgeDependencies = PolicyEngineDbBridgeDependencies_INCOMPLETE

export type PolicyEngineDbBridgeScope = {
  listPolicyRulesForDescriptorScope: (
    rawInput: ListPolicyRulesForDescriptorScopeInput,
    rawOptions?: PolicyEngineDbMethodOptions
  ) => Promise<OpenApiPolicyRule[]>
  getIntegrationTemplateForPolicyEvaluation: (
    rawInput: GetIntegrationTemplateForPolicyEvaluationInput,
    rawOptions?: PolicyEngineDbMethodOptions
  ) => Promise<GetIntegrationTemplateForPolicyEvaluationOutput>
  checkAndConsumePolicyRateLimit: (
    rawInput: CheckAndConsumePolicyRateLimitInput,
    rawOptions?: PolicyEngineDbMethodOptions
  ) => Promise<CheckAndConsumePolicyRateLimitOutput>
  appendPolicyDecisionAuditEvent: (
    rawInput: AppendPolicyDecisionAuditEventInput,
    rawOptions?: PolicyEngineDbMethodOptions
  ) => Promise<void>
  publishPolicyEngineInvalidation: (rawInput: PolicyEngineInvalidationEvent) => Promise<void>
  subscribePolicyEngineInvalidation: (input: {
    onEvent: (event: PolicyEngineInvalidationEvent) => void
  }) => (() => void)
}

export type PolicyEngineDbPackageWiringInput = {
  clients: PolicyEngineDbClients
  db: {
    policy_rule_repository: {
      listPolicyRulesForDescriptorScope: (input: {
        descriptor: ListPolicyRulesForDescriptorScopeInput['descriptor']
        context?: unknown
        transaction_client?: unknown
      }) => Promise<unknown>
    }
    integration_repository: {
      getIntegrationTemplateForPolicyEvaluation: (input: {
        tenant_id: string
        workload_id: string
        integration_id: string
        context?: unknown
        transaction_client?: unknown
      }) => Promise<unknown>
    }
    audit_event_repository: {
      appendPolicyDecisionAuditEvent: (input: {
        descriptor: AppendPolicyDecisionAuditEventInput['descriptor']
        decision: AppendPolicyDecisionAuditEventInput['decision']
        correlation_id: string
        timestamp: string
        event_id: string
        context?: unknown
        transaction_client?: unknown
      }) => Promise<void> | void
    }
    rate_limit_store: {
      checkAndConsumePolicyRateLimit: (input: {
        descriptor: CheckAndConsumePolicyRateLimitInput['descriptor']
        rule: CheckAndConsumePolicyRateLimitInput['rule']
        key: string
        now: Date
        context: {
          clients: {
            redis?: unknown
          }
        }
      }) => Promise<unknown>
    }
    invalidation_bus: {
      publishPolicyEngineInvalidation: (input: {
        event: PolicyEngineInvalidationEvent
        context: {
          clients: {
            redis?: unknown
          }
        }
      }) => Promise<void> | void
      subscribePolicyEngineInvalidation: (input: {
        onEvent: (event: PolicyEngineInvalidationEvent) => void
        context: {
          clients: {
            redis?: unknown
          }
        }
      }) => (() => void)
    }
  }
}

export type PolicyEngineDbBridgeError = {
  code:
    | 'policy_engine_db_integration_incomplete'
    | 'policy_engine_db_dependency_missing'
    | 'policy_engine_db_client_missing'
    | 'policy_engine_db_subscription_not_supported'
  message: string
}

const toIncompleteError = (methodName: string) =>
  new Error(`policy_engine_db_integration_incomplete:${methodName}`)

const toMissingDependencyError = ({
  methodName,
  dependencyName
}: {
  methodName: string
  dependencyName: string
}) => new Error(`policy_engine_db_dependency_missing:${methodName}:${dependencyName}`)

const toMissingClientError = ({
  methodName,
  clientName
}: {
  methodName: string
  clientName: 'postgres' | 'redis'
}) => new Error(`policy_engine_db_client_missing:${methodName}:${clientName}`)

const parseMethodOptions = (
  rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
): PolicyEngineDbMethodOptions_INCOMPLETE => PolicyEngineDbMethodOptionsSchema.parse(rawOptions ?? {})

const buildExecutionContext = ({
  clients,
  options
}: {
  clients: PolicyEngineDbClients_INCOMPLETE
  options: PolicyEngineDbMethodOptions_INCOMPLETE
}): PolicyEngineDbExecutionContext_INCOMPLETE => ({
  clients,
  ...(options.transaction_client !== undefined ? {transaction_client: options.transaction_client} : {})
})

const ensurePostgresCapability = ({
  context,
  methodName
}: {
  context: PolicyEngineDbExecutionContext_INCOMPLETE
  methodName: string
}) => {
  if (context.transaction_client !== undefined) {
    return
  }

  if (context.clients.postgres === undefined) {
    throw toMissingClientError({methodName, clientName: 'postgres'})
  }
}

const ensureRedisCapability = ({
  context,
  methodName
}: {
  context: PolicyEngineDbExecutionContext_INCOMPLETE
  methodName: string
}) => {
  if (context.clients.redis === undefined) {
    throw toMissingClientError({methodName, clientName: 'redis'})
  }
}

const parsePolicyRulesFromStore = (rawPolicies: unknown): OpenApiPolicyRule[] =>
  z.array(OpenApiPolicyRuleSchema).parse(rawPolicies)

const createDefaultFailClosedBridge_INCOMPLETE = (): PolicyEngineDbBridgeScope_INCOMPLETE => ({
  listPolicyRulesForDescriptorScope_INCOMPLETE: rawInput => {
    const input = ListPolicyRulesForDescriptorScopeInputSchema.parse(rawInput)
    void input

    return Promise.reject(toIncompleteError('listPolicyRulesForDescriptorScope_INCOMPLETE'))
  },
  getIntegrationTemplateForPolicyEvaluation_INCOMPLETE: rawInput => {
    const input = GetIntegrationTemplateForPolicyEvaluationInputSchema.parse(rawInput)
    void input

    return Promise.reject(
      toIncompleteError('getIntegrationTemplateForPolicyEvaluation_INCOMPLETE')
    )
  },
  checkAndConsumePolicyRateLimit_INCOMPLETE: rawInput => {
    const input = CheckAndConsumePolicyRateLimitInputSchema.parse(rawInput)
    void input

    return Promise.reject(toIncompleteError('checkAndConsumePolicyRateLimit_INCOMPLETE'))
  },
  appendPolicyDecisionAuditEvent_INCOMPLETE: rawInput => {
    const input = AppendPolicyDecisionAuditEventInputSchema.parse(rawInput)
    void input

    return Promise.reject(toIncompleteError('appendPolicyDecisionAuditEvent_INCOMPLETE'))
  },
  publishPolicyEngineInvalidation_INCOMPLETE: rawInput => {
    const input = PolicyEngineInvalidationEventSchema.parse(rawInput)
    void input

    return Promise.reject(toIncompleteError('publishPolicyEngineInvalidation_INCOMPLETE'))
  },
  subscribePolicyEngineInvalidation_INCOMPLETE: ({onEvent}) => {
    if (typeof onEvent !== 'function') {
      throw new Error(
        'policy_engine_db_integration_incomplete:subscribePolicyEngineInvalidation_INCOMPLETE_invalid_handler'
      )
    }

    throw toIncompleteError('subscribePolicyEngineInvalidation_INCOMPLETE')
  }
})

export const createPolicyEngineDbBridge_INCOMPLETE = (
  dependencies: PolicyEngineDbBridgeDependencies_INCOMPLETE
): PolicyEngineDbBridgeScope_INCOMPLETE => {
  const clients = dependencies.clients ?? {}
  const repositories = dependencies.repositories ?? {}

  return {
    listPolicyRulesForDescriptorScope_INCOMPLETE: async (rawInput, rawOptions) => {
      const input = ListPolicyRulesForDescriptorScopeInputSchema.parse(rawInput)
      const options = parseMethodOptions(rawOptions)
      const policyRuleStore = repositories.policyRuleStore
      if (!policyRuleStore) {
        throw toMissingDependencyError({
          methodName: 'listPolicyRulesForDescriptorScope_INCOMPLETE',
          dependencyName: 'policyRuleStore'
        })
      }

      const context = buildExecutionContext({clients, options})
      ensurePostgresCapability({
        context,
        methodName: 'listPolicyRulesForDescriptorScope_INCOMPLETE'
      })

      const policiesFromStore = await policyRuleStore.listPolicyRulesForDescriptorScope({
        descriptor: input.descriptor,
        context
      })
      return parsePolicyRulesFromStore(policiesFromStore)
    },
    getIntegrationTemplateForPolicyEvaluation_INCOMPLETE: async (rawInput, rawOptions) => {
      const input = GetIntegrationTemplateForPolicyEvaluationInputSchema.parse(rawInput)
      const options = parseMethodOptions(rawOptions)
      const templateStore = repositories.templateStore
      if (!templateStore) {
        throw toMissingDependencyError({
          methodName: 'getIntegrationTemplateForPolicyEvaluation_INCOMPLETE',
          dependencyName: 'templateStore'
        })
      }

      const context = buildExecutionContext({clients, options})
      ensurePostgresCapability({
        context,
        methodName: 'getIntegrationTemplateForPolicyEvaluation_INCOMPLETE'
      })

      const templateFromStore = await templateStore.getIntegrationTemplateForPolicyEvaluation({
        tenant_id: input.tenant_id,
        workload_id: input.workload_id,
        integration_id: input.integration_id,
        context
      })
      return GetIntegrationTemplateForPolicyEvaluationOutputSchema.parse(templateFromStore)
    },
    checkAndConsumePolicyRateLimit_INCOMPLETE: async (rawInput, rawOptions) => {
      const input = CheckAndConsumePolicyRateLimitInputSchema.parse(rawInput)
      const options = parseMethodOptions(rawOptions)
      const rateLimitStore = repositories.rateLimitStore
      if (!rateLimitStore) {
        throw toMissingDependencyError({
          methodName: 'checkAndConsumePolicyRateLimit_INCOMPLETE',
          dependencyName: 'rateLimitStore'
        })
      }

      const context = buildExecutionContext({clients, options})
      ensureRedisCapability({
        context,
        methodName: 'checkAndConsumePolicyRateLimit_INCOMPLETE'
      })

      const rateLimitResult = await rateLimitStore.checkAndConsumePolicyRateLimit({
        descriptor: input.descriptor,
        rule: input.rule,
        key: input.key,
        now: input.now,
        context
      })
      return CheckAndConsumePolicyRateLimitOutputSchema.parse(rateLimitResult)
    },
    appendPolicyDecisionAuditEvent_INCOMPLETE: async (rawInput, rawOptions) => {
      const input = AppendPolicyDecisionAuditEventInputSchema.parse(rawInput)
      const options = parseMethodOptions(rawOptions)
      const auditStore = repositories.auditStore
      if (!auditStore) {
        throw toMissingDependencyError({
          methodName: 'appendPolicyDecisionAuditEvent_INCOMPLETE',
          dependencyName: 'auditStore'
        })
      }

      const context = buildExecutionContext({clients, options})
      ensurePostgresCapability({
        context,
        methodName: 'appendPolicyDecisionAuditEvent_INCOMPLETE'
      })

      await auditStore.appendPolicyDecisionAuditEvent({
        descriptor: input.descriptor,
        decision: input.decision,
        correlation_id: input.correlation_id,
        timestamp: input.timestamp,
        context
      })
    },
    publishPolicyEngineInvalidation_INCOMPLETE: async rawInput => {
      const input = PolicyEngineInvalidationEventSchema.parse(rawInput)
      const invalidationBus = repositories.invalidationBus
      if (!invalidationBus) {
        throw toMissingDependencyError({
          methodName: 'publishPolicyEngineInvalidation_INCOMPLETE',
          dependencyName: 'invalidationBus'
        })
      }

      const context = buildExecutionContext({
        clients,
        options: {}
      })
      ensureRedisCapability({
        context,
        methodName: 'publishPolicyEngineInvalidation_INCOMPLETE'
      })

      await invalidationBus.publishPolicyEngineInvalidation({
        event: input,
        context
      })
    },
    subscribePolicyEngineInvalidation_INCOMPLETE: ({onEvent}) => {
      if (typeof onEvent !== 'function') {
        throw new Error('policy_engine_db_subscription_not_supported:invalid_handler')
      }

      const invalidationBus = repositories.invalidationBus
      if (!invalidationBus) {
        throw toMissingDependencyError({
          methodName: 'subscribePolicyEngineInvalidation_INCOMPLETE',
          dependencyName: 'invalidationBus'
        })
      }

      const context = buildExecutionContext({
        clients,
        options: {}
      })
      ensureRedisCapability({
        context,
        methodName: 'subscribePolicyEngineInvalidation_INCOMPLETE'
      })

      const unsubscribe = invalidationBus.subscribePolicyEngineInvalidation({
        onEvent: event => onEvent(PolicyEngineInvalidationEventSchema.parse(event)),
        context
      })

      if (typeof unsubscribe === 'function') {
        return unsubscribe
      }

      throw new Error('policy_engine_db_subscription_not_supported:async_unsubscribe_not_supported')
    }
  }
}

export const createPolicyEngineDbBridge = (
  dependencies: PolicyEngineDbBridgeDependencies
): PolicyEngineDbBridgeScope => {
  const legacyBridge = createPolicyEngineDbBridge_INCOMPLETE(dependencies)

  return {
    listPolicyRulesForDescriptorScope: (rawInput, rawOptions) =>
      legacyBridge.listPolicyRulesForDescriptorScope_INCOMPLETE(rawInput, rawOptions),
    getIntegrationTemplateForPolicyEvaluation: (rawInput, rawOptions) =>
      legacyBridge.getIntegrationTemplateForPolicyEvaluation_INCOMPLETE(rawInput, rawOptions),
    checkAndConsumePolicyRateLimit: (rawInput, rawOptions) =>
      legacyBridge.checkAndConsumePolicyRateLimit_INCOMPLETE(rawInput, rawOptions),
    appendPolicyDecisionAuditEvent: (rawInput, rawOptions) =>
      legacyBridge.appendPolicyDecisionAuditEvent_INCOMPLETE(rawInput, rawOptions),
    publishPolicyEngineInvalidation: rawInput =>
      legacyBridge.publishPolicyEngineInvalidation_INCOMPLETE(rawInput),
    subscribePolicyEngineInvalidation: ({onEvent}) =>
      legacyBridge.subscribePolicyEngineInvalidation_INCOMPLETE({
        onEvent
      })
  }
}

export const createPolicyEngineDbBridgeFromDbPackage = ({
  clients,
  db
}: PolicyEngineDbPackageWiringInput): PolicyEngineDbBridgeScope => {
  return createPolicyEngineDbBridge({
    clients,
    repositories: {
      policyRuleStore: {
        listPolicyRulesForDescriptorScope: ({descriptor, context}) =>
          db.policy_rule_repository.listPolicyRulesForDescriptorScope({
            descriptor,
            context,
            transaction_client: context.transaction_client
          })
      },
      templateStore: {
        getIntegrationTemplateForPolicyEvaluation: ({
          tenant_id,
          workload_id,
          integration_id,
          context
        }) =>
          db.integration_repository.getIntegrationTemplateForPolicyEvaluation({
            tenant_id,
            workload_id,
            integration_id,
            context,
            transaction_client: context.transaction_client
          })
      },
      rateLimitStore: {
        checkAndConsumePolicyRateLimit: ({descriptor, rule, key, now, context}) =>
          db.rate_limit_store.checkAndConsumePolicyRateLimit({
            descriptor,
            rule,
            key,
            now,
            context
          })
      },
      auditStore: {
        appendPolicyDecisionAuditEvent: ({descriptor, decision, correlation_id, timestamp, context}) =>
          db.audit_event_repository.appendPolicyDecisionAuditEvent({
            descriptor,
            decision,
            correlation_id,
            timestamp,
            event_id: `evt_${randomUUID()}`,
            context,
            transaction_client: context.transaction_client
          })
      },
      invalidationBus: {
        publishPolicyEngineInvalidation: ({event, context}) =>
          db.invalidation_bus.publishPolicyEngineInvalidation({
            event,
            context
          }),
        subscribePolicyEngineInvalidation: ({onEvent, context}) =>
          db.invalidation_bus.subscribePolicyEngineInvalidation({
            onEvent,
            context
          })
      }
    }
  })
}

const defaultPolicyEngineDbBridge_INCOMPLETE = createDefaultFailClosedBridge_INCOMPLETE()

const defaultPolicyEngineDbBridge = createPolicyEngineDbBridge({})

export const listPolicyRulesForDescriptorScope = (
  rawInput: ListPolicyRulesForDescriptorScopeInput,
  rawOptions?: PolicyEngineDbMethodOptions
): Promise<OpenApiPolicyRule[]> =>
  defaultPolicyEngineDbBridge.listPolicyRulesForDescriptorScope(rawInput, rawOptions)

export const getIntegrationTemplateForPolicyEvaluation = (
  rawInput: GetIntegrationTemplateForPolicyEvaluationInput,
  rawOptions?: PolicyEngineDbMethodOptions
): Promise<GetIntegrationTemplateForPolicyEvaluationOutput> =>
  defaultPolicyEngineDbBridge.getIntegrationTemplateForPolicyEvaluation(rawInput, rawOptions)

export const checkAndConsumePolicyRateLimit = (
  rawInput: CheckAndConsumePolicyRateLimitInput,
  rawOptions?: PolicyEngineDbMethodOptions
): Promise<CheckAndConsumePolicyRateLimitOutput> =>
  defaultPolicyEngineDbBridge.checkAndConsumePolicyRateLimit(rawInput, rawOptions)

export const appendPolicyDecisionAuditEvent = (
  rawInput: AppendPolicyDecisionAuditEventInput,
  rawOptions?: PolicyEngineDbMethodOptions
): Promise<void> =>
  defaultPolicyEngineDbBridge.appendPolicyDecisionAuditEvent(rawInput, rawOptions)

export const publishPolicyEngineInvalidation = (
  rawInput: PolicyEngineInvalidationEvent
): Promise<void> => defaultPolicyEngineDbBridge.publishPolicyEngineInvalidation(rawInput)

export const subscribePolicyEngineInvalidation = ({
  onEvent
}: {
  onEvent: (event: PolicyEngineInvalidationEvent) => void
}): (() => void) =>
  defaultPolicyEngineDbBridge.subscribePolicyEngineInvalidation({
    onEvent
  })

export const listPolicyRulesForDescriptorScope_INCOMPLETE = (
  rawInput: ListPolicyRulesForDescriptorScopeInput,
  rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
): Promise<OpenApiPolicyRule[]> =>
  defaultPolicyEngineDbBridge_INCOMPLETE.listPolicyRulesForDescriptorScope_INCOMPLETE(
    rawInput,
    rawOptions
  )

export const getIntegrationTemplateForPolicyEvaluation_INCOMPLETE = (
  rawInput: GetIntegrationTemplateForPolicyEvaluationInput,
  rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
): Promise<GetIntegrationTemplateForPolicyEvaluationOutput> =>
  defaultPolicyEngineDbBridge_INCOMPLETE.getIntegrationTemplateForPolicyEvaluation_INCOMPLETE(
    rawInput,
    rawOptions
  )

export const checkAndConsumePolicyRateLimit_INCOMPLETE = (
  rawInput: CheckAndConsumePolicyRateLimitInput,
  rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
): Promise<CheckAndConsumePolicyRateLimitOutput> =>
  defaultPolicyEngineDbBridge_INCOMPLETE.checkAndConsumePolicyRateLimit_INCOMPLETE(
    rawInput,
    rawOptions
  )

export const appendPolicyDecisionAuditEvent_INCOMPLETE = (
  rawInput: AppendPolicyDecisionAuditEventInput,
  rawOptions?: PolicyEngineDbMethodOptions_INCOMPLETE
): Promise<void> =>
  defaultPolicyEngineDbBridge_INCOMPLETE.appendPolicyDecisionAuditEvent_INCOMPLETE(
    rawInput,
    rawOptions
  )

export const publishPolicyEngineInvalidation_INCOMPLETE = (
  rawInput: PolicyEngineInvalidationEvent
): Promise<void> =>
  defaultPolicyEngineDbBridge_INCOMPLETE.publishPolicyEngineInvalidation_INCOMPLETE(rawInput)

export const subscribePolicyEngineInvalidation_INCOMPLETE = ({
  onEvent
}: {
  onEvent: (event: PolicyEngineInvalidationEvent) => void
}): (() => void) =>
  defaultPolicyEngineDbBridge_INCOMPLETE.subscribePolicyEngineInvalidation_INCOMPLETE({
    onEvent
  })

export const validateTemplateReadModelFromDb = (rawTemplate: unknown): OpenApiTemplate =>
  OpenApiTemplateSchema.parse(rawTemplate)

export const validatePolicyDecisionForAuditFromDb = (rawDecision: unknown): PolicyDecision =>
  PolicyDecisionSchema.parse(rawDecision)
