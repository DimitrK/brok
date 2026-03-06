import {
  OpenApiAuditEventSchema,
  OpenApiIntegrationSchema,
  OpenApiIntegrationSecretMaterialWriteSchema,
  OpenApiIntegrationUpdateRequestSchema,
  OpenApiIntegrationWriteSchema,
  type OpenApiAuditEvent,
  type OpenApiIntegration,
  type OpenApiIntegrationSecretMaterialWrite,
  type OpenApiIntegrationUpdateRequest,
  type OpenApiIntegrationWrite
} from '@broker-interceptor/schemas'
import {z} from 'zod'

import {type AuditAppendEventResult} from './contracts'
import {err, type AuditResult} from './errors'

export const IntegrationLifecycleAuditActionSchema = z.enum([
  'admin.integration.created',
  'admin.integration.updated',
  'admin.integration.deleted'
])
export type IntegrationLifecycleAuditAction = z.infer<typeof IntegrationLifecycleAuditActionSchema>

const IntegrationAuditEventBaseSchema = z
  .object({
    event_id: z.string().min(1),
    timestamp: z.string().datetime({offset: true}),
    tenant_id: z.string().min(1),
    integration_id: z.string().min(1),
    correlation_id: z.string().min(1),
    message: z.string().nullable().optional(),
    actor_subject: z.string().min(1).optional(),
    actor_email: z.string().email().optional(),
    actor_roles: z.array(z.string().min(1)).optional(),
    metadata: z.record(z.string(), z.unknown()).optional()
  })
  .strict()

export const IntegrationCreatedAuditInputSchema = IntegrationAuditEventBaseSchema.extend({
  integration_write: OpenApiIntegrationWriteSchema
}).strict()
export type IntegrationCreatedAuditInput = z.infer<typeof IntegrationCreatedAuditInputSchema>

export const IntegrationUpdatedAuditInputSchema = IntegrationAuditEventBaseSchema.extend({
  integration: OpenApiIntegrationSchema,
  update: OpenApiIntegrationUpdateRequestSchema,
  secret_material: OpenApiIntegrationSecretMaterialWriteSchema.optional()
}).strict()
export type IntegrationUpdatedAuditInput = z.infer<typeof IntegrationUpdatedAuditInputSchema>

export const IntegrationDeletedAuditInputSchema = IntegrationAuditEventBaseSchema.extend({
  integration: OpenApiIntegrationSchema,
  secret_material: OpenApiIntegrationSecretMaterialWriteSchema.optional()
}).strict()
export type IntegrationDeletedAuditInput = z.infer<typeof IntegrationDeletedAuditInputSchema>

type AuditAppender<TDataAccessContext = unknown> = {
  appendAuditEvent: (input: {
    event: unknown
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
}

type IntegrationActorMetadata = {
  actor_subject: string | null
  actor_email: string | null
  actor_roles: string[] | null
}

const buildActorMetadata = (
  input: z.infer<typeof IntegrationAuditEventBaseSchema>
): IntegrationActorMetadata => ({
  actor_subject: input.actor_subject ?? null,
  actor_email: input.actor_email ?? null,
  actor_roles: input.actor_roles ?? null
})

const summarizeSecretMaterial = (
  secretMaterial: OpenApiIntegrationSecretMaterialWrite
): Record<string, unknown> => {
  switch (secretMaterial.type) {
    case 'api_key':
      return {
        credential_type: 'api_key'
      }
    case 'oauth_refresh_token':
      return {
        credential_type: 'oauth_refresh_token'
      }
    case 'aws_sigv4':
      return {
        credential_type: 'aws_sigv4',
        credential_region: secretMaterial.region,
        credential_has_session_token: secretMaterial.session_token !== undefined
      }
    default:
      return {
        credential_type: 'unknown'
      }
  }
}

const buildCreatedMetadata = (
  integrationWrite: OpenApiIntegrationWrite
): Record<string, unknown> => ({
  provider: integrationWrite.provider,
  integration_name: integrationWrite.name,
  template_id: integrationWrite.template_id,
  ...summarizeSecretMaterial(integrationWrite.secret_material)
})

const buildUpdatedMetadata = ({
  integration,
  update,
  secret_material
}: {
  integration: OpenApiIntegration
  update: OpenApiIntegrationUpdateRequest
  secret_material?: OpenApiIntegrationSecretMaterialWrite
}): Record<string, unknown> => ({
  provider: integration.provider,
  integration_name: integration.name,
  enabled: integration.enabled,
  credential_ref_present: integration.secret_ref !== null && integration.secret_ref !== undefined,
  credential_version: integration.secret_version ?? null,
  current_template_id: integration.template_id,
  next_template_id: update.template_id ?? integration.template_id,
  enabled_changed: update.enabled !== undefined,
  next_enabled: update.enabled ?? integration.enabled,
  ...(secret_material ? summarizeSecretMaterial(secret_material) : {})
})

const buildDeletedMetadata = ({
  integration,
  secret_material
}: {
  integration: OpenApiIntegration
  secret_material?: OpenApiIntegrationSecretMaterialWrite
}): Record<string, unknown> => ({
  provider: integration.provider,
  integration_name: integration.name,
  enabled: integration.enabled,
  template_id: integration.template_id,
  credential_ref_present: integration.secret_ref !== null && integration.secret_ref !== undefined,
  credential_version: integration.secret_version ?? null,
  ...(secret_material ? summarizeSecretMaterial(secret_material) : {})
})

const buildIntegrationLifecycleAuditEvent = ({
  action,
  input,
  metadata
}: {
  action: IntegrationLifecycleAuditAction
  input: z.infer<typeof IntegrationAuditEventBaseSchema>
  metadata: Record<string, unknown>
}): OpenApiAuditEvent =>
  OpenApiAuditEventSchema.parse({
    event_id: input.event_id,
    timestamp: input.timestamp,
    tenant_id: input.tenant_id,
    workload_id: null,
    integration_id: input.integration_id,
    correlation_id: input.correlation_id,
    event_type: 'admin_action',
    decision: 'allowed',
    action_group: action,
    risk_tier: null,
    message: input.message ?? null,
    metadata: {
      ...(input.metadata ?? {}),
      ...metadata,
      admin_action: action,
      ...buildActorMetadata(input)
    }
  })

const appendIntegrationAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  event,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  event: OpenApiAuditEvent
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedEvent = OpenApiAuditEventSchema.safeParse(event)
  if (!parsedEvent.success) {
    return err('invalid_input', parsedEvent.error.message)
  }

  return audit.appendAuditEvent({
    event: parsedEvent.data,
    db_context
  })
}

export const appendIntegrationCreatedAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: IntegrationCreatedAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedInput = IntegrationCreatedAuditInputSchema.safeParse(input)
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message)
  }

  return appendIntegrationAuditEvent({
    audit,
    event: buildIntegrationLifecycleAuditEvent({
      action: 'admin.integration.created',
      input: parsedInput.data,
      metadata: buildCreatedMetadata(parsedInput.data.integration_write)
    }),
    db_context
  })
}

export const appendIntegrationUpdatedAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: IntegrationUpdatedAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedInput = IntegrationUpdatedAuditInputSchema.safeParse(input)
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message)
  }

  if (parsedInput.data.integration.tenant_id !== parsedInput.data.tenant_id) {
    return err('invalid_input', 'integration tenant_id must match audit event tenant_id')
  }

  if (parsedInput.data.integration.integration_id !== parsedInput.data.integration_id) {
    return err('invalid_input', 'integration_id must match the audited integration identifier')
  }

  return appendIntegrationAuditEvent({
    audit,
    event: buildIntegrationLifecycleAuditEvent({
      action: 'admin.integration.updated',
      input: parsedInput.data,
      metadata: buildUpdatedMetadata(parsedInput.data)
    }),
    db_context
  })
}

export const appendIntegrationDeletedAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: IntegrationDeletedAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedInput = IntegrationDeletedAuditInputSchema.safeParse(input)
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message)
  }

  if (parsedInput.data.integration.tenant_id !== parsedInput.data.tenant_id) {
    return err('invalid_input', 'integration tenant_id must match audit event tenant_id')
  }

  if (parsedInput.data.integration.integration_id !== parsedInput.data.integration_id) {
    return err('invalid_input', 'integration_id must match the audited integration identifier')
  }

  return appendIntegrationAuditEvent({
    audit,
    event: buildIntegrationLifecycleAuditEvent({
      action: 'admin.integration.deleted',
      input: parsedInput.data,
      metadata: buildDeletedMetadata(parsedInput.data)
    }),
    db_context
  })
}

export type IntegrationLifecycleAuditEmitter<TDataAccessContext = unknown> = {
  appendIntegrationCreatedAuditEvent: (input: {
    input: IntegrationCreatedAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
  appendIntegrationUpdatedAuditEvent: (input: {
    input: IntegrationUpdatedAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
  appendIntegrationDeletedAuditEvent: (input: {
    input: IntegrationDeletedAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
}

export const createIntegrationLifecycleAuditEmitter = <TDataAccessContext = unknown>(
  audit: AuditAppender<TDataAccessContext>
): IntegrationLifecycleAuditEmitter<TDataAccessContext> => ({
  appendIntegrationCreatedAuditEvent: ({input, db_context}) =>
    appendIntegrationCreatedAuditEvent({audit, input, db_context}),
  appendIntegrationUpdatedAuditEvent: ({input, db_context}) =>
    appendIntegrationUpdatedAuditEvent({audit, input, db_context}),
  appendIntegrationDeletedAuditEvent: ({input, db_context}) =>
    appendIntegrationDeletedAuditEvent({audit, input, db_context})
})
