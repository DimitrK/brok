import {OpenApiAuditEventSchema, type OpenApiAuditEvent} from '@broker-interceptor/schemas'
import {z} from 'zod'

import {type AuditAppendEventResult} from './contracts'
import {err, type AuditResult} from './errors'

export const AdminAuditActionSchema = z.enum([
  'admin.login.succeeded',
  'admin.login.failed',
  'admin.signup_mode.changed',
  'admin.access_request.created',
  'admin.access_request.approved',
  'admin.access_request.denied'
])
export type AdminAuditAction = z.infer<typeof AdminAuditActionSchema>

export const AdminSignupModeSchema = z.enum(['open', 'closed'])
export type AdminSignupMode = z.infer<typeof AdminSignupModeSchema>

const AdminAuditEventBaseSchema = z
  .object({
    event_id: z.string().min(1),
    timestamp: z.string().datetime({offset: true}),
    tenant_id: z.string().min(1),
    workload_id: z.string().min(1).nullable().optional(),
    integration_id: z.string().min(1).nullable().optional(),
    correlation_id: z.string().min(1),
    message: z.string().nullable().optional(),
    actor_subject: z.string().min(1).optional(),
    actor_email: z.string().email().optional(),
    actor_roles: z.array(z.string().min(1)).optional(),
    metadata: z.record(z.string(), z.unknown()).optional()
  })
  .strict()

export const AdminLoginAuditInputSchema = AdminAuditEventBaseSchema.extend({
  provider: z.string().min(1),
  reason_code: z.string().min(1).optional()
}).strict()
export type AdminLoginAuditInput = z.infer<typeof AdminLoginAuditInputSchema>

export const AdminSignupModeChangedAuditInputSchema = AdminAuditEventBaseSchema.extend({
  mode: AdminSignupModeSchema,
  previous_mode: AdminSignupModeSchema.optional()
}).strict()
export type AdminSignupModeChangedAuditInput = z.infer<typeof AdminSignupModeChangedAuditInputSchema>

export const AdminAccessRequestAuditInputSchema = AdminAuditEventBaseSchema.extend({
  request_id: z.string().min(1),
  target_subject: z.string().min(1).optional(),
  target_email: z.string().email().optional(),
  reason_code: z.string().min(1).optional()
}).strict()
export type AdminAccessRequestAuditInput = z.infer<typeof AdminAccessRequestAuditInputSchema>

type AuditAppender<TDataAccessContext = unknown> = {
  appendAuditEvent: (input: {
    event: unknown
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
}

const buildAdminAuditEvent = ({
  action,
  decision,
  input,
  metadata
}: {
  action: AdminAuditAction
  decision: 'allowed' | 'denied' | 'approval_required' | 'throttled' | null
  input: z.infer<typeof AdminAuditEventBaseSchema>
  metadata: Record<string, unknown>
}): OpenApiAuditEvent =>
  OpenApiAuditEventSchema.parse({
    event_id: input.event_id,
    timestamp: input.timestamp,
    tenant_id: input.tenant_id,
    workload_id: input.workload_id ?? null,
    integration_id: input.integration_id ?? null,
    correlation_id: input.correlation_id,
    event_type: 'admin_action',
    decision,
    action_group: action,
    risk_tier: null,
    message: input.message ?? null,
    metadata: {
      ...(input.metadata ?? {}),
      ...metadata,
      admin_action: action,
      actor_subject: input.actor_subject ?? null,
      actor_email: input.actor_email ?? null,
      actor_roles: input.actor_roles ?? null
    }
  })

const appendAdminAuditEvent = async <TDataAccessContext = unknown>({
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

export const appendAdminLoginSucceededAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: AdminLoginAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedInput = AdminLoginAuditInputSchema.safeParse(input)
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message)
  }

  const event = buildAdminAuditEvent({
    action: 'admin.login.succeeded',
    decision: 'allowed',
    input: parsedInput.data,
    metadata: {
      provider: parsedInput.data.provider
    }
  })

  return appendAdminAuditEvent({
    audit,
    event,
    db_context
  })
}

export const appendAdminLoginFailedAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: AdminLoginAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedInput = AdminLoginAuditInputSchema.safeParse(input)
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message)
  }

  const event = buildAdminAuditEvent({
    action: 'admin.login.failed',
    decision: 'denied',
    input: parsedInput.data,
    metadata: {
      provider: parsedInput.data.provider,
      reason_code: parsedInput.data.reason_code ?? null
    }
  })

  return appendAdminAuditEvent({
    audit,
    event,
    db_context
  })
}

export const appendAdminSignupModeChangedAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: AdminSignupModeChangedAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedInput = AdminSignupModeChangedAuditInputSchema.safeParse(input)
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message)
  }

  const event = buildAdminAuditEvent({
    action: 'admin.signup_mode.changed',
    decision: null,
    input: parsedInput.data,
    metadata: {
      mode: parsedInput.data.mode,
      previous_mode: parsedInput.data.previous_mode ?? null
    }
  })

  return appendAdminAuditEvent({
    audit,
    event,
    db_context
  })
}

const appendAdminAccessRequestAuditEvent = async <TDataAccessContext = unknown>({
  audit,
  action,
  decision,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  action: Extract<AdminAuditAction, `admin.access_request.${string}`>
  decision: 'allowed' | 'denied' | 'approval_required'
  input: AdminAccessRequestAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> => {
  const parsedInput = AdminAccessRequestAuditInputSchema.safeParse(input)
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message)
  }

  const event = buildAdminAuditEvent({
    action,
    decision,
    input: parsedInput.data,
    metadata: {
      request_id: parsedInput.data.request_id,
      target_subject: parsedInput.data.target_subject ?? null,
      target_email: parsedInput.data.target_email ?? null,
      reason_code: parsedInput.data.reason_code ?? null
    }
  })

  return appendAdminAuditEvent({
    audit,
    event,
    db_context
  })
}

export const appendAdminAccessRequestCreatedAuditEvent = <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: AdminAccessRequestAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> =>
  appendAdminAccessRequestAuditEvent({
    audit,
    action: 'admin.access_request.created',
    decision: 'approval_required',
    input,
    db_context
  })

export const appendAdminAccessRequestApprovedAuditEvent = <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: AdminAccessRequestAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> =>
  appendAdminAccessRequestAuditEvent({
    audit,
    action: 'admin.access_request.approved',
    decision: 'allowed',
    input,
    db_context
  })

export const appendAdminAccessRequestDeniedAuditEvent = <TDataAccessContext = unknown>({
  audit,
  input,
  db_context
}: {
  audit: AuditAppender<TDataAccessContext>
  input: AdminAccessRequestAuditInput
  db_context?: TDataAccessContext
}): Promise<AuditResult<AuditAppendEventResult>> =>
  appendAdminAccessRequestAuditEvent({
    audit,
    action: 'admin.access_request.denied',
    decision: 'denied',
    input,
    db_context
  })

export type AdminAuthPolicyAuditEmitter<TDataAccessContext = unknown> = {
  appendAdminLoginSucceededAuditEvent: (input: {
    input: AdminLoginAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
  appendAdminLoginFailedAuditEvent: (input: {
    input: AdminLoginAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
  appendAdminSignupModeChangedAuditEvent: (input: {
    input: AdminSignupModeChangedAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
  appendAdminAccessRequestCreatedAuditEvent: (input: {
    input: AdminAccessRequestAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
  appendAdminAccessRequestApprovedAuditEvent: (input: {
    input: AdminAccessRequestAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
  appendAdminAccessRequestDeniedAuditEvent: (input: {
    input: AdminAccessRequestAuditInput
    db_context?: TDataAccessContext
  }) => Promise<AuditResult<AuditAppendEventResult>>
}

export const createAdminAuthPolicyAuditEmitter = <TDataAccessContext = unknown>(
  audit: AuditAppender<TDataAccessContext>
): AdminAuthPolicyAuditEmitter<TDataAccessContext> => ({
  appendAdminLoginSucceededAuditEvent: ({input, db_context}) =>
    appendAdminLoginSucceededAuditEvent({audit, input, db_context}),
  appendAdminLoginFailedAuditEvent: ({input, db_context}) =>
    appendAdminLoginFailedAuditEvent({audit, input, db_context}),
  appendAdminSignupModeChangedAuditEvent: ({input, db_context}) =>
    appendAdminSignupModeChangedAuditEvent({audit, input, db_context}),
  appendAdminAccessRequestCreatedAuditEvent: ({input, db_context}) =>
    appendAdminAccessRequestCreatedAuditEvent({audit, input, db_context}),
  appendAdminAccessRequestApprovedAuditEvent: ({input, db_context}) =>
    appendAdminAccessRequestApprovedAuditEvent({audit, input, db_context}),
  appendAdminAccessRequestDeniedAuditEvent: ({input, db_context}) =>
    appendAdminAccessRequestDeniedAuditEvent({audit, input, db_context})
})
