import {OpenApiAuditEventSchema} from '@broker-interceptor/schemas'
import {describe, expect, it, vi} from 'vitest'

import {AuditAppendEventResultSchema} from '../contracts'
import {ok} from '../errors'
import {
  appendAdminAccessRequestApprovedAuditEvent,
  appendAdminAccessRequestCreatedAuditEvent,
  appendAdminAccessRequestDeniedAuditEvent,
  appendAdminLoginFailedAuditEvent,
  appendAdminLoginSucceededAuditEvent,
  appendAdminSignupModeChangedAuditEvent,
  createAdminAuthPolicyAuditEmitter
} from '../admin'

const buildBaseInput = (overrides: Record<string, unknown> = {}) => ({
  event_id: 'evt_admin_1',
  timestamp: '2026-02-14T10:00:00.000Z',
  tenant_id: 'tenant_1',
  correlation_id: 'corr_admin_1',
  actor_subject: 'sub_admin_1',
  actor_email: 'admin@example.com',
  ...overrides
})

const createMockAuditAppender = () => {
  const appendAuditEvent = vi.fn(
    ({event}: {event: unknown; db_context?: unknown}) =>
      Promise.resolve(
        ok(
          AuditAppendEventResultSchema.parse({
            event: OpenApiAuditEventSchema.parse(event),
            profile_id: 'default_strict_v1',
            delivery_status: 'stored',
            structured_log: {
              message: 'audit.event'
            }
          })
        )
      )
  )

  return {
    appendAuditEvent
  }
}

describe('admin auth-policy audit emission helpers', () => {
  it('emits admin.login.succeeded as admin_action with allowed decision', async () => {
    const audit = createMockAuditAppender()
    const result = await appendAdminLoginSucceededAuditEvent({
      audit,
      input: {
        ...buildBaseInput(),
        provider: 'google'
      }
    })

    expect(result.ok).toBe(true)
    const appendInput = audit.appendAuditEvent.mock.calls[0]?.[0]
    const event = OpenApiAuditEventSchema.parse(appendInput?.event)
    expect(event.event_type).toBe('admin_action')
    expect(event.action_group).toBe('admin.login.succeeded')
    expect(event.decision).toBe('allowed')
    expect((event.metadata as Record<string, unknown>).admin_action).toBe('admin.login.succeeded')
    expect((event.metadata as Record<string, unknown>).provider).toBe('google')
  })

  it('emits admin.login.failed with denied decision and reason code', async () => {
    const audit = createMockAuditAppender()
    const result = await appendAdminLoginFailedAuditEvent({
      audit,
      input: {
        ...buildBaseInput(),
        provider: 'github',
        reason_code: 'token_invalid'
      }
    })

    expect(result.ok).toBe(true)
    const appendInput = audit.appendAuditEvent.mock.calls[0]?.[0]
    const event = OpenApiAuditEventSchema.parse(appendInput?.event)
    expect(event.action_group).toBe('admin.login.failed')
    expect(event.decision).toBe('denied')
    expect((event.metadata as Record<string, unknown>).reason_code).toBe('token_invalid')
  })

  it('emits admin.signup_mode.changed with mode metadata', async () => {
    const audit = createMockAuditAppender()
    const result = await appendAdminSignupModeChangedAuditEvent({
      audit,
      input: {
        ...buildBaseInput(),
        mode: 'closed',
        previous_mode: 'open'
      }
    })

    expect(result.ok).toBe(true)
    const appendInput = audit.appendAuditEvent.mock.calls[0]?.[0]
    const event = OpenApiAuditEventSchema.parse(appendInput?.event)
    expect(event.action_group).toBe('admin.signup_mode.changed')
    expect(event.decision).toBeNull()
    expect((event.metadata as Record<string, unknown>).mode).toBe('closed')
    expect((event.metadata as Record<string, unknown>).previous_mode).toBe('open')
  })

  it('emits admin.access_request.created with approval_required decision', async () => {
    const audit = createMockAuditAppender()
    const result = await appendAdminAccessRequestCreatedAuditEvent({
      audit,
      input: {
        ...buildBaseInput(),
        request_id: 'request_1',
        target_email: 'new-admin@example.com'
      }
    })

    expect(result.ok).toBe(true)
    const appendInput = audit.appendAuditEvent.mock.calls[0]?.[0]
    const event = OpenApiAuditEventSchema.parse(appendInput?.event)
    expect(event.action_group).toBe('admin.access_request.created')
    expect(event.decision).toBe('approval_required')
    expect((event.metadata as Record<string, unknown>).request_id).toBe('request_1')
  })

  it('emits admin.access_request.approved and denied with mapped decisions', async () => {
    const audit = createMockAuditAppender()

    const approved = await appendAdminAccessRequestApprovedAuditEvent({
      audit,
      input: {
        ...buildBaseInput({
          event_id: 'evt_admin_approved'
        }),
        request_id: 'request_approved'
      }
    })
    const denied = await appendAdminAccessRequestDeniedAuditEvent({
      audit,
      input: {
        ...buildBaseInput({
          event_id: 'evt_admin_denied'
        }),
        request_id: 'request_denied',
        reason_code: 'manual_rejection'
      }
    })

    expect(approved.ok).toBe(true)
    expect(denied.ok).toBe(true)

    const approvedEvent = OpenApiAuditEventSchema.parse(audit.appendAuditEvent.mock.calls[0]?.[0]?.event)
    const deniedEvent = OpenApiAuditEventSchema.parse(audit.appendAuditEvent.mock.calls[1]?.[0]?.event)

    expect(approvedEvent.action_group).toBe('admin.access_request.approved')
    expect(approvedEvent.decision).toBe('allowed')
    expect(deniedEvent.action_group).toBe('admin.access_request.denied')
    expect(deniedEvent.decision).toBe('denied')
  })

  it('passes db_context through emitter factory methods', async () => {
    const audit = createMockAuditAppender()
    const emitter = createAdminAuthPolicyAuditEmitter(audit)
    const db_context = {transaction_client: {id: 'tx_admin_1'}}

    const result = await emitter.appendAdminLoginSucceededAuditEvent({
      input: {
        ...buildBaseInput(),
        provider: 'google'
      },
      db_context
    })

    expect(result.ok).toBe(true)
    expect(audit.appendAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        db_context
      })
    )
  })

  it('fails closed with invalid_input when action input is malformed', async () => {
    const audit = createMockAuditAppender()
    const result = await appendAdminAccessRequestCreatedAuditEvent({
      audit,
      input: {
        ...buildBaseInput(),
        request_id: ''
      }
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error.code).toBe('invalid_input')
    }
    expect(audit.appendAuditEvent).not.toHaveBeenCalled()
  })
})
