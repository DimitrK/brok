import {OpenApiAuditEventSchema, OpenApiIntegrationSchema} from '@broker-interceptor/schemas'
import {describe, expect, it, vi} from 'vitest'

import {AuditAppendEventResultSchema} from '../contracts'
import {
  appendIntegrationCreatedAuditEvent,
  appendIntegrationDeletedAuditEvent,
  appendIntegrationUpdatedAuditEvent,
  createIntegrationLifecycleAuditEmitter
} from '../integration'
import {ok} from '../errors'

const buildBaseInput = (overrides: Record<string, unknown> = {}) => ({
  event_id: 'evt_integration_1',
  timestamp: '2026-03-01T08:00:00.000Z',
  tenant_id: 'tenant_1',
  integration_id: 'integration_1',
  correlation_id: 'corr_integration_1',
  actor_subject: 'sub_admin_1',
  actor_email: 'admin@example.com',
  ...overrides
})

const buildIntegration = (overrides: Record<string, unknown> = {}) =>
  OpenApiIntegrationSchema.parse({
    integration_id: 'integration_1',
    tenant_id: 'tenant_1',
    provider: 's3_compatible',
    name: 'Nightly backups',
    template_id: 'tpl_s3_v1',
    enabled: true,
    secret_ref: 'sec_1',
    secret_version: 2,
    last_rotated_at: '2026-03-01T07:00:00.000Z',
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

describe('integration lifecycle audit emission helpers', () => {
  it('emits created events for aws_sigv4 integrations without raw secret values', async () => {
    const audit = createMockAuditAppender()

    const result = await appendIntegrationCreatedAuditEvent({
      audit,
      input: {
        ...buildBaseInput(),
        integration_write: {
          provider: 's3_compatible',
          name: 'Nightly backups',
          template_id: 'tpl_s3_v1',
          secret_material: {
            type: 'aws_sigv4',
            access_key_id: 'AKIA_TEST_ACCESS_KEY',
            secret_access_key: 'super-secret',
            session_token: 'session-token',
            region: 'eu-west-1'
          }
        }
      }
    })

    expect(result.ok).toBe(true)
    const appendInput = audit.appendAuditEvent.mock.calls[0]?.[0]
    const event = OpenApiAuditEventSchema.parse(appendInput?.event)
    const metadata = event.metadata as Record<string, unknown>

    expect(event.event_type).toBe('admin_action')
    expect(event.action_group).toBe('admin.integration.created')
    expect(event.decision).toBe('allowed')
    expect(metadata.credential_type).toBe('aws_sigv4')
    expect(metadata.credential_region).toBe('eu-west-1')
    expect(metadata.credential_has_session_token).toBe(true)
    expect(metadata).not.toHaveProperty('secret_access_key')
    expect(metadata).not.toHaveProperty('session_token')
    expect(metadata).not.toHaveProperty('access_key_id')
  })

  it('emits update and delete events with integration identifiers and package-safe secret summaries', async () => {
    const audit = createMockAuditAppender()
    const integration = buildIntegration()

    const updated = await appendIntegrationUpdatedAuditEvent({
      audit,
      input: {
        ...buildBaseInput(),
        integration,
        update: {
          enabled: false,
          template_id: 'tpl_s3_v2'
        },
        secret_material: {
          type: 'aws_sigv4',
          access_key_id: 'AKIA_TEST_ACCESS_KEY',
          secret_access_key: 'super-secret',
          region: 'eu-central-1'
        }
      }
    })

    const deleted = await appendIntegrationDeletedAuditEvent({
      audit,
      input: {
        ...buildBaseInput({
          event_id: 'evt_integration_deleted'
        }),
        integration
      }
    })

    expect(updated.ok).toBe(true)
    expect(deleted.ok).toBe(true)

    const updatedEvent = OpenApiAuditEventSchema.parse(audit.appendAuditEvent.mock.calls[0]?.[0]?.event)
    const deletedEvent = OpenApiAuditEventSchema.parse(audit.appendAuditEvent.mock.calls[1]?.[0]?.event)
    const updatedMetadata = updatedEvent.metadata as Record<string, unknown>
    const deletedMetadata = deletedEvent.metadata as Record<string, unknown>

    expect(updatedEvent.action_group).toBe('admin.integration.updated')
    expect(updatedMetadata.current_template_id).toBe('tpl_s3_v1')
    expect(updatedMetadata.next_template_id).toBe('tpl_s3_v2')
    expect(updatedMetadata.next_enabled).toBe(false)
    expect(updatedMetadata.credential_type).toBe('aws_sigv4')
    expect(updatedMetadata.credential_region).toBe('eu-central-1')

    expect(deletedEvent.action_group).toBe('admin.integration.deleted')
    expect(deletedMetadata.provider).toBe('s3_compatible')
    expect(deletedMetadata.credential_ref_present).toBe(true)
    expect(deletedMetadata.credential_version).toBe(2)
  })

  it('passes db_context through the emitter factory', async () => {
    const audit = createMockAuditAppender()
    const emitter = createIntegrationLifecycleAuditEmitter(audit)
    const db_context = {transaction_client: {id: 'tx_integration_1'}}

    const result = await emitter.appendIntegrationDeletedAuditEvent({
      input: {
        ...buildBaseInput(),
        integration: buildIntegration()
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

  it('fails closed when integration identity does not match the audit envelope', async () => {
    const audit = createMockAuditAppender()

    const result = await appendIntegrationUpdatedAuditEvent({
      audit,
      input: {
        ...buildBaseInput({
          integration_id: 'integration_1'
        }),
        integration: buildIntegration({
          integration_id: 'integration_2'
        }),
        update: {
          enabled: false
        }
      }
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error.code).toBe('invalid_input')
    }
    expect(audit.appendAuditEvent).not.toHaveBeenCalled()
  })
})
