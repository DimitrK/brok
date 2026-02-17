import {OpenApiAuditEventSchema} from '@broker-interceptor/schemas'

import {
  AuditAppendEventInputSchema,
  AuditAppendEventResultSchema,
  AuditQueryEventsInputSchema,
  AuditQueryEventsResultSchema,
  AuditRedactionProfileSchema,
  type AuditAppendEventResult,
  type AuditQueryEventsResult,
  type AuditRedactionProfile
} from './contracts'
import {err, ok, type AuditResult} from './errors'
import {
  createDefaultAuditRedactionProfile,
  redactAuditEvent,
  redactStructuredLogPayload,
  toStructuredAuditLogRecord
} from './redaction'
import {normalizeAuditEventSearchFilter} from './search'
import type {AuditStoreAdapter} from './store'

export type AuditRedactionProfileResolver<TDataAccessContext = unknown> = (
  input: {
    tenant_id: string
    db_context?: TDataAccessContext
  }
) => Promise<AuditRedactionProfile | null> | AuditRedactionProfile | null

export type AuditServiceDependencies<TDataAccessContext = unknown> = {
  store: AuditStoreAdapter<TDataAccessContext>
  resolveRedactionProfile?: AuditRedactionProfileResolver<TDataAccessContext>
}

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message
  }
  return 'Unexpected error'
}

export class AuditService<TDataAccessContext = unknown> {
  public constructor(private readonly dependencies: AuditServiceDependencies<TDataAccessContext>) {}

  private async resolveTenantRedactionProfile(
    {
      tenant_id,
      db_context
    }: {
      tenant_id: string
      db_context?: TDataAccessContext
    }
  ): Promise<AuditResult<AuditRedactionProfile>> {
    const defaultProfile = createDefaultAuditRedactionProfile({tenant_id})
    const resolver = this.dependencies.resolveRedactionProfile

    if (!resolver) {
      return ok(defaultProfile)
    }

    let resolvedProfile: AuditRedactionProfile | null
    try {
      resolvedProfile = await resolver({
        tenant_id,
        db_context
      })
    } catch (error) {
      return err('redaction_profile_invalid', toErrorMessage(error))
    }

    if (!resolvedProfile) {
      return ok(defaultProfile)
    }

    const parsedProfile = AuditRedactionProfileSchema.safeParse(resolvedProfile)
    if (!parsedProfile.success) {
      return err('redaction_profile_invalid', parsedProfile.error.message)
    }

    if (parsedProfile.data.tenant_id !== tenant_id) {
      return err(
        'redaction_profile_invalid',
        'Resolved redaction profile tenant_id does not match event tenant_id'
      )
    }

    return ok(parsedProfile.data)
  }

  public async appendAuditEvent({
    event,
    db_context
  }: {
    event: unknown
    db_context?: TDataAccessContext
  }): Promise<AuditResult<AuditAppendEventResult>> {
    const parsedInput = AuditAppendEventInputSchema.safeParse({event})
    if (!parsedInput.success) {
      return err('invalid_input', parsedInput.error.message)
    }

    const profileResult = await this.resolveTenantRedactionProfile({
      tenant_id: parsedInput.data.event.tenant_id,
      db_context
    })
    if (!profileResult.ok) {
      return profileResult
    }

    const redactedEvent = redactAuditEvent({
      event: parsedInput.data.event,
      profile: profileResult.value
    })

    try {
      await this.dependencies.store.appendAuditEvent({
        event: redactedEvent,
        db_context
      })
    } catch (error) {
      return err('storage_write_failed', toErrorMessage(error))
    }

    const structuredLog = redactStructuredLogPayload({
      payload: toStructuredAuditLogRecord({
        event: redactedEvent,
        delivery_status: 'stored'
      }),
      profile: profileResult.value
    })

    const response = AuditAppendEventResultSchema.parse({
      event: redactedEvent,
      profile_id: profileResult.value.profile_id,
      delivery_status: 'stored',
      structured_log: structuredLog
    })

    return ok(response)
  }

  public async queryAuditEvents({
    query,
    db_context
  }: {
    query: unknown
    db_context?: TDataAccessContext
  }): Promise<AuditResult<AuditQueryEventsResult>> {
    const parsedInput = AuditQueryEventsInputSchema.safeParse({query})
    if (!parsedInput.success) {
      return err('invalid_input', parsedInput.error.message)
    }

    const filter = normalizeAuditEventSearchFilter(parsedInput.data.query)
    if (!filter.ok) {
      return filter
    }

    let events
    try {
      events = await this.dependencies.store.queryAuditEvents({
        filter: filter.value,
        db_context
      })
    } catch (error) {
      return err('storage_query_failed', toErrorMessage(error))
    }

    const parsedEvents = events.map(event => OpenApiAuditEventSchema.parse(event))
    const payload = AuditQueryEventsResultSchema.parse({events: parsedEvents})
    return ok(payload)
  }
}

export const createAuditService = <TDataAccessContext = unknown>(
  dependencies: AuditServiceDependencies<TDataAccessContext>
): AuditService<TDataAccessContext> =>
  new AuditService(dependencies)
