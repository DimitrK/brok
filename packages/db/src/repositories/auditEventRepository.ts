import {
  AppendSsrfGuardDecisionProjectionInputSchema,
  AuditRedactionProfileSchema,
  AuditQueryFilterSchema,
  CanonicalRequestDescriptorSchema,
  GetAuditRedactionProfileByTenantInputSchema,
  OpenApiAuditEventSchema,
  SsrfGuardDecisionProjectionSchema,
  UpsertAuditRedactionProfileInputSchema,
  type AppendSsrfGuardDecisionProjectionInput,
  type AuditRedactionProfile,
  type AuditEvent,
  type AuditQueryFilter,
  type CanonicalRequestDescriptor,
  type SsrfGuardDecisionProjection
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {CursorPage, DatabaseClient, RepositoryOperationContext} from '../types.js'
import {decodeCursor, encodeCursor, parseCursorPair, resolveRepositoryDbClient} from '../utils.js'

const toAuditEvent = (value: unknown): AuditEvent => OpenApiAuditEventSchema.parse(value)
const toAuditRedactionProfile = (value: unknown): AuditRedactionProfile =>
  AuditRedactionProfileSchema.parse(value)
const toSsrfGuardDecisionProjection = (record: {
  eventId: string
  timestamp: Date
  tenantId: string
  workloadId: string
  integrationId: string
  templateId: string
  templateVersion: number
  destinationHost: string
  destinationPort: number
  resolvedIps: string[]
  decision: 'allowed' | 'denied' | 'approval_required' | 'throttled'
  reasonCode: string
  correlationId: string
}): SsrfGuardDecisionProjection =>
  SsrfGuardDecisionProjectionSchema.parse({
    event_id: record.eventId,
    timestamp: record.timestamp.toISOString(),
    tenant_id: record.tenantId,
    workload_id: record.workloadId,
    integration_id: record.integrationId,
    template_id: record.templateId,
    template_version: record.templateVersion,
    destination_host: record.destinationHost,
    destination_port: record.destinationPort,
    resolved_ips: record.resolvedIps,
    decision: record.decision,
    reason_code: record.reasonCode,
    correlation_id: record.correlationId
  })

const equivalentIsoTimestamp = (left: string, right: string): boolean => {
  const leftEpochMs = Date.parse(left)
  const rightEpochMs = Date.parse(right)
  return Number.isFinite(leftEpochMs) && Number.isFinite(rightEpochMs) && leftEpochMs === rightEpochMs
}

const ssrfProjectionEquals = (
  left: SsrfGuardDecisionProjection,
  right: SsrfGuardDecisionProjection
): boolean =>
  left.event_id === right.event_id &&
  equivalentIsoTimestamp(left.timestamp, right.timestamp) &&
  left.tenant_id === right.tenant_id &&
  left.workload_id === right.workload_id &&
  left.integration_id === right.integration_id &&
  left.template_id === right.template_id &&
  left.template_version === right.template_version &&
  left.destination_host === right.destination_host &&
  left.destination_port === right.destination_port &&
  left.decision === right.decision &&
  left.reason_code === right.reason_code &&
  left.correlation_id === right.correlation_id &&
  left.resolved_ips.length === right.resolved_ips.length &&
  left.resolved_ips.every((value, index) => value === right.resolved_ips[index])

const policyDecisionInputSchema = CanonicalRequestDescriptorSchema.transform(descriptor => descriptor)

export class AuditEventRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async appendAuditEvent(input: {
    event: AuditEvent
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }): Promise<void> {
    const event = OpenApiAuditEventSchema.parse(input.event)

    try {
      const operationContext =
        input.context ?? (input.transaction_client !== undefined
          ? {
              transaction_client: input.transaction_client
            }
          : undefined)

      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'auditEvent',
          method: 'create'
        }
      ])

      await dbClient.auditEvent.create({
        data: {
          eventId: event.event_id,
          tenantId: event.tenant_id,
          timestamp: new Date(event.timestamp),
          workloadId: event.workload_id ?? null,
          integrationId: event.integration_id ?? null,
          correlationId: event.correlation_id,
          eventType: event.event_type,
          decision: event.decision ?? null,
          actionGroup: event.action_group ?? null,
          riskTier: event.risk_tier ?? null,
          upstreamStatusCode: event.upstream_status_code ?? null,
          latencyMs: event.latency_ms ?? null,
          eventJson: event
        }
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async appendPolicyDecisionAuditEvent(input: {
    descriptor: CanonicalRequestDescriptor
    decision: {
      decision: 'allowed' | 'denied' | 'approval_required' | 'throttled'
      reason_code: string
      action_group: string
      risk_tier: 'low' | 'medium' | 'high'
      policy_match?: {
        policy_id?: string | null
        rule_type?: 'allow' | 'deny' | 'approval_required' | 'rate_limit'
      }
      trace: unknown[]
    }
    correlation_id: string
    timestamp: string
    event_id: string
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }): Promise<void> {
    const descriptor = policyDecisionInputSchema.parse(input.descriptor)
    const event = OpenApiAuditEventSchema.parse({
      event_id: input.event_id,
      timestamp: input.timestamp,
      tenant_id: descriptor.tenant_id,
      workload_id: descriptor.workload_id,
      integration_id: descriptor.integration_id,
      correlation_id: input.correlation_id,
      event_type: 'policy_decision',
      decision: input.decision.decision,
      action_group: input.decision.action_group,
      risk_tier: input.decision.risk_tier,
      canonical_descriptor: descriptor,
      policy: input.decision.policy_match?.rule_type
        ? {
            rule_id: input.decision.policy_match.policy_id ?? null,
            rule_type: input.decision.policy_match.rule_type,
            approval_id: null
          }
        : null,
      metadata: {
        reason_code: input.decision.reason_code,
        trace: input.decision.trace
      }
    })

    const operationContext =
      input.context ?? (input.transaction_client !== undefined
        ? {
            transaction_client: input.transaction_client
          }
        : undefined)

    await this.appendAuditEvent({
      event,
      context: operationContext
    })
  }

  public async appendSsrfGuardDecisionProjection(
    rawInput: AppendSsrfGuardDecisionProjectionInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<SsrfGuardDecisionProjection> {
    const input = AppendSsrfGuardDecisionProjectionInputSchema.parse({
      projection: rawInput.projection
    })
    const operationContext =
      rawInput.context ?? context ?? (rawInput.transaction_client !== undefined
        ? {
            transaction_client: rawInput.transaction_client
          }
        : undefined)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'ssrfGuardDecision',
          method: 'upsert'
        }
      ])

      const record = await dbClient.ssrfGuardDecision.upsert({
        where: {
          eventId: input.projection.event_id
        },
        create: {
          eventId: input.projection.event_id,
          timestamp: new Date(input.projection.timestamp),
          tenantId: input.projection.tenant_id,
          workloadId: input.projection.workload_id,
          integrationId: input.projection.integration_id,
          templateId: input.projection.template_id,
          templateVersion: input.projection.template_version,
          destinationHost: input.projection.destination_host,
          destinationPort: input.projection.destination_port,
          resolvedIps: input.projection.resolved_ips,
          decision: input.projection.decision,
          reasonCode: input.projection.reason_code,
          correlationId: input.projection.correlation_id
        },
        update: {}
      })

      const projection = toSsrfGuardDecisionProjection(record)
      if (!ssrfProjectionEquals(projection, input.projection)) {
        throw new DbRepositoryError('conflict', 'SSRF decision projection event_id already exists with different payload')
      }

      return projection
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getAuditRedactionProfileByTenant(input: {
    tenant_id: string
    db_context?: RepositoryOperationContext
  }): Promise<AuditRedactionProfile | null> {
    const parsedInput = GetAuditRedactionProfileByTenantInputSchema.parse({
      tenant_id: input.tenant_id
    })

    try {
      const dbClient = resolveRepositoryDbClient(this.db, input.db_context, [
        {
          model: 'auditRedactionProfile',
          method: 'findUnique'
        }
      ])

      const record = await dbClient.auditRedactionProfile.findUnique({
        where: {
          tenantId: parsedInput.tenant_id
        }
      })

      if (!record) {
        return null
      }

      return toAuditRedactionProfile(record.profileJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async upsertAuditRedactionProfile(input: {
    profile: AuditRedactionProfile
    db_context?: RepositoryOperationContext
  }): Promise<AuditRedactionProfile> {
    const parsedInput = UpsertAuditRedactionProfileInputSchema.parse({
      profile: input.profile
    })

    try {
      const dbClient = resolveRepositoryDbClient(this.db, input.db_context, [
        {
          model: 'auditRedactionProfile',
          method: 'upsert'
        }
      ])

      const record = await dbClient.auditRedactionProfile.upsert({
        where: {
          tenantId: parsedInput.profile.tenant_id
        },
        create: {
          tenantId: parsedInput.profile.tenant_id,
          profileId: parsedInput.profile.profile_id,
          profileJson: parsedInput.profile
        },
        update: {
          profileId: parsedInput.profile.profile_id,
          profileJson: parsedInput.profile
        }
      })

      return toAuditRedactionProfile(record.profileJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async queryAuditEvents(rawFilter: AuditQueryFilter): Promise<CursorPage<AuditEvent>> {
    const filter = AuditQueryFilterSchema.parse(rawFilter)

    if (filter.cursor) {
      decodeCursor(filter.cursor)
    }

    const limit = filter.limit ?? 100

    try {
      const whereInput: {
        timestamp?: {
          gte?: Date
          lte?: Date
        }
        tenantId?: string
        workloadId?: string
        integrationId?: string
        actionGroup?: string
        decision?: 'allowed' | 'denied' | 'approval_required' | 'throttled'
        OR?: Array<{
          timestamp: {
            lt?: Date
            equals?: Date
          }
          eventId?: {
            lt: string
          }
        }>
      } = {
        ...(filter.time_min || filter.time_max
          ? {
              timestamp: {
                ...(filter.time_min ? {gte: new Date(filter.time_min)} : {}),
                ...(filter.time_max ? {lte: new Date(filter.time_max)} : {})
              }
            }
          : {}),
        ...(filter.tenant_id ? {tenantId: filter.tenant_id} : {}),
        ...(filter.workload_id ? {workloadId: filter.workload_id} : {}),
        ...(filter.integration_id ? {integrationId: filter.integration_id} : {}),
        ...(filter.action_group ? {actionGroup: filter.action_group} : {}),
        ...(filter.decision ? {decision: filter.decision} : {})
      }

      if (filter.cursor) {
        const cursor = parseCursorPair(filter.cursor)
        if (filter.tenant_id && filter.tenant_id !== cursor.tenant_id) {
          throw new DbRepositoryError('validation_error', 'Cursor tenant scope mismatch')
        }

        const cursorTimestamp = new Date(cursor.timestamp)
        whereInput.OR = [
          {
            timestamp: {
              lt: cursorTimestamp
            }
          },
          {
            timestamp: {
              equals: cursorTimestamp
            },
            eventId: {
              lt: cursor.event_id
            }
          }
        ]
      }

      const records = await this.db.auditEvent.findMany({
        where: whereInput,
        orderBy: [
          {
            timestamp: 'desc'
          },
          {
            eventId: 'desc'
          }
        ],
        take: limit,
        select: {
          eventJson: true,
          eventId: true,
          timestamp: true,
          tenantId: true
        }
      })

      const items = records.map(record => toAuditEvent(record.eventJson))
      const hasMore = records.length === limit
      const lastRecord = records.at(-1)

      return {
        items,
        ...(hasMore && lastRecord
          ? {
              next_cursor: encodeCursor(
                `${lastRecord.timestamp.toISOString()}|${lastRecord.eventId}|${lastRecord.tenantId}`
              )
            }
          : {})
      }
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
