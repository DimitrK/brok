import {type OpenApiAuditEvent} from '@broker-interceptor/schemas'

import {
  AuditEventSearchFilterSchema,
  AuditEventSearchQuerySchema,
  type AuditEventSearchFilter
} from './contracts'
import {err, ok, type AuditResult} from './errors'

const parseIsoDate = (value: string): Date => new Date(value)

const toEventTimestamp = (event: OpenApiAuditEvent): Date => parseIsoDate(event.timestamp)

export const normalizeAuditEventSearchFilter = (
  rawQuery: unknown
): AuditResult<AuditEventSearchFilter> => {
  const parsedQuery = AuditEventSearchQuerySchema.safeParse(rawQuery)
  if (!parsedQuery.success) {
    return err('invalid_search_query', parsedQuery.error.message)
  }

  const filter = AuditEventSearchFilterSchema.parse({
    ...(parsedQuery.data.time_min ? {time_min: parseIsoDate(parsedQuery.data.time_min)} : {}),
    ...(parsedQuery.data.time_max ? {time_max: parseIsoDate(parsedQuery.data.time_max)} : {}),
    ...(parsedQuery.data.tenant_id ? {tenant_id: parsedQuery.data.tenant_id} : {}),
    ...(parsedQuery.data.workload_id ? {workload_id: parsedQuery.data.workload_id} : {}),
    ...(parsedQuery.data.integration_id ? {integration_id: parsedQuery.data.integration_id} : {}),
    ...(parsedQuery.data.action_group ? {action_group: parsedQuery.data.action_group} : {}),
    ...(parsedQuery.data.decision ? {decision: parsedQuery.data.decision} : {})
  })

  if (filter.time_min && filter.time_max && filter.time_min > filter.time_max) {
    return err('invalid_time_range', 'time_min must be <= time_max')
  }

  return ok(filter)
}

export const buildAuditSearchPredicate = (filter: AuditEventSearchFilter) => (event: OpenApiAuditEvent) => {
  const eventTime = toEventTimestamp(event)

  if (filter.time_min && eventTime < filter.time_min) {
    return false
  }

  if (filter.time_max && eventTime > filter.time_max) {
    return false
  }

  if (filter.tenant_id && event.tenant_id !== filter.tenant_id) {
    return false
  }

  if (filter.workload_id && event.workload_id !== filter.workload_id) {
    return false
  }

  if (filter.integration_id && event.integration_id !== filter.integration_id) {
    return false
  }

  if (filter.action_group && event.action_group !== filter.action_group) {
    return false
  }

  if (filter.decision && event.decision !== filter.decision) {
    return false
  }

  return true
}

export const filterAuditEvents = ({
  events,
  filter
}: {
  events: OpenApiAuditEvent[]
  filter: AuditEventSearchFilter
}) => events.filter(buildAuditSearchPredicate(filter))
