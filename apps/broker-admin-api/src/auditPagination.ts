import type {OpenApiAuditEvent} from '@broker-interceptor/schemas'
import {z} from 'zod'

import {badRequest} from './errors'
import {auditFilterSchema} from './repository'

const defaultAuditPageSize = 50

const auditCursorPayloadSchema = z
  .object({
    v: z.literal(1),
    offset: z.number().int().min(0)
  })
  .strict()

const auditListLimitQuerySchema = z.preprocess(value => {
  if (value === undefined) {
    return undefined
  }

  if (typeof value !== 'string') {
    return value
  }

  const parsed = Number.parseInt(value, 10)
  return Number.isNaN(parsed) ? value : parsed
}, z.number().int().min(1).max(100).optional())

export const auditListQuerySchema = auditFilterSchema
  .extend({
    limit: auditListLimitQuerySchema,
    cursor: z.string().min(1).optional()
  })
  .strict()

const parseAuditCursor = ({cursor, maxOffset}: {cursor: string; maxOffset: number}) => {
  let decoded: unknown
  try {
    decoded = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as unknown
  } catch {
    throw badRequest('audit_cursor_invalid', 'Audit cursor is invalid')
  }

  const parsed = auditCursorPayloadSchema.safeParse(decoded)
  if (!parsed.success) {
    throw badRequest('audit_cursor_invalid', 'Audit cursor is invalid')
  }

  if (parsed.data.offset > maxOffset) {
    throw badRequest('audit_cursor_invalid', 'Audit cursor is outside the available result set')
  }

  return parsed.data
}

const toAuditCursor = ({offset}: {offset: number}) =>
  Buffer.from(JSON.stringify(auditCursorPayloadSchema.parse({v: 1, offset})), 'utf8').toString('base64url')

const compareAuditEventsByRecency = (left: OpenApiAuditEvent, right: OpenApiAuditEvent) => {
  const leftTs = Date.parse(left.timestamp)
  const rightTs = Date.parse(right.timestamp)
  if (leftTs !== rightTs) {
    return rightTs - leftTs
  }

  return right.event_id.localeCompare(left.event_id)
}

export const paginateAuditEvents = ({
  events,
  limit,
  cursor
}: {
  events: OpenApiAuditEvent[]
  limit?: number
  cursor?: string
}): {
  events: OpenApiAuditEvent[]
  next_cursor?: string
} => {
  const sorted = [...events].sort(compareAuditEventsByRecency)
  const pageLimit = limit ?? defaultAuditPageSize
  const offset = cursor ? parseAuditCursor({cursor, maxOffset: sorted.length}).offset : 0

  const page = sorted.slice(offset, offset + pageLimit)
  const nextOffset = offset + page.length
  const nextCursor = nextOffset < sorted.length ? toAuditCursor({offset: nextOffset}) : undefined

  return {
    events: page,
    ...(nextCursor ? {next_cursor: nextCursor} : {})
  }
}
