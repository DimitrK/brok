import {randomUUID} from 'node:crypto'
import type {IncomingMessage, ServerResponse} from 'node:http'

import {OpenApiErrorSchema} from '@broker-interceptor/schemas'
import {z} from 'zod'

import {badRequest, unsupportedMediaType} from './errors'

const DEFAULT_SECURITY_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-resource-policy': 'same-origin',
  'cache-control': 'no-store'
}

const isJsonContentType = (contentTypeHeader: string | undefined) => {
  if (!contentTypeHeader) {
    return false
  }

  return contentTypeHeader.toLowerCase().includes('application/json')
}

export const extractCorrelationId = (request: IncomingMessage) => {
  const header = request.headers['x-correlation-id']
  const value = Array.isArray(header) ? header[0] : header
  if (typeof value !== 'string') {
    return randomUUID()
  }

  const trimmed = value.trim()
  if (trimmed.length === 0 || trimmed.length > 128) {
    return randomUUID()
  }

  return trimmed
}

const readBodyBuffer = async ({
  request,
  maxBodyBytes
}: {
  request: IncomingMessage
  maxBodyBytes: number
}) => {
  const chunks: Buffer[] = []
  let size = 0

  for await (const chunk of request) {
    let bufferChunk: Buffer
    if (typeof chunk === 'string') {
      bufferChunk = Buffer.from(chunk, 'utf8')
    } else if (chunk instanceof Uint8Array) {
      bufferChunk = Buffer.from(chunk)
    } else {
      throw badRequest('request_body_invalid', 'Request body contains an invalid chunk type')
    }

    size += bufferChunk.length
    if (size > maxBodyBytes) {
      throw badRequest('request_body_too_large', `Request body exceeds ${maxBodyBytes} bytes`)
    }

    chunks.push(bufferChunk)
  }

  return Buffer.concat(chunks)
}

export async function parseJsonBody<TSchema extends z.ZodTypeAny>({
  request,
  schema,
  maxBodyBytes,
  required
}: {
  request: IncomingMessage
  schema: TSchema
  maxBodyBytes: number
  required: true
}): Promise<z.infer<TSchema>>
export async function parseJsonBody<TSchema extends z.ZodTypeAny>({
  request,
  schema,
  maxBodyBytes,
  required
}: {
  request: IncomingMessage
  schema: TSchema
  maxBodyBytes: number
  required: false
}): Promise<z.infer<TSchema> | undefined>
export async function parseJsonBody<TSchema extends z.ZodTypeAny>({
  request,
  schema,
  maxBodyBytes,
  required
}: {
  request: IncomingMessage
  schema: TSchema
  maxBodyBytes: number
  required: boolean
}): Promise<z.infer<TSchema> | undefined> {
  const hasPotentialBody = Boolean(request.headers['content-length'] || request.headers['transfer-encoding'])
  if (!required && !hasPotentialBody) {
    return undefined
  }

  if (!isJsonContentType(request.headers['content-type'])) {
    throw unsupportedMediaType('content_type_invalid', 'Content-Type must be application/json')
  }

  const raw = await readBodyBuffer({request, maxBodyBytes})
  if (raw.length === 0) {
    if (required) {
      throw badRequest('request_body_missing', 'Request body is required')
    }

    return undefined
  }

  let parsedBody: unknown
  try {
    parsedBody = JSON.parse(raw.toString('utf8')) as unknown
  } catch {
    throw badRequest('request_body_invalid_json', 'Request body contains invalid JSON')
  }

  const parsed = schema.safeParse(parsedBody)
  if (!parsed.success) {
    throw badRequest('request_body_schema_invalid', parsed.error.issues.map(issue => issue.message).join('; '))
  }

  return parsed.data
}

export const parseQuery = <TSchema extends z.ZodTypeAny>({
  searchParams,
  schema
}: {
  searchParams: URLSearchParams
  schema: TSchema
}) => {
  const queryObject = Object.fromEntries(searchParams.entries())

  const parsed = schema.safeParse(queryObject)
  if (!parsed.success) {
    throw badRequest('query_invalid', parsed.error.issues.map(issue => issue.message).join('; '))
  }

  return parsed.data
}

export const decodePathParam = (value: string) => {
  try {
    return decodeURIComponent(value)
  } catch {
    throw badRequest('path_param_invalid', 'Path parameter encoding is invalid')
  }
}

const serialize = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8')

export const sendJson = ({
  response,
  status,
  correlationId,
  payload,
  headers
}: {
  response: ServerResponse
  status: number
  correlationId: string
  payload: unknown
  headers?: Record<string, string>
}) => {
  const body = serialize(payload)

  response.writeHead(status, {
    ...DEFAULT_SECURITY_HEADERS,
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(body.length),
    'x-correlation-id': correlationId,
    ...(headers ?? {})
  })

  response.end(body)
}

export const sendError = ({
  response,
  status,
  error,
  message,
  correlationId
}: {
  response: ServerResponse
  status: number
  error: string
  message: string
  correlationId: string
}) => {
  const payload = OpenApiErrorSchema.parse({
    error,
    message,
    correlation_id: correlationId
  })

  sendJson({
    response,
    status,
    payload,
    correlationId
  })
}

export const sendNoContent = ({
  response,
  correlationId,
  headers
}: {
  response: ServerResponse
  correlationId: string
  headers?: Record<string, string>
}) => {
  response.writeHead(204, {
    ...DEFAULT_SECURITY_HEADERS,
    'x-correlation-id': correlationId,
    ...(headers ?? {})
  })

  response.end()
}
