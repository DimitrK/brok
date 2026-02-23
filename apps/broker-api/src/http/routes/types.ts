import type {IncomingMessage, ServerResponse} from 'node:http'

import type {AuditService} from '@broker-interceptor/audit'
import type {FetchLike} from '@broker-interceptor/forwarder'
import type {StructuredLogger} from '@broker-interceptor/logging'
import type {OpenApiAuditEvent} from '@broker-interceptor/schemas'
import type {DnsResolver} from '@broker-interceptor/ssrf-guard'

import type {ServiceConfig} from '../../config'
import {DataPlaneRepository} from '../../repository'

export type MtlsAuthContext = {
  tenant_id: string
  workload_id: string
  cert_fingerprint256: string
  san_uri: string
}

export type SessionContext = {
  session_token: string
  session: {
    session_id: string
    workload_id: string
    tenant_id: string
    cert_fingerprint256: string
    token_hash: string
    expires_at: string
    dpop_jkt?: string
    scopes: string[]
  }
}

export type RequestHandlerState = {
  mtlsContext: MtlsAuthContext | null
  executeAuditRecorded: boolean
}

export type RouteRuntime = {
  config: ServiceConfig
  repository: DataPlaneRepository
  auditService: AuditService
  logger: StructuredLogger
  fetchImpl?: FetchLike
  baseDnsResolver: DnsResolver
  now: () => Date
  requireMtlsContextWithLogging: (input: {
    request: IncomingMessage
    repository: DataPlaneRepository
    expectedSanUriPrefix?: string
  }) => Promise<MtlsAuthContext>
  requireSessionContextWithLogging: (input: {
    request: IncomingMessage
    repository: DataPlaneRepository
    mtls: MtlsAuthContext
    config: ServiceConfig
    pathname: string
    requiredScope: 'execute' | 'manifest.read'
  }) => Promise<SessionContext>
  buildPublicRouteUrl: (input: {pathname: string}) => string
  getSingleHeaderValue: (input: {
    request: IncomingMessage
    name: 'authorization' | 'dpop'
  }) => string | undefined
  isDpopRequiredForIdentity: (input: {tenantId: string; workloadId: string}) => boolean
  isDpopFailureReasonCode: (value: string) => boolean
  buildAuditEvent: (input: {
    correlationId: string
    tenantId: string
    event: Omit<OpenApiAuditEvent, 'event_id' | 'timestamp' | 'tenant_id' | 'correlation_id'>
  }) => OpenApiAuditEvent
  appendAuditEvent: (input: {event: OpenApiAuditEvent}) => Promise<void>
  appendDpopFailureAuditEvent: (input: {
    correlationId: string
    tenantId: string
    workloadId: string
    reasonCode: string
    eventType: 'session_issued' | 'execute'
  }) => Promise<void>
  parseDestinationFromRequestUrl: (rawUrl: string) => {
    host: string
    port: number
  }
  appendSsrfDecisionProjectionBestEffort: (input: {
    projection: Parameters<DataPlaneRepository['appendSsrfDecisionProjectionShared']>[0]['projection']
    correlationId: string
    stage: string
  }) => Promise<void>
  reportPersistenceWarning: (input: {
    stage: string
    correlationId: string
    error: unknown
  }) => void
  normalizeResolvedIps: (value: string[]) => string[]
  ipSetsEqual: (left: string[], right: string[]) => boolean
  clamp: (input: {value: number; min: number; max: number}) => number
  toForwarderIdempotencyFingerprint: (input: {
    descriptor: Record<string, unknown>
    request: Record<string, unknown>
  }) => string
  decodedBase64ByteLength: (value: string) => number
}

export type RouteHandlerContext = {
  request: IncomingMessage
  response: ServerResponse
  correlationId: string
  method: string
  pathname: string
  state: RequestHandlerState
  runtime: RouteRuntime
}

export type BrokerApiRouteKind =
  | 'health'
  | 'manifestKeys'
  | 'session'
  | 'execute'
  | 'workloadManifest'
  | 'fallback'

export type BrokerApiRouteLogicHandler = (context: RouteHandlerContext) => void | Promise<void>

export type BrokerApiRouteHandler = (request: IncomingMessage, response: ServerResponse) => Promise<void>

export type BrokerApiRouteHandlers = {
  health: BrokerApiRouteHandler
  manifestKeys: BrokerApiRouteHandler
  session: BrokerApiRouteHandler
  execute: BrokerApiRouteHandler
  workloadManifest: BrokerApiRouteHandler
  fallback: BrokerApiRouteHandler
}
