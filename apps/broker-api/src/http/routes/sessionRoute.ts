import {issueSession, SessionInputValidationError, verifyDpopProofJwt} from '@broker-interceptor/auth'
import {setLogContextFields} from '@broker-interceptor/logging'
import {OpenApiSessionRequestSchema, OpenApiSessionResponseSchema} from '@broker-interceptor/schemas'

import {badRequest, unauthorized} from '../../errors'
import {parseJsonBody, sendJson} from '../../http'
import type {BrokerApiRouteLogicHandler} from './types'

const SESSION_SCOPES = new Set(['execute', 'manifest.read'])

export const handleSessionRoute: BrokerApiRouteLogicHandler = async ({
  request,
  response,
  correlationId,
  method,
  pathname,
  state,
  runtime
}) => {
  const mtls = await runtime.requireMtlsContextWithLogging({
    request,
    repository: runtime.repository,
    ...(runtime.config.expectedSanUriPrefix
      ? {expectedSanUriPrefix: runtime.config.expectedSanUriPrefix}
      : {})
  })
  state.mtlsContext = mtls
  setLogContextFields({
    tenant_id: mtls.tenant_id,
    workload_id: mtls.workload_id
  })

  runtime.logger.info({
    event: 'session.issue.start',
    component: 'server.session',
    message: 'Session issuance started'
  })

  const body = await parseJsonBody({
    request,
    schema: OpenApiSessionRequestSchema,
    maxBodyBytes: runtime.config.maxBodyBytes,
    required: true
  })

  const sessionTtlSeconds = body.requested_ttl_seconds ?? runtime.config.sessionDefaultTtlSeconds
  const sessionScopes = runtime.repository.buildSessionScopes({requestedScopes: body.scopes})
  const invalidScopes = sessionScopes.filter(scope => !SESSION_SCOPES.has(scope))
  if (invalidScopes.length > 0) {
    throw badRequest('session_scope_invalid', `Unsupported session scopes: ${invalidScopes.join(',')}`)
  }

  const dpopRequiredByIdentity = runtime.isDpopRequiredForIdentity({
    tenantId: mtls.tenant_id,
    workloadId: mtls.workload_id
  })
  const dpopJwt = runtime.getSingleHeaderValue({request, name: 'dpop'})

  let dpopJkt: string | undefined
  if (dpopJwt) {
    const dpopResult = await verifyDpopProofJwt({
      dpopJwt,
      method,
      url: runtime.buildPublicRouteUrl({pathname}),
      tenantId: mtls.tenant_id,
      sessionId: mtls.workload_id,
      jtiStore: runtime.repository.getDpopReplayStore(),
      maxSkewSeconds: runtime.config.dpopMaxSkewSeconds,
      replayTtlSeconds: runtime.config.dpopMaxSkewSeconds
    })

    if (!dpopResult.ok) {
      await runtime.appendDpopFailureAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        workloadId: mtls.workload_id,
        reasonCode: dpopResult.error,
        eventType: 'session_issued'
      })
      throw unauthorized(dpopResult.error, 'DPoP verification failed')
    }

    dpopJkt = dpopResult.jkt
  }

  if (dpopRequiredByIdentity && !dpopJkt) {
    await runtime.appendDpopFailureAuditEvent({
      correlationId,
      tenantId: mtls.tenant_id,
      workloadId: mtls.workload_id,
      reasonCode: 'dpop_missing',
      eventType: 'session_issued'
    })
    throw unauthorized('dpop_missing', 'Workload or tenant policy requires DPoP for session issuance')
  }

  let issued
  try {
    issued = issueSession({
      workloadId: mtls.workload_id,
      tenantId: mtls.tenant_id,
      certFingerprint256: mtls.cert_fingerprint256,
      ttlSeconds: sessionTtlSeconds,
      now: runtime.now(),
      ...(dpopJkt ? {dpopKeyThumbprint: dpopJkt} : {})
    })
  } catch (error) {
    if (error instanceof SessionInputValidationError) {
      throw badRequest(error.code, 'Session input validation failed')
    }

    throw error
  }

  await runtime.repository.saveSession({
    session: {
      sessionId: issued.session.sessionId,
      workloadId: issued.session.workloadId,
      tenantId: issued.session.tenantId,
      certFingerprint256: issued.session.certFingerprint256,
      tokenHash: issued.session.tokenHash,
      expiresAt: issued.session.expiresAt,
      ...(issued.session.dpopKeyThumbprint
        ? {dpopKeyThumbprint: issued.session.dpopKeyThumbprint}
        : {})
    },
    scopes: sessionScopes
  })

  await runtime.appendAuditEvent({
    event: runtime.buildAuditEvent({
      correlationId,
      tenantId: mtls.tenant_id,
      event: {
        workload_id: mtls.workload_id,
        integration_id: null,
        event_type: 'session_issued',
        decision: null,
        action_group: null,
        risk_tier: null,
        destination: null,
        latency_ms: null,
        upstream_status_code: null,
        canonical_descriptor: null,
        message: 'Session issued',
        metadata: {
          scopes: sessionScopes,
          dpop_bound: Boolean(dpopJkt)
        }
      }
    })
  })

  const payload = OpenApiSessionResponseSchema.parse({
    session_token: issued.token,
    expires_at: issued.session.expiresAt,
    bound_cert_thumbprint: issued.session.certFingerprint256,
    ...(issued.session.dpopKeyThumbprint ? {dpop_jkt: issued.session.dpopKeyThumbprint} : {})
  })

  sendJson({
    response,
    status: 200,
    correlationId,
    payload
  })

  runtime.logger.info({
    event: 'session.issue.success',
    component: 'server.session',
    message: 'Session issued'
  })
}
