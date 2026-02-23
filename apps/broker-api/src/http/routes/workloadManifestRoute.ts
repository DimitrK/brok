import {signManifest, UnsignedManifestSchema} from '@broker-interceptor/crypto'
import {setLogContextFields} from '@broker-interceptor/logging'
import {OpenApiManifestSchema} from '@broker-interceptor/schemas'

import {badRequest, internal, isAppError, unauthorized} from '../../errors'
import {decodePathParam, sendJson} from '../../http'
import type {BrokerApiRouteLogicHandler} from './types'

const workloadManifestPathPattern = /^\/v1\/workloads\/([^/]+)\/manifest$/u

export const isWorkloadManifestPath = (pathname: string) => workloadManifestPathPattern.test(pathname)

const matchWorkloadManifestPath = (pathname: string) => pathname.match(workloadManifestPathPattern)

export const handleWorkloadManifestRoute: BrokerApiRouteLogicHandler = async ({
  request,
  response,
  correlationId,
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

  const manifestMatch = matchWorkloadManifestPath(pathname)
  if (!manifestMatch) {
    throw badRequest('route_not_found', `Unsupported route GET ${pathname}`)
  }

  const requestedWorkloadId = decodePathParam(manifestMatch[1])
  if (requestedWorkloadId !== mtls.workload_id) {
    throw unauthorized('manifest_workload_mismatch', 'Manifest workload id must match mTLS workload identity')
  }

  await runtime.requireSessionContextWithLogging({
    request,
    repository: runtime.repository,
    mtls,
    config: runtime.config,
    pathname,
    requiredScope: 'manifest.read'
  }).catch(async error => {
    if (isAppError(error) && runtime.isDpopFailureReasonCode(error.code)) {
      await runtime.appendDpopFailureAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        workloadId: mtls.workload_id,
        reasonCode: error.code,
        eventType: 'execute'
      })
    }

    throw error
  })

  const manifestRules = await runtime.repository.listManifestTemplateRulesForTenantShared({
    tenantId: mtls.tenant_id
  })
  if (manifestRules.length === 0) {
    throw badRequest('manifest_no_rules', 'No manifest rules are available for this workload')
  }

  const nowDate = runtime.now()
  const dpopRequiredForManifest = runtime.isDpopRequiredForIdentity({
    tenantId: mtls.tenant_id,
    workloadId: mtls.workload_id
  })
  const unsignedManifest = UnsignedManifestSchema.parse({
    manifest_version: 1,
    issued_at: nowDate.toISOString(),
    expires_at: new Date(nowDate.getTime() + runtime.repository.getManifestTtlSeconds() * 1000).toISOString(),
    broker_execute_url: new URL('/v1/execute', runtime.config.publicBaseUrl).toString(),
    dpop_required: dpopRequiredForManifest,
    dpop_ath_required: dpopRequiredForManifest,
    match_rules: manifestRules.map(rule => ({
      integration_id: rule.integration_id,
      provider: rule.provider,
      match: {
        hosts: rule.hosts,
        schemes: rule.schemes,
        ports: rule.ports,
        path_groups: rule.path_groups
      },
      rewrite: {
        mode: 'execute',
        send_intended_url: true
      }
    }))
  })

  const signedManifest = await signManifest({
    manifest: unsignedManifest,
    signing_key: await runtime.repository.getManifestSigningPrivateKeyShared()
  })
  if (!signedManifest.ok) {
    throw internal(signedManifest.error.code, signedManifest.error.message)
  }

  const payload = OpenApiManifestSchema.parse(signedManifest.value)
  runtime.logger.info({
    event: 'manifest.issued',
    component: 'server.manifest',
    message: 'Manifest issued'
  })

  await runtime.appendAuditEvent({
    event: runtime.buildAuditEvent({
      correlationId,
      tenantId: mtls.tenant_id,
      event: {
        workload_id: mtls.workload_id,
        integration_id: null,
        event_type: 'execute',
        decision: null,
        action_group: null,
        risk_tier: null,
        destination: null,
        latency_ms: null,
        upstream_status_code: null,
        canonical_descriptor: null,
        message: 'Manifest issued',
        metadata: {
          workload_id: requestedWorkloadId,
          dpop_required: payload.dpop_required ?? false
        }
      }
    })
  })

  sendJson({
    response,
    status: 200,
    correlationId,
    payload
  })
}
