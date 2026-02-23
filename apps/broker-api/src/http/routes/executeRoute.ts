import {randomUUID} from 'node:crypto'

import {canonicalizeExecuteRequest} from '@broker-interceptor/canonicalizer'
import {forwardExecuteRequest} from '@broker-interceptor/forwarder'
import {setLogContextFields} from '@broker-interceptor/logging'
import {classifyPathGroup, evaluatePolicyDecision} from '@broker-interceptor/policy-engine'
import {
  OpenApiExecuteRequestSchema,
  OpenApiExecuteResponseApprovalRequiredSchema,
  OpenApiExecuteResponseExecutedSchema
} from '@broker-interceptor/schemas'
import {enforceRedirectDenyPolicy, guardExecuteRequestDestination} from '@broker-interceptor/ssrf-guard'

import {badRequest, conflict, isAppError, serviceUnavailable} from '../../errors'
import {parseJsonBody, sendJson} from '../../http'
import {isDataPlaneRepositoryError} from '../../repository'
import type {BrokerApiRouteLogicHandler} from './types'

const minimumForwarderIdempotencyTtlSeconds = 60
const maximumForwarderIdempotencyTtlSeconds = 60 * 60 * 24

export const handleExecuteRoute: BrokerApiRouteLogicHandler = async ({
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

  runtime.logger.info({
    event: 'execute.start',
    component: 'server.execute',
    message: 'Execute pipeline started'
  })

  try {
    await runtime.requireSessionContextWithLogging({
      request,
      repository: runtime.repository,
      mtls,
      config: runtime.config,
      pathname,
      requiredScope: 'execute'
    })
  } catch (error) {
    if (isAppError(error) && runtime.isDpopFailureReasonCode(error.code)) {
      state.executeAuditRecorded = true
      await runtime.appendDpopFailureAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        workloadId: mtls.workload_id,
        reasonCode: error.code,
        eventType: 'execute'
      })
    }

    throw error
  }

  const executeRequest = await parseJsonBody({
    request,
    schema: OpenApiExecuteRequestSchema,
    maxBodyBytes: runtime.config.maxBodyBytes,
    required: true
  })

  const integration = await runtime.repository.getIntegrationByTenantAndIdShared({
    tenantId: mtls.tenant_id,
    integrationId: executeRequest.integration_id
  })
  if (!integration) {
    throw badRequest('integration_not_found', 'Integration was not found for tenant')
  }

  if (!integration.enabled) {
    throw badRequest('integration_disabled', 'Integration is disabled')
  }
  setLogContextFields({
    integration_id: integration.integration_id
  })

  const ssrfStorageScope = {
    tenant_id: mtls.tenant_id,
    workload_id: mtls.workload_id,
    integration_id: integration.integration_id
  }

  let template = null
  if (runtime.repository.isSsrfTemplateLookupBridgeWiredShared()) {
    try {
      template = await runtime.repository.loadSsrfActiveTemplateForExecuteShared({
        scope: ssrfStorageScope
      })
    } catch (error) {
      runtime.reportPersistenceWarning({
        stage: 'ssrf_template_lookup',
        correlationId,
        error
      })
      throw serviceUnavailable(
        'ssrf_template_lookup_failed',
        'Unable to load active integration template for execute request'
      )
    }
  }

  if (!template) {
    template = await runtime.repository.getLatestTemplateByIdShared({
      tenantId: mtls.tenant_id,
      templateId: integration.template_id
    })
  }
  if (!template) {
    throw badRequest('template_not_found', 'Integration template was not found')
  }

  await runtime.repository.syncSsrfTemplateBindingShared({
    scope: ssrfStorageScope,
    template,
    now: runtime.now()
  })

  const canonicalized = canonicalizeExecuteRequest({
    context: {
      tenant_id: mtls.tenant_id,
      workload_id: mtls.workload_id,
      integration_id: integration.integration_id
    },
    template,
    execute_request: executeRequest
  })
  if (!canonicalized.ok) {
    throw badRequest(canonicalized.error.code, canonicalized.error.message)
  }

  const classification = classifyPathGroup({
    template,
    method: canonicalized.value.descriptor.method,
    canonical_url: canonicalized.value.descriptor.canonical_url
  })
  if (!classification.matched) {
    throw badRequest(classification.reason_code, 'No matching path group')
  }

  if (classification.path_group.group_id !== canonicalized.value.matched_path_group_id) {
    throw badRequest('descriptor_group_mismatch', 'Canonicalizer and classifier path groups diverged')
  }

  const policies = await runtime.repository.listPolicyRulesForDescriptorShared({
    descriptor: canonicalized.value.descriptor
  })
  const decision = await evaluatePolicyDecision({
    descriptor: canonicalized.value.descriptor,
    template,
    policies,
    now: runtime.now(),
    rateLimiter: async ({rule, key, now: rateLimitNow}) => {
      if (!rule.rate_limit) {
        return {allowed: true}
      }

      const outcome = await runtime.repository.incrementRateLimitCounterShared({
        key,
        intervalSeconds: rule.rate_limit.interval_seconds,
        maxRequests: rule.rate_limit.max_requests,
        now: rateLimitNow
      })
      return {allowed: outcome.allowed}
    }
  })

  runtime.logger.info({
    event: 'policy.decision',
    component: 'server.execute',
    message: `Policy decision: ${decision.decision}`,
    reason_code: decision.reason_code,
    metadata: {
      decision: decision.decision,
      action_group: decision.action_group
    }
  })

  state.executeAuditRecorded = true
  await runtime.appendAuditEvent({
    event: runtime.buildAuditEvent({
      correlationId,
      tenantId: mtls.tenant_id,
      event: {
        workload_id: mtls.workload_id,
        integration_id: integration.integration_id,
        event_type: 'policy_decision',
        decision: decision.decision,
        action_group: decision.action_group,
        risk_tier: decision.risk_tier,
        destination: {
          scheme: 'https',
          host: new URL(canonicalized.value.descriptor.canonical_url).hostname,
          port: 443,
          path_group: decision.action_group
        },
        latency_ms: null,
        upstream_status_code: null,
        canonical_descriptor: canonicalized.value.descriptor,
        policy: decision.policy_match
          ? {
              rule_id: decision.policy_match.policy_id ?? null,
              rule_type: decision.policy_match.rule_type,
              approval_id: null
            }
          : null,
        message: `Policy decision: ${decision.reason_code}`,
        metadata: {
          reason_code: decision.reason_code,
          trace: decision.trace
        }
      }
    })
  })

  if (decision.decision === 'denied') {
    runtime.logger.warn({
      event: 'execute.denied',
      component: 'server.execute',
      message: 'Execution denied by policy',
      reason_code: decision.reason_code
    })

    state.executeAuditRecorded = true
    await runtime.appendAuditEvent({
      event: runtime.buildAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        event: {
          workload_id: mtls.workload_id,
          integration_id: integration.integration_id,
          event_type: 'execute',
          decision: 'denied',
          action_group: decision.action_group,
          risk_tier: decision.risk_tier,
          destination: {
            scheme: 'https',
            host: new URL(canonicalized.value.descriptor.canonical_url).hostname,
            port: 443,
            path_group: decision.action_group
          },
          latency_ms: null,
          upstream_status_code: null,
          canonical_descriptor: canonicalized.value.descriptor,
          message: `Execution denied: ${decision.reason_code}`,
          metadata: {
            reason_code: decision.reason_code
          }
        }
      })
    })

    throw badRequest(decision.reason_code, 'Request denied by policy')
  }

  if (decision.decision === 'throttled') {
    runtime.logger.warn({
      event: 'execute.throttled',
      component: 'server.execute',
      message: 'Execution throttled by policy',
      reason_code: decision.reason_code
    })

    state.executeAuditRecorded = true
    await runtime.appendAuditEvent({
      event: runtime.buildAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        event: {
          workload_id: mtls.workload_id,
          integration_id: integration.integration_id,
          event_type: 'throttle',
          decision: 'throttled',
          action_group: decision.action_group,
          risk_tier: decision.risk_tier,
          destination: {
            scheme: 'https',
            host: new URL(canonicalized.value.descriptor.canonical_url).hostname,
            port: 443,
            path_group: decision.action_group
          },
          latency_ms: null,
          upstream_status_code: null,
          canonical_descriptor: canonicalized.value.descriptor,
          message: `Execution throttled: ${decision.reason_code}`,
          metadata: {
            reason_code: decision.reason_code,
            rate_limit: decision.rate_limit
          }
        }
      })
    })

    throw badRequest(decision.reason_code, 'Request throttled by policy')
  }

  if (decision.decision === 'approval_required') {
    runtime.logger.warn({
      event: 'execute.approval_required',
      component: 'server.execute',
      message: 'Execution requires approval',
      reason_code: decision.reason_code
    })

    const summary = runtime.repository.buildApprovalSummary({
      descriptor: canonicalized.value.descriptor,
      actionGroup: decision.action_group,
      riskTier: decision.risk_tier,
      integrationId: integration.integration_id
    })

    const approval = await runtime.repository.createOrReuseApprovalRequest({
      descriptor: canonicalized.value.descriptor,
      summary,
      correlationId,
      now: runtime.now()
    })

    state.executeAuditRecorded = true
    await runtime.appendAuditEvent({
      event: runtime.buildAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        event: {
          workload_id: mtls.workload_id,
          integration_id: integration.integration_id,
          event_type: 'approval_created',
          decision: 'approval_required',
          action_group: decision.action_group,
          risk_tier: decision.risk_tier,
          destination: {
            scheme: 'https',
            host: new URL(canonicalized.value.descriptor.canonical_url).hostname,
            port: 443,
            path_group: decision.action_group
          },
          latency_ms: null,
          upstream_status_code: null,
          canonical_descriptor: canonicalized.value.descriptor,
          policy: {
            rule_id: decision.policy_match?.policy_id ?? null,
            rule_type: decision.policy_match?.rule_type ?? 'approval_required',
            approval_id: approval.approval_id
          },
          message: `Approval required: ${approval.approval_id}`,
          metadata: {
            reason_code: decision.reason_code
          }
        }
      })
    })

    const payload = OpenApiExecuteResponseApprovalRequiredSchema.parse({
      status: 'approval_required',
      approval_id: approval.approval_id,
      expires_at: approval.expires_at,
      correlation_id: correlationId,
      summary: approval.summary
    })

    sendJson({
      response,
      status: 202,
      correlationId,
      payload
    })
    return
  }

  let ssrfResolvedIps: string[] = []
  const ssrfResult = await guardExecuteRequestDestination({
    input: {
      execute_request: executeRequest,
      template
    },
    options: {
      dns_resolver: async ({hostname}) => {
        const normalizedHost = hostname.trim().toLowerCase()
        const nowAtResolution = runtime.now()
        const cachedEntry = await runtime.repository.readSsrfDnsResolutionCacheShared({
          normalizedHost,
          now: nowAtResolution
        })

        if (cachedEntry) {
          const cacheAgeMs = nowAtResolution.getTime() - cachedEntry.resolved_at_epoch_ms
          const refreshThresholdMs = Math.max(1_000, Math.floor((cachedEntry.ttl_seconds * 1000) / 2))
          if (cacheAgeMs < refreshThresholdMs) {
            ssrfResolvedIps = runtime.normalizeResolvedIps(cachedEntry.resolved_ips)
            return ssrfResolvedIps
          }

          const refreshed = runtime.normalizeResolvedIps(
            await Promise.resolve(runtime.baseDnsResolver({hostname: normalizedHost}))
          )
          ssrfResolvedIps = refreshed

          if (!runtime.ipSetsEqual(refreshed, cachedEntry.resolved_ips)) {
            await runtime.repository.appendSsrfDnsRebindingObservationShared({
              normalizedHost,
              resolvedIps: refreshed,
              now: nowAtResolution
            })
          }

          if (refreshed.length > 0) {
            await runtime.repository.writeSsrfDnsResolutionCacheShared({
              normalizedHost,
              resolvedIps: refreshed,
              now: nowAtResolution,
              ttlSeconds: cachedEntry.ttl_seconds
            })
          }

          return refreshed
        }

        const resolved = runtime.normalizeResolvedIps(
          await Promise.resolve(runtime.baseDnsResolver({hostname: normalizedHost}))
        )
        ssrfResolvedIps = resolved

        if (resolved.length > 0) {
          await runtime.repository.writeSsrfDnsResolutionCacheShared({
            normalizedHost,
            resolvedIps: resolved,
            now: nowAtResolution
          })
        }

        return resolved
      },
      dns_resolution: {
        timeout_ms: runtime.config.dns_timeout_ms
      }
    }
  })

  if (!ssrfResult.ok) {
    const destination = runtime.parseDestinationFromRequestUrl(canonicalized.value.descriptor.canonical_url)
    await runtime.appendSsrfDecisionProjectionBestEffort({
      projection: {
        event_id: `ssrf_${randomUUID()}`,
        timestamp: runtime.now().toISOString(),
        tenant_id: mtls.tenant_id,
        workload_id: mtls.workload_id,
        integration_id: integration.integration_id,
        template_id: template.template_id,
        template_version: template.version,
        destination_host: destination.host,
        destination_port: destination.port,
        resolved_ips: ssrfResolvedIps,
        decision: 'denied',
        reason_code: ssrfResult.error.code,
        correlation_id: correlationId
      },
      correlationId,
      stage: 'ssrf_decision_projection_denied'
    })

    state.executeAuditRecorded = true
    await runtime.appendAuditEvent({
      event: runtime.buildAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        event: {
          workload_id: mtls.workload_id,
          integration_id: integration.integration_id,
          event_type: 'execute',
          decision: 'denied',
          action_group: decision.action_group,
          risk_tier: decision.risk_tier,
          destination: {
            scheme: 'https',
            host: new URL(canonicalized.value.descriptor.canonical_url).hostname,
            port: 443,
            path_group: decision.action_group
          },
          latency_ms: null,
          upstream_status_code: null,
          canonical_descriptor: canonicalized.value.descriptor,
          message: ssrfResult.error.message,
          metadata: {
            reason_code: ssrfResult.error.code
          }
        }
      })
    })

    throw badRequest(ssrfResult.error.code, ssrfResult.error.message)
  }

  await runtime.appendSsrfDecisionProjectionBestEffort({
    projection: {
      event_id: `ssrf_${randomUUID()}`,
      timestamp: runtime.now().toISOString(),
      tenant_id: mtls.tenant_id,
      workload_id: mtls.workload_id,
      integration_id: integration.integration_id,
      template_id: template.template_id,
      template_version: template.version,
      destination_host: ssrfResult.value.destination.host,
      destination_port: ssrfResult.value.destination.port,
      resolved_ips: ssrfResult.value.resolved_ips,
      decision: 'allowed',
      reason_code: template.network_safety.dns_resolution_required
        ? 'dns_resolution_required'
        : 'invalid_input',
      correlation_id: correlationId
    },
    correlationId,
    stage: 'ssrf_decision_projection_allowed'
  })

  const idempotencyKey = executeRequest.client_context?.idempotency_key?.trim()
  let forwarderPersistenceContext: {
    scope: {
      tenant_id: string
      workload_id: string
      integration_id: string
      action_group: string
      idempotency_key: string
    }
    lock_token: string
    idempotency_record_created: boolean
    finalized: boolean
  } | null = null

  if (idempotencyKey) {
    if (!runtime.repository.isForwarderPersistenceEnabledShared()) {
      throw serviceUnavailable(
        'forwarder_persistence_unavailable',
        'Idempotency key was provided but forwarder persistence is not configured'
      )
    }

    const scope = {
      tenant_id: mtls.tenant_id,
      workload_id: mtls.workload_id,
      integration_id: integration.integration_id,
      action_group: decision.action_group,
      idempotency_key: idempotencyKey
    }

    const lockTtlMs = runtime.clamp({
      value: runtime.config.forwarder.total_timeout_ms + 1000,
      min: 1000,
      max: maximumForwarderIdempotencyTtlSeconds * 1000
    })
    const lockResult = await runtime.repository.acquireForwarderExecutionLockShared({
      scope,
      ttlMs: lockTtlMs
    })

    if (!lockResult.acquired) {
      throw conflict(
        'forwarder_execution_locked',
        'Execute request is already in progress for the provided idempotency key'
      )
    }

    forwarderPersistenceContext = {
      scope,
      lock_token: lockResult.lock_token,
      idempotency_record_created: false,
      finalized: false
    }
  }

  try {
    if (forwarderPersistenceContext) {
      const idempotencyTtlSeconds = runtime.clamp({
        value: Math.ceil(runtime.config.forwarder.total_timeout_ms / 1000) * 2,
        min: minimumForwarderIdempotencyTtlSeconds,
        max: maximumForwarderIdempotencyTtlSeconds
      })

      const idempotencyFingerprint = runtime.toForwarderIdempotencyFingerprint({
        descriptor: canonicalized.value.descriptor as unknown as Record<string, unknown>,
        request: executeRequest.request as unknown as Record<string, unknown>
      })

      const idempotencyResult = await runtime.repository.createForwarderIdempotencyRecordShared({
        scope: forwarderPersistenceContext.scope,
        requestFingerprintSha256: idempotencyFingerprint,
        correlationId,
        expiresAt: new Date(runtime.now().getTime() + idempotencyTtlSeconds * 1000).toISOString()
      })

      if (!idempotencyResult.created) {
        const existingRecord = await runtime.repository.getForwarderIdempotencyRecordShared({
          scope: forwarderPersistenceContext.scope
        })

        if (idempotencyResult.conflict === 'fingerprint_mismatch') {
          throw conflict(
            'idempotency_key_conflict',
            'Idempotency key is already bound to a different execute request fingerprint'
          )
        }

        if (existingRecord?.state === 'in_progress') {
          throw conflict(
            'idempotency_request_in_progress',
            'An execute request with the same idempotency key is already in progress'
          )
        }

        throw conflict(
          'idempotency_key_reused',
          `Idempotency key cannot be reused while previous request state is ${existingRecord?.state ?? 'unknown'}`
        )
      }

      forwarderPersistenceContext.idempotency_record_created = true
    }

    let injectedHeaders
    try {
      injectedHeaders = await runtime.repository.getInjectedHeadersForIntegrationShared({
        tenantId: mtls.tenant_id,
        integrationId: integration.integration_id,
        correlationId
      })
    } catch (error) {
      if (isDataPlaneRepositoryError(error) && error.code === 'integration_secret_unavailable') {
        state.executeAuditRecorded = true
        await runtime.appendAuditEvent({
          event: runtime.buildAuditEvent({
            correlationId,
            tenantId: mtls.tenant_id,
            event: {
              workload_id: mtls.workload_id,
              integration_id: integration.integration_id,
              event_type: 'execute',
              decision: 'denied',
              action_group: decision.action_group,
              risk_tier: decision.risk_tier,
              destination: {
                scheme: 'https',
                host: ssrfResult.value.destination.host,
                port: ssrfResult.value.destination.port,
                path_group: decision.action_group
              },
              latency_ms: null,
              upstream_status_code: null,
              canonical_descriptor: canonicalized.value.descriptor,
              message: 'Execution denied: integration secret is unavailable',
              metadata: {
                reason_code: error.code
              }
            }
          })
        })

        throw serviceUnavailable(
          'integration_secret_unavailable',
          'Integration secret material is unavailable for execute request'
        )
      }

      throw error
    }

    const forwardResult = await forwardExecuteRequest({
      input: {
        execute_request: executeRequest,
        template,
        matched_path_group_id: canonicalized.value.matched_path_group_id,
        injected_headers: injectedHeaders,
        correlation_id: correlationId,
        timeouts: {
          total_timeout_ms: runtime.config.forwarder.total_timeout_ms
        },
        limits: {
          max_request_body_bytes: runtime.config.forwarder.max_request_body_bytes,
          max_response_bytes: runtime.config.forwarder.max_response_bytes
        }
      },
      ...(runtime.fetchImpl ? {fetchImpl: runtime.fetchImpl} : {})
    })

    if (!forwardResult.ok) {
      state.executeAuditRecorded = true
      await runtime.appendAuditEvent({
        event: runtime.buildAuditEvent({
          correlationId,
          tenantId: mtls.tenant_id,
          event: {
            workload_id: mtls.workload_id,
            integration_id: integration.integration_id,
            event_type: 'execute',
            decision: 'denied',
            action_group: decision.action_group,
            risk_tier: decision.risk_tier,
            destination: {
              scheme: 'https',
              host: ssrfResult.value.destination.host,
              port: ssrfResult.value.destination.port,
              path_group: decision.action_group
            },
            latency_ms: null,
            upstream_status_code: null,
            canonical_descriptor: canonicalized.value.descriptor,
            message: forwardResult.error.message,
            metadata: {
              reason_code: forwardResult.error.code
            }
          }
        })
      })

      throw badRequest(forwardResult.error.code, forwardResult.error.message)
    }

    const redirectCheck = enforceRedirectDenyPolicy({
      input: {
        template,
        upstream_status_code: forwardResult.value.upstream.status_code,
        upstream_headers: forwardResult.value.upstream.headers
      }
    })
    if (!redirectCheck.ok) {
      throw badRequest(redirectCheck.error.code, redirectCheck.error.message)
    }

    if (forwarderPersistenceContext && !forwarderPersistenceContext.finalized) {
      const completeResult = await runtime.repository.completeForwarderIdempotencyRecordShared({
        scope: forwarderPersistenceContext.scope,
        correlationId,
        upstreamStatusCode: forwardResult.value.upstream.status_code,
        responseBytes: runtime.decodedBase64ByteLength(forwardResult.value.upstream.body_base64)
      })

      if (!completeResult.updated) {
        throw serviceUnavailable(
          'forwarder_idempotency_complete_failed',
          'Failed to finalize execute idempotency state'
        )
      }
      forwarderPersistenceContext.finalized = true
    }

    state.executeAuditRecorded = true
    await runtime.appendAuditEvent({
      event: runtime.buildAuditEvent({
        correlationId,
        tenantId: mtls.tenant_id,
        event: {
          workload_id: mtls.workload_id,
          integration_id: integration.integration_id,
          event_type: 'execute',
          decision: 'allowed',
          action_group: decision.action_group,
          risk_tier: decision.risk_tier,
          destination: {
            scheme: ssrfResult.value.destination.scheme,
            host: ssrfResult.value.destination.host,
            port: ssrfResult.value.destination.port,
            path_group: decision.action_group
          },
          latency_ms: null,
          upstream_status_code: forwardResult.value.upstream.status_code,
          canonical_descriptor: canonicalized.value.descriptor,
          policy: decision.policy_match
            ? {
                rule_id: decision.policy_match.policy_id ?? null,
                rule_type: decision.policy_match.rule_type,
                approval_id: null
              }
            : null,
          message: 'Execution forwarded successfully',
          metadata: {
            resolved_ips: ssrfResult.value.resolved_ips
          }
        }
      })
    })

    const payload = OpenApiExecuteResponseExecutedSchema.parse(forwardResult.value)
    sendJson({
      response,
      status: 200,
      correlationId,
      payload
    })

    runtime.logger.info({
      event: 'execute.completed',
      component: 'server.execute',
      message: 'Execution completed',
      status_code: payload.upstream.status_code
    })
  } catch (error) {
    if (
      forwarderPersistenceContext &&
      forwarderPersistenceContext.idempotency_record_created &&
      !forwarderPersistenceContext.finalized
    ) {
      const errorCode = isAppError(error) ? error.code : 'forwarder_execute_error'
      try {
        const failResult = await runtime.repository.failForwarderIdempotencyRecordShared({
          scope: forwarderPersistenceContext.scope,
          correlationId,
          errorCode
        })
        forwarderPersistenceContext.finalized = failResult.updated
      } catch (storeError) {
        runtime.reportPersistenceWarning({
          stage: 'forwarder_idempotency_fail_finalize',
          correlationId,
          error: storeError
        })
      }
    }

    throw error
  } finally {
    if (forwarderPersistenceContext) {
      try {
        await runtime.repository.releaseForwarderExecutionLockShared({
          scope: forwarderPersistenceContext.scope,
          lockToken: forwarderPersistenceContext.lock_token
        })
      } catch (storeError) {
        runtime.reportPersistenceWarning({
          stage: 'forwarder_execution_lock_release',
          correlationId,
          error: storeError
        })
      }
    }
  }
}
