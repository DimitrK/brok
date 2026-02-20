import {createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse} from 'node:http';
import {createHash, randomUUID} from 'node:crypto';
import {lookup as dnsLookup} from 'node:dns/promises';
import {BlockList, isIP} from 'node:net';
import type {TLSSocket} from 'node:tls';

import {type AuditService} from '@broker-interceptor/audit';
import {
  issueSession,
  SessionInputValidationError,
  verifyBoundDpopProofJwt,
  verifyDpopProofJwt,
  verifyMtls,
  verifySessionBinding,
  extractWorkloadPrincipal,
  hashToken
} from '@broker-interceptor/auth';
import {canonicalizeExecuteRequest} from '@broker-interceptor/canonicalizer';
import {signManifest, UnsignedManifestSchema} from '@broker-interceptor/crypto';
import {forwardExecuteRequest, type FetchLike} from '@broker-interceptor/forwarder';
import {
  createNoopLogger,
  runWithLogContext,
  setLogContextFields,
  type StructuredLogger
} from '@broker-interceptor/logging';
import {classifyPathGroup, evaluatePolicyDecision} from '@broker-interceptor/policy-engine';
import {
  OpenApiAuditEventSchema,
  OpenApiExecuteRequestSchema,
  OpenApiExecuteResponseApprovalRequiredSchema,
  OpenApiExecuteResponseExecutedSchema,
  OpenApiManifestKeysSchema,
  OpenApiManifestSchema,
  OpenApiSessionRequestSchema,
  OpenApiSessionResponseSchema,
  type OpenApiAuditEvent
} from '@broker-interceptor/schemas';
import {
  enforceRedirectDenyPolicy,
  guardExecuteRequestDestination,
  type DnsResolver
} from '@broker-interceptor/ssrf-guard';

import type {ServiceConfig} from './config';
import {badRequest, conflict, internal, isAppError, unauthorized, serviceUnavailable} from './errors';
import {decodePathParam, extractCorrelationId, parseJsonBody, sendError, sendJson} from './http';
import {DataPlaneRepository, isDataPlaneRepositoryError} from './repository';

const SESSION_SCOPES = new Set(['execute', 'manifest.read']);
const manifestPathPattern = /^\/v1\/workloads\/([^/]+)\/manifest$/u;
const minimumForwarderIdempotencyTtlSeconds = 60;
const maximumForwarderIdempotencyTtlSeconds = 60 * 60 * 24;

const parseUrl = (request: IncomingMessage) => {
  const host = request.headers.host ?? 'localhost';
  return new URL(request.url ?? '/', `https://${host}`);
};

const getSingleHeaderValue = ({
  request,
  name
}: {
  request: IncomingMessage;
  name: 'authorization' | 'dpop';
}): string | undefined => {
  const headerValue = name === 'authorization' ? request.headers.authorization : request.headers.dpop;
  if (!headerValue) {
    return undefined;
  }

  if (Array.isArray(headerValue)) {
    if (headerValue.length === 0) {
      return undefined;
    }

    return headerValue[0];
  }

  return headerValue;
};

const parseBearerToken = ({request}: {request: IncomingMessage}) => {
  const authorizationHeader = getSingleHeaderValue({request, name: 'authorization'});
  if (!authorizationHeader) {
    throw unauthorized('session_missing', 'Authorization bearer token is required');
  }

  const match = /^Bearer\s+(.+)$/u.exec(authorizationHeader);
  if (!match) {
    throw unauthorized('session_missing', 'Authorization must use Bearer scheme');
  }

  const token = match[1]?.trim();
  if (!token) {
    throw unauthorized('session_missing', 'Authorization bearer token is required');
  }

  return token;
};

const normalizeRemoteAddress = (value: string) => {
  if (value.startsWith('::ffff:')) {
    return value.slice(7);
  }

  return value;
};

const matchesCidr = ({ip, cidr}: {ip: string; cidr: string}) => {
  const [base, maskText] = cidr.split('/', 2);
  if (!base || !maskText) {
    return false;
  }

  const ipFamily = isIP(ip);
  const baseFamily = isIP(base);
  if (ipFamily === 0 || baseFamily === 0 || ipFamily !== baseFamily) {
    return false;
  }

  const mask = Number.parseInt(maskText, 10);
  if (Number.isNaN(mask)) {
    return false;
  }

  const maxMask = ipFamily === 4 ? 32 : 128;
  if (mask < 0 || mask > maxMask) {
    return false;
  }

  const blockList = new BlockList();
  blockList.addSubnet(base, mask, ipFamily === 4 ? 'ipv4' : 'ipv6');
  return blockList.check(ip, ipFamily === 4 ? 'ipv4' : 'ipv6');
};

const isRemoteIpAllowed = ({remoteIp, allowlist}: {remoteIp: string; allowlist: string[]}) => {
  const normalizedIp = normalizeRemoteAddress(remoteIp);
  return allowlist.some(entry => {
    if (entry.includes('/')) {
      return matchesCidr({ip: normalizedIp, cidr: entry});
    }

    return normalizeRemoteAddress(entry) === normalizedIp;
  });
};

type MtlsAuthContext = {
  tenant_id: string;
  workload_id: string;
  cert_fingerprint256: string;
  san_uri: string;
};

const requireMtlsContext = async ({
  request,
  repository,
  expectedSanUriPrefix
}: {
  request: IncomingMessage;
  repository: DataPlaneRepository;
  expectedSanUriPrefix?: string;
}): Promise<MtlsAuthContext> => {
  const tlsSocket = request.socket as TLSSocket;
  const principal = extractWorkloadPrincipal({tlsSocket});
  const mtlsCheck = verifyMtls({
    principal,
    ...(expectedSanUriPrefix ? {expectedSanUriPrefix} : {})
  });

  if (!mtlsCheck.ok || !principal.sanUri || !principal.certFingerprint256) {
    throw unauthorized('mtls_required', mtlsCheck.ok ? 'mTLS authentication failed' : mtlsCheck.error);
  }

  const workload = await repository.getWorkloadBySanUriShared({sanUri: principal.sanUri});
  if (!workload || !workload.enabled) {
    throw unauthorized('workload_disabled', 'Workload is disabled or unknown');
  }

  if (workload.ip_allowlist && workload.ip_allowlist.length > 0) {
    const remoteAddress = tlsSocket.remoteAddress;
    if (!remoteAddress) {
      throw unauthorized('workload_ip_denied', 'Remote IP is unavailable for allowlist enforcement');
    }

    if (!isRemoteIpAllowed({remoteIp: remoteAddress, allowlist: workload.ip_allowlist})) {
      throw unauthorized('workload_ip_denied', 'Remote IP is not in workload allowlist');
    }
  }

  return {
    tenant_id: workload.tenant_id,
    workload_id: workload.workload_id,
    cert_fingerprint256: principal.certFingerprint256,
    san_uri: principal.sanUri
  };
};

type SessionContext = {
  session_token: string;
  session: {
    session_id: string;
    workload_id: string;
    tenant_id: string;
    cert_fingerprint256: string;
    token_hash: string;
    expires_at: string;
    dpop_jkt?: string;
    scopes: string[];
  };
};

const buildPublicRouteUrl = ({config, pathname}: {config: ServiceConfig; pathname: string}) =>
  new URL(pathname, config.publicBaseUrl).toString();

const requireSessionContext = async ({
  request,
  repository,
  mtls,
  config,
  pathname,
  requiredScope
}: {
  request: IncomingMessage;
  repository: DataPlaneRepository;
  mtls: MtlsAuthContext;
  config: ServiceConfig;
  pathname: string;
  requiredScope: 'execute' | 'manifest.read';
}): Promise<SessionContext> => {
  const token = parseBearerToken({request});
  const session = await repository.getSessionByTokenHashShared({tokenHash: hashToken(token)});
  if (!session) {
    throw unauthorized('session_invalid', 'Session token is invalid or expired');
  }

  if (session.workload_id !== mtls.workload_id || session.tenant_id !== mtls.tenant_id) {
    throw unauthorized('session_scope_invalid', 'Session does not match mTLS workload identity');
  }

  if (!session.scopes.includes(requiredScope)) {
    throw unauthorized('session_scope_missing', `Session does not grant ${requiredScope}`);
  }

  const dpopRequiredByIdentity = isDpopRequiredForIdentity({
    repository,
    tenantId: mtls.tenant_id,
    workloadId: mtls.workload_id
  });
  const sessionRequiresDpop = Boolean(session.dpop_jkt);

  let dpopJkt: string | undefined;
  if (dpopRequiredByIdentity || sessionRequiresDpop) {
    if (!session.dpop_jkt) {
      throw unauthorized('session_dpop_required', 'Workload or tenant policy requires DPoP-bound sessions');
    }

    const dpopJwt = getSingleHeaderValue({request, name: 'dpop'});
    if (!dpopJwt) {
      throw unauthorized('dpop_missing', 'DPoP proof is required');
    }

    const dpopResult = await verifyBoundDpopProofJwt({
      dpopJwt,
      method: request.method ?? 'GET',
      url: buildPublicRouteUrl({config, pathname}),
      expectedJkt: session.dpop_jkt,
      accessToken: token,
      tenantId: mtls.tenant_id,
      sessionId: session.session_id,
      jtiStore: repository.getDpopReplayStore(),
      maxSkewSeconds: config.dpopMaxSkewSeconds,
      replayTtlSeconds: config.dpopMaxSkewSeconds
    });

    if (!dpopResult.ok) {
      throw unauthorized(dpopResult.error, 'DPoP verification failed');
    }

    dpopJkt = dpopResult.jkt;
  }

  const bindingResult = verifySessionBinding({
    session: {
      sessionId: session.session_id,
      workloadId: session.workload_id,
      tenantId: session.tenant_id,
      certFingerprint256: session.cert_fingerprint256,
      tokenHash: session.token_hash,
      expiresAt: session.expires_at,
      ...(session.dpop_jkt ? {dpopKeyThumbprint: session.dpop_jkt} : {})
    },
    certFingerprint256: mtls.cert_fingerprint256,
    ...(dpopJkt ? {dpopKeyThumbprint: dpopJkt} : {})
  });

  if (!bindingResult.ok) {
    const bindingErrorCode =
      'error' in bindingResult ? (bindingResult.error ?? 'session_binding_invalid') : 'session_binding_invalid';
    throw unauthorized(bindingErrorCode, 'Session binding validation failed');
  }

  return {
    session_token: token,
    session
  };
};

const buildAuditEvent = ({
  repository,
  correlationId,
  tenantId,
  event
}: {
  repository: DataPlaneRepository;
  correlationId: string;
  tenantId: string;
  event: Omit<OpenApiAuditEvent, 'event_id' | 'timestamp' | 'tenant_id' | 'correlation_id'>;
}) =>
  OpenApiAuditEventSchema.parse({
    event_id: repository.createEventId(),
    timestamp: repository.getNowIso(),
    tenant_id: tenantId,
    correlation_id: correlationId,
    ...event
  });

const appendAuditEvent = async ({auditService, event}: {auditService: AuditService; event: OpenApiAuditEvent}) => {
  const result = await auditService.appendAuditEvent({event});
  if (!result.ok) {
    throw serviceUnavailable('audit_write_failed', result.error.message);
  }
};

const DPOP_FAILURE_REASON_CODES = new Set([
  'dpop_missing',
  'dpop_invalid',
  'dpop_invalid_header',
  'dpop_invalid_claims',
  'dpop_http_method_mismatch',
  'dpop_htu_mismatch',
  'dpop_ath_mismatch',
  'dpop_jkt_mismatch',
  'dpop_signature_invalid',
  'dpop_replay',
  'dpop_iat_invalid',
  'dpop_verification_error',
  'session_dpop_required'
]);

const isDpopFailureReasonCode = (value: string) => DPOP_FAILURE_REASON_CODES.has(value) || value.startsWith('dpop_');

const appendDpopFailureAuditEvent = async ({
  repository,
  auditService,
  correlationId,
  tenantId,
  workloadId,
  reasonCode,
  eventType
}: {
  repository: DataPlaneRepository;
  auditService: AuditService;
  correlationId: string;
  tenantId: string;
  workloadId: string;
  reasonCode: string;
  eventType: 'session_issued' | 'execute';
}) =>
  appendAuditEvent({
    auditService,
    event: buildAuditEvent({
      repository,
      correlationId,
      tenantId,
      event: {
        workload_id: workloadId,
        integration_id: null,
        event_type: eventType,
        decision: 'denied',
        action_group: null,
        risk_tier: null,
        destination: null,
        latency_ms: null,
        upstream_status_code: null,
        canonical_descriptor: null,
        message: `DPoP authentication failed: ${reasonCode}`,
        metadata: {
          reason_code: reasonCode
        }
      }
    })
  });

const isDpopRequiredForIdentity = ({
  repository,
  tenantId,
  workloadId
}: {
  repository: DataPlaneRepository;
  tenantId: string;
  workloadId: string;
}) => repository.isWorkloadDpopRequired({workloadId}) || repository.isTenantDpopRequired({tenantId});

const toForwarderIdempotencyFingerprint = ({
  descriptor,
  request
}: {
  descriptor: Record<string, unknown>;
  request: Record<string, unknown>;
}) =>
  createHash('sha256')
    .update(
      JSON.stringify({
        descriptor,
        request
      }),
      'utf8'
    )
    .digest('hex');

const decodedBase64ByteLength = (value: string) => {
  const normalized = value.trim();
  if (normalized.length === 0) {
    return 0;
  }
  const padding = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - padding);
};

const clamp = ({value, min, max}: {value: number; min: number; max: number}) => Math.min(max, Math.max(min, value));

const normalizeResolvedIps = (value: string[]) =>
  Array.from(new Set(value.map(item => item.trim()).filter(item => item.length > 0))).sort((left, right) =>
    left.localeCompare(right)
  );

const ipSetsEqual = (left: string[], right: string[]) => {
  const normalizedLeft = normalizeResolvedIps(left);
  const normalizedRight = normalizeResolvedIps(right);
  return normalizedLeft.join('|') === normalizedRight.join('|');
};

const parseDestinationFromRequestUrl = (rawUrl: string) => {
  const parsed = new URL(rawUrl);
  const port = parsed.port.length > 0 ? Number.parseInt(parsed.port, 10) : 443;
  return {
    host: parsed.hostname.toLowerCase(),
    port
  };
};

const reportPersistenceWarning = ({
  logger,
  stage,
  correlationId,
  error
}: {
  logger: StructuredLogger;
  stage: string;
  correlationId: string;
  error: unknown;
}) => {
  const reasonCode = isAppError(error) ? error.code : error instanceof Error ? error.name : 'unknown_error';
  logger.warn({
    event: 'repository.persistence.warning',
    component: 'repository.persistence',
    message: `Non-blocking persistence operation failed (${stage})`,
    correlation_id: correlationId,
    reason_code: reasonCode,
    metadata: {
      warning_code: 'BROKER_API_PERSISTENCE_WARNING'
    }
  });
};

export type CreateBrokerApiServerInput = {
  config: ServiceConfig;
  repository: DataPlaneRepository;
  auditService: AuditService;
  logger?: StructuredLogger;
  fetchImpl?: FetchLike;
  dnsResolver?: DnsResolver;
  now?: () => Date;
};

export const createBrokerApiRequestHandler = ({
  config,
  repository,
  auditService,
  logger = createNoopLogger(),
  fetchImpl,
  dnsResolver,
  now = () => new Date()
}: CreateBrokerApiServerInput) => {
  const baseDnsResolver: DnsResolver =
    dnsResolver ??
    (async ({hostname}) => {
      const records = await dnsLookup(hostname, {all: true, verbatim: true});
      return records.map(record => record.address);
    });

  const handleRequest = async (request: IncomingMessage, response: ServerResponse) => {
    const correlationId = extractCorrelationId(request);
    const requestId = randomUUID();
    const startedAtMs = now().getTime();
    const requestMethod = request.method ?? 'GET';

    return runWithLogContext(
      {
        correlation_id: correlationId,
        request_id: requestId,
        method: requestMethod
      },
      async () => {
        let method = requestMethod;
        let pathname = '/';
        let mtlsContext: MtlsAuthContext | null = null;
        let executeAuditRecorded = false;
        let responseReasonCode: string | undefined;

        logger.info({
          event: 'request.received',
          component: 'http.server',
          message: 'Request received',
          route: request.url ?? '/',
          method: requestMethod
        });

        try {
          method = requestMethod;
          const url = parseUrl(request);
          pathname = url.pathname;
          setLogContextFields({
            route: pathname,
            method
          });

          if (method === 'GET' && pathname === '/healthz') {
            sendJson({
              response,
              status: 200,
              correlationId,
              payload: {status: 'ok'}
            });
            return;
          }

      // Public endpoint for manifest signing keys (requires mTLS but not session)
      if (method === 'GET' && pathname === '/v1/keys/manifest') {
        // Require mTLS but not a session token - keys are public material
        await requireMtlsContext({
          request,
          repository,
          ...(config.expectedSanUriPrefix ? {expectedSanUriPrefix: config.expectedSanUriPrefix} : {})
        });

        const manifestKeys = await repository.getManifestVerificationKeysShared();
        const payload = OpenApiManifestKeysSchema.parse(manifestKeys);

        sendJson({
          response,
          status: 200,
          correlationId,
          payload,
          headers: {
            'cache-control': 'public, max-age=60, must-revalidate'
          }
        });
        return;
      }

      const mtls = await requireMtlsContext({
        request,
        repository,
        ...(config.expectedSanUriPrefix ? {expectedSanUriPrefix: config.expectedSanUriPrefix} : {})
      });
      mtlsContext = mtls;
      setLogContextFields({
        tenant_id: mtls.tenant_id,
        workload_id: mtls.workload_id
      });

      if (method === 'POST' && pathname === '/v1/session') {
        logger.info({
          event: 'session.issue.start',
          component: 'server.session',
          message: 'Session issuance started'
        });
        const body = await parseJsonBody({
          request,
          schema: OpenApiSessionRequestSchema,
          maxBodyBytes: config.maxBodyBytes,
          required: true
        });

        const sessionTtlSeconds = body.requested_ttl_seconds ?? config.sessionDefaultTtlSeconds;
        const sessionScopes = repository.buildSessionScopes({requestedScopes: body.scopes});
        const invalidScopes = sessionScopes.filter(scope => !SESSION_SCOPES.has(scope));
        if (invalidScopes.length > 0) {
          throw badRequest('session_scope_invalid', `Unsupported session scopes: ${invalidScopes.join(',')}`);
        }

        const dpopRequiredByIdentity = isDpopRequiredForIdentity({
          repository,
          tenantId: mtls.tenant_id,
          workloadId: mtls.workload_id
        });
        const dpopJwt = getSingleHeaderValue({request, name: 'dpop'});

        let dpopJkt: string | undefined;
        if (dpopJwt) {
          const dpopResult = await verifyDpopProofJwt({
            dpopJwt,
            method,
            url: buildPublicRouteUrl({config, pathname}),
            tenantId: mtls.tenant_id,
            sessionId: mtls.workload_id,
            jtiStore: repository.getDpopReplayStore(),
            maxSkewSeconds: config.dpopMaxSkewSeconds,
            replayTtlSeconds: config.dpopMaxSkewSeconds
          });
          if (!dpopResult.ok) {
            await appendDpopFailureAuditEvent({
              repository,
              auditService,
              correlationId,
              tenantId: mtls.tenant_id,
              workloadId: mtls.workload_id,
              reasonCode: dpopResult.error,
              eventType: 'session_issued'
            });
            throw unauthorized(dpopResult.error, 'DPoP verification failed');
          }

          dpopJkt = dpopResult.jkt;
        }

        if (dpopRequiredByIdentity && !dpopJkt) {
          await appendDpopFailureAuditEvent({
            repository,
            auditService,
            correlationId,
            tenantId: mtls.tenant_id,
            workloadId: mtls.workload_id,
            reasonCode: 'dpop_missing',
            eventType: 'session_issued'
          });
          throw unauthorized('dpop_missing', 'Workload or tenant policy requires DPoP for session issuance');
        }

        let issued;
        try {
          issued = issueSession({
            workloadId: mtls.workload_id,
            tenantId: mtls.tenant_id,
            certFingerprint256: mtls.cert_fingerprint256,
            ttlSeconds: sessionTtlSeconds,
            now: now(),
            ...(dpopJkt ? {dpopKeyThumbprint: dpopJkt} : {})
          });
        } catch (error) {
          if (error instanceof SessionInputValidationError) {
            throw badRequest(error.code, 'Session input validation failed');
          }
          throw error;
        }

        await repository.saveSession({
          session: {
            sessionId: issued.session.sessionId,
            workloadId: issued.session.workloadId,
            tenantId: issued.session.tenantId,
            certFingerprint256: issued.session.certFingerprint256,
            tokenHash: issued.session.tokenHash,
            expiresAt: issued.session.expiresAt,
            ...(issued.session.dpopKeyThumbprint ? {dpopKeyThumbprint: issued.session.dpopKeyThumbprint} : {})
          },
          scopes: sessionScopes
        });

        await appendAuditEvent({
          auditService,
          event: buildAuditEvent({
            repository,
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
        });

        const payload = OpenApiSessionResponseSchema.parse({
          session_token: issued.token,
          expires_at: issued.session.expiresAt,
          bound_cert_thumbprint: issued.session.certFingerprint256,
          ...(issued.session.dpopKeyThumbprint ? {dpop_jkt: issued.session.dpopKeyThumbprint} : {})
        });

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        logger.info({
          event: 'session.issue.success',
          component: 'server.session',
          message: 'Session issued'
        });
        return;
      }

      if (method === 'POST' && pathname === '/v1/execute') {
        logger.info({
          event: 'execute.start',
          component: 'server.execute',
          message: 'Execute pipeline started'
        });
        try {
          await requireSessionContext({
            request,
            repository,
            mtls,
            config,
            pathname,
            requiredScope: 'execute'
          });
        } catch (error) {
          if (isAppError(error) && isDpopFailureReasonCode(error.code)) {
            executeAuditRecorded = true;
            await appendDpopFailureAuditEvent({
              repository,
              auditService,
              correlationId,
              tenantId: mtls.tenant_id,
              workloadId: mtls.workload_id,
              reasonCode: error.code,
              eventType: 'execute'
            });
          }

          throw error;
        }

        const executeRequest = await parseJsonBody({
          request,
          schema: OpenApiExecuteRequestSchema,
          maxBodyBytes: config.maxBodyBytes,
          required: true
        });

        const integration = await repository.getIntegrationByTenantAndIdShared({
          tenantId: mtls.tenant_id,
          integrationId: executeRequest.integration_id
        });
        if (!integration) {
          throw badRequest('integration_not_found', 'Integration was not found for tenant');
        }

        if (!integration.enabled) {
          throw badRequest('integration_disabled', 'Integration is disabled');
        }
        setLogContextFields({
          integration_id: integration.integration_id
        });

        const ssrfStorageScope = {
          tenant_id: mtls.tenant_id,
          workload_id: mtls.workload_id,
          integration_id: integration.integration_id
        };
        let template = null;
        if (repository.isSsrfTemplateLookupBridgeWiredShared()) {
          try {
            template = await repository.loadSsrfActiveTemplateForExecuteShared({
              scope: ssrfStorageScope
            });
          } catch (error) {
            reportPersistenceWarning({
              logger,
              stage: 'ssrf_template_lookup',
              correlationId,
              error
            });
            throw serviceUnavailable(
              'ssrf_template_lookup_failed',
              'Unable to load active integration template for execute request'
            );
          }
        } else {
          template = await repository.getLatestTemplateByIdShared({
            tenantId: mtls.tenant_id,
            templateId: integration.template_id
          });
        }
        if (!template) {
          throw badRequest('template_not_found', 'Integration template was not found');
        }
        await repository.syncSsrfTemplateBindingShared({
          scope: ssrfStorageScope,
          template,
          now: now()
        });

        const canonicalized = canonicalizeExecuteRequest({
          context: {
            tenant_id: mtls.tenant_id,
            workload_id: mtls.workload_id,
            integration_id: integration.integration_id
          },
          template,
          execute_request: executeRequest
        });
        if (!canonicalized.ok) {
          throw badRequest(canonicalized.error.code, canonicalized.error.message);
        }

        const classification = classifyPathGroup({
          template,
          method: canonicalized.value.descriptor.method,
          canonical_url: canonicalized.value.descriptor.canonical_url
        });
        if (!classification.matched) {
          throw badRequest(classification.reason_code, 'No matching path group');
        }

        if (classification.path_group.group_id !== canonicalized.value.matched_path_group_id) {
          throw badRequest('descriptor_group_mismatch', 'Canonicalizer and classifier path groups diverged');
        }

        const policies = await repository.listPolicyRulesForDescriptorShared({
          descriptor: canonicalized.value.descriptor
        });
        const decision = await evaluatePolicyDecision({
          descriptor: canonicalized.value.descriptor,
          template,
          policies,
          now: now(),
          rateLimiter: async ({rule, key, now: rateLimitNow}) => {
            if (!rule.rate_limit) {
              return {allowed: true};
            }

            const outcome = await repository.incrementRateLimitCounterShared({
              key,
              intervalSeconds: rule.rate_limit.interval_seconds,
              maxRequests: rule.rate_limit.max_requests,
              now: rateLimitNow
            });
            return {allowed: outcome.allowed};
          }
        });
        logger.info({
          event: 'policy.decision',
          component: 'server.execute',
          message: `Policy decision: ${decision.decision}`,
          reason_code: decision.reason_code,
          metadata: {
            decision: decision.decision,
            action_group: decision.action_group
          }
        });

        executeAuditRecorded = true;
        await appendAuditEvent({
          auditService,
          event: buildAuditEvent({
            repository,
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
        });

        if (decision.decision === 'denied') {
          logger.warn({
            event: 'execute.denied',
            component: 'server.execute',
            message: 'Execution denied by policy',
            reason_code: decision.reason_code
          });
          executeAuditRecorded = true;
          await appendAuditEvent({
            auditService,
            event: buildAuditEvent({
              repository,
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
          });

          throw badRequest(decision.reason_code, 'Request denied by policy');
        }

        if (decision.decision === 'throttled') {
          logger.warn({
            event: 'execute.throttled',
            component: 'server.execute',
            message: 'Execution throttled by policy',
            reason_code: decision.reason_code
          });
          executeAuditRecorded = true;
          await appendAuditEvent({
            auditService,
            event: buildAuditEvent({
              repository,
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
          });

          throw badRequest(decision.reason_code, 'Request throttled by policy');
        }

        if (decision.decision === 'approval_required') {
          logger.warn({
            event: 'execute.approval_required',
            component: 'server.execute',
            message: 'Execution requires approval',
            reason_code: decision.reason_code
          });
          const summary = repository.buildApprovalSummary({
            descriptor: canonicalized.value.descriptor,
            actionGroup: decision.action_group,
            riskTier: decision.risk_tier,
            integrationId: integration.integration_id
          });

          const approval = await repository.createOrReuseApprovalRequest({
            descriptor: canonicalized.value.descriptor,
            summary,
            correlationId,
            now: now()
          });

          executeAuditRecorded = true;
          await appendAuditEvent({
            auditService,
            event: buildAuditEvent({
              repository,
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
          });

          const payload = OpenApiExecuteResponseApprovalRequiredSchema.parse({
            status: 'approval_required',
            approval_id: approval.approval_id,
            expires_at: approval.expires_at,
            correlation_id: correlationId,
            summary: approval.summary
          });

          sendJson({
            response,
            status: 202,
            correlationId,
            payload
          });
          return;
        }

        let ssrfResolvedIps: string[] = [];
        const ssrfResult = await guardExecuteRequestDestination({
          input: {
            execute_request: executeRequest,
            template
          },
          options: {
            dns_resolver: async ({hostname}) => {
              const normalizedHost = hostname.trim().toLowerCase();
              const nowAtResolution = now();
              const cachedEntry = await repository.readSsrfDnsResolutionCacheShared({
                normalizedHost,
                now: nowAtResolution
              });
              if (cachedEntry) {
                const cacheAgeMs = nowAtResolution.getTime() - cachedEntry.resolved_at_epoch_ms;
                const refreshThresholdMs = Math.max(1_000, Math.floor((cachedEntry.ttl_seconds * 1000) / 2));
                if (cacheAgeMs < refreshThresholdMs) {
                  ssrfResolvedIps = normalizeResolvedIps(cachedEntry.resolved_ips);
                  return ssrfResolvedIps;
                }

                const refreshed = normalizeResolvedIps(
                  await Promise.resolve(baseDnsResolver({hostname: normalizedHost}))
                );
                ssrfResolvedIps = refreshed;
                if (!ipSetsEqual(refreshed, cachedEntry.resolved_ips)) {
                  await repository.appendSsrfDnsRebindingObservationShared({
                    normalizedHost,
                    resolvedIps: refreshed,
                    now: nowAtResolution
                  });
                }
                if (refreshed.length > 0) {
                  await repository.writeSsrfDnsResolutionCacheShared({
                    normalizedHost,
                    resolvedIps: refreshed,
                    now: nowAtResolution,
                    ttlSeconds: cachedEntry.ttl_seconds
                  });
                }
                return refreshed;
              }

              const resolved = normalizeResolvedIps(await Promise.resolve(baseDnsResolver({hostname: normalizedHost})));
              ssrfResolvedIps = resolved;
              if (resolved.length > 0) {
                await repository.writeSsrfDnsResolutionCacheShared({
                  normalizedHost,
                  resolvedIps: resolved,
                  now: nowAtResolution
                });
              }
              return resolved;
            },
            dns_resolution: {
              timeout_ms: config.dns_timeout_ms
            }
          }
        });
        if (!ssrfResult.ok) {
          const destination = parseDestinationFromRequestUrl(canonicalized.value.descriptor.canonical_url);
          await repository.appendSsrfDecisionProjectionShared({
            projection: {
              event_id: `ssrf_${randomUUID()}`,
              timestamp: now().toISOString(),
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
            }
          });

          executeAuditRecorded = true;
          await appendAuditEvent({
            auditService,
            event: buildAuditEvent({
              repository,
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
          });

          throw badRequest(ssrfResult.error.code, ssrfResult.error.message);
        }

        await repository.appendSsrfDecisionProjectionShared({
          projection: {
            event_id: `ssrf_${randomUUID()}`,
            timestamp: now().toISOString(),
            tenant_id: mtls.tenant_id,
            workload_id: mtls.workload_id,
            integration_id: integration.integration_id,
            template_id: template.template_id,
            template_version: template.version,
            destination_host: ssrfResult.value.destination.host,
            destination_port: ssrfResult.value.destination.port,
            resolved_ips: ssrfResult.value.resolved_ips,
            decision: 'allowed',
            reason_code: template.network_safety.dns_resolution_required ? 'dns_resolution_required' : 'invalid_input',
            correlation_id: correlationId
          }
        });

        const idempotencyKey = executeRequest.client_context?.idempotency_key?.trim();
        let forwarderPersistenceContext: {
          scope: {
            tenant_id: string;
            workload_id: string;
            integration_id: string;
            action_group: string;
            idempotency_key: string;
          };
          lock_token: string;
          idempotency_record_created: boolean;
          finalized: boolean;
        } | null = null;

        if (idempotencyKey) {
          if (!repository.isForwarderPersistenceEnabledShared()) {
            throw serviceUnavailable(
              'forwarder_persistence_unavailable',
              'Idempotency key was provided but forwarder persistence is not configured'
            );
          }

          const scope = {
            tenant_id: mtls.tenant_id,
            workload_id: mtls.workload_id,
            integration_id: integration.integration_id,
            action_group: decision.action_group,
            idempotency_key: idempotencyKey
          };
          const lockTtlMs = clamp({
            value: config.forwarder.total_timeout_ms + 1000,
            min: 1000,
            max: maximumForwarderIdempotencyTtlSeconds * 1000
          });
          const lockResult = await repository.acquireForwarderExecutionLockShared({
            scope,
            ttlMs: lockTtlMs
          });
          if (!lockResult.acquired) {
            throw conflict(
              'forwarder_execution_locked',
              'Execute request is already in progress for the provided idempotency key'
            );
          }

          forwarderPersistenceContext = {
            scope,
            lock_token: lockResult.lock_token,
            idempotency_record_created: false,
            finalized: false
          };
        }

        try {
          if (forwarderPersistenceContext) {
            const idempotencyTtlSeconds = clamp({
              value: Math.ceil(config.forwarder.total_timeout_ms / 1000) * 2,
              min: minimumForwarderIdempotencyTtlSeconds,
              max: maximumForwarderIdempotencyTtlSeconds
            });
            const idempotencyFingerprint = toForwarderIdempotencyFingerprint({
              descriptor: canonicalized.value.descriptor as unknown as Record<string, unknown>,
              request: executeRequest.request as unknown as Record<string, unknown>
            });
            const idempotencyResult = await repository.createForwarderIdempotencyRecordShared({
              scope: forwarderPersistenceContext.scope,
              requestFingerprintSha256: idempotencyFingerprint,
              correlationId,
              expiresAt: new Date(now().getTime() + idempotencyTtlSeconds * 1000).toISOString()
            });

            if (!idempotencyResult.created) {
              const existingRecord = await repository.getForwarderIdempotencyRecordShared({
                scope: forwarderPersistenceContext.scope
              });
              if (idempotencyResult.conflict === 'fingerprint_mismatch') {
                throw conflict(
                  'idempotency_key_conflict',
                  'Idempotency key is already bound to a different execute request fingerprint'
                );
              }

              if (existingRecord?.state === 'in_progress') {
                throw conflict(
                  'idempotency_request_in_progress',
                  'An execute request with the same idempotency key is already in progress'
                );
              }

              throw conflict(
                'idempotency_key_reused',
                `Idempotency key cannot be reused while previous request state is ${existingRecord?.state ?? 'unknown'}`
              );
            }

            forwarderPersistenceContext.idempotency_record_created = true;
          }

          let injectedHeaders;
          try {
            injectedHeaders = await repository.getInjectedHeadersForIntegrationShared({
              tenantId: mtls.tenant_id,
              integrationId: integration.integration_id,
              correlationId
            });
          } catch (error) {
            if (isDataPlaneRepositoryError(error) && error.code === 'integration_secret_unavailable') {
              executeAuditRecorded = true;
              await appendAuditEvent({
                auditService,
                event: buildAuditEvent({
                  repository,
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
              });
              throw serviceUnavailable(
                'integration_secret_unavailable',
                'Integration secret material is unavailable for execute request'
              );
            }
            throw error;
          }

          const forwardResult = await forwardExecuteRequest({
            input: {
              execute_request: executeRequest,
              template,
              matched_path_group_id: canonicalized.value.matched_path_group_id,
              injected_headers: injectedHeaders,
              correlation_id: correlationId,
              timeouts: {
                total_timeout_ms: config.forwarder.total_timeout_ms
              },
              limits: {
                max_request_body_bytes: config.forwarder.max_request_body_bytes,
                max_response_bytes: config.forwarder.max_response_bytes
              }
            },
            ...(fetchImpl ? {fetchImpl} : {})
          });
          if (!forwardResult.ok) {
            executeAuditRecorded = true;
            await appendAuditEvent({
              auditService,
              event: buildAuditEvent({
                repository,
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
            });

            throw badRequest(forwardResult.error.code, forwardResult.error.message);
          }

          const redirectCheck = enforceRedirectDenyPolicy({
            input: {
              template,
              upstream_status_code: forwardResult.value.upstream.status_code,
              upstream_headers: forwardResult.value.upstream.headers
            }
          });
          if (!redirectCheck.ok) {
            throw badRequest(redirectCheck.error.code, redirectCheck.error.message);
          }

          if (forwarderPersistenceContext && !forwarderPersistenceContext.finalized) {
            const completeResult = await repository.completeForwarderIdempotencyRecordShared({
              scope: forwarderPersistenceContext.scope,
              correlationId,
              upstreamStatusCode: forwardResult.value.upstream.status_code,
              responseBytes: decodedBase64ByteLength(forwardResult.value.upstream.body_base64)
            });
            if (!completeResult.updated) {
              throw serviceUnavailable(
                'forwarder_idempotency_complete_failed',
                'Failed to finalize execute idempotency state'
              );
            }
            forwarderPersistenceContext.finalized = true;
          }

          executeAuditRecorded = true;
          await appendAuditEvent({
            auditService,
            event: buildAuditEvent({
              repository,
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
          });

          const payload = OpenApiExecuteResponseExecutedSchema.parse(forwardResult.value);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });
          logger.info({
            event: 'execute.completed',
            component: 'server.execute',
            message: 'Execution completed',
            status_code: payload.upstream.status_code
          });
          return;
        } catch (error) {
          if (
            forwarderPersistenceContext &&
            forwarderPersistenceContext.idempotency_record_created &&
            !forwarderPersistenceContext.finalized
          ) {
            const errorCode = isAppError(error) ? error.code : 'forwarder_execute_error';
            try {
              const failResult = await repository.failForwarderIdempotencyRecordShared({
                scope: forwarderPersistenceContext.scope,
                correlationId,
                errorCode
              });
              forwarderPersistenceContext.finalized = failResult.updated;
            } catch (storeError) {
              reportPersistenceWarning({
                logger,
                stage: 'forwarder_idempotency_fail_finalize',
                correlationId,
                error: storeError
              });
            }
          }
          throw error;
        } finally {
          if (forwarderPersistenceContext) {
            try {
              await repository.releaseForwarderExecutionLockShared({
                scope: forwarderPersistenceContext.scope,
                lockToken: forwarderPersistenceContext.lock_token
              });
            } catch (storeError) {
              reportPersistenceWarning({
                logger,
                stage: 'forwarder_execution_lock_release',
                correlationId,
                error: storeError
              });
            }
          }
        }
      }

      {
        const manifestMatch = pathname.match(manifestPathPattern);
        if (manifestMatch && method === 'GET') {
          const requestedWorkloadId = decodePathParam(manifestMatch[1]);
          if (requestedWorkloadId !== mtls.workload_id) {
            throw unauthorized('manifest_workload_mismatch', 'Manifest workload id must match mTLS workload identity');
          }

          await requireSessionContext({
            request,
            repository,
            mtls,
            config,
            pathname,
            requiredScope: 'manifest.read'
          }).catch(async error => {
            if (isAppError(error) && isDpopFailureReasonCode(error.code)) {
              await appendDpopFailureAuditEvent({
                repository,
                auditService,
                correlationId,
                tenantId: mtls.tenant_id,
                workloadId: mtls.workload_id,
                reasonCode: error.code,
                eventType: 'execute'
              });
            }

            throw error;
          });

          const manifestRules = await repository.listManifestTemplateRulesForTenantShared({
            tenantId: mtls.tenant_id
          });
          if (manifestRules.length === 0) {
            throw badRequest('manifest_no_rules', 'No manifest rules are available for this workload');
          }

          const nowDate = now();
          const dpopRequiredForManifest = isDpopRequiredForIdentity({
            repository,
            tenantId: mtls.tenant_id,
            workloadId: mtls.workload_id
          });
          const unsignedManifest = UnsignedManifestSchema.parse({
            manifest_version: 1,
            issued_at: nowDate.toISOString(),
            expires_at: new Date(nowDate.getTime() + repository.getManifestTtlSeconds() * 1000).toISOString(),
            broker_execute_url: new URL('/v1/execute', config.publicBaseUrl).toString(),
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
          });

          const signedManifest = await signManifest({
            manifest: unsignedManifest,
            signing_key: await repository.getManifestSigningPrivateKeyShared()
          });
          if (!signedManifest.ok) {
            throw internal(signedManifest.error.code, signedManifest.error.message);
          }

          const payload = OpenApiManifestSchema.parse(signedManifest.value);
          logger.info({
            event: 'manifest.issued',
            component: 'server.manifest',
            message: 'Manifest issued'
          });

          await appendAuditEvent({
            auditService,
            event: buildAuditEvent({
              repository,
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
          });

          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });
          return;
        }
      }

      throw badRequest('route_not_found', `Unsupported route ${method} ${pathname}`);
        } catch (error) {
          if (isAppError(error)) {
            responseReasonCode = error.code;
            logger.warn({
              event: 'request.rejected',
              component: 'http.server',
              message: `Request rejected: ${error.code}`,
              reason_code: error.code,
              route: pathname,
              method
            });

            if (method === 'POST' && pathname === '/v1/execute' && mtlsContext && !executeAuditRecorded) {
              try {
                await appendAuditEvent({
                  auditService,
                  event: buildAuditEvent({
                    repository,
                    correlationId,
                    tenantId: mtlsContext.tenant_id,
                    event: {
                      workload_id: mtlsContext.workload_id,
                      integration_id: null,
                      event_type: 'execute',
                      decision: 'denied',
                      action_group: null,
                      risk_tier: null,
                      destination: null,
                      latency_ms: null,
                      upstream_status_code: null,
                      canonical_descriptor: null,
                      message: `Execution rejected before forwarding: ${error.code}`,
                      metadata: {
                        reason_code: error.code
                      }
                    }
                  })
                });
                executeAuditRecorded = true;
              } catch (auditError) {
                if (isAppError(auditError)) {
                  responseReasonCode = auditError.code;
                  sendError({
                    response,
                    status: auditError.status,
                    error: auditError.code,
                    message: auditError.message,
                    correlationId
                  });
                  return;
                }

                responseReasonCode = 'internal_error';
                sendError({
                  response,
                  status: 500,
                  error: 'internal_error',
                  message: 'Unexpected internal error',
                  correlationId
                });
                return;
              }
            }

            sendError({
              response,
              status: error.status,
              error: error.code,
              message: error.message,
              correlationId
            });
            return;
          }

          responseReasonCode = 'internal_error';
          logger.error({
            event: 'request.failed',
            component: 'http.server',
            message: 'Unexpected internal error',
            reason_code: 'internal_error',
            route: pathname,
            method,
            metadata: {
              error
            }
          });

          sendError({
            response,
            status: 500,
            error: 'internal_error',
            message: 'Unexpected internal error',
            correlationId
          });
        } finally {
          const durationMs = Math.max(0, now().getTime() - startedAtMs);
          const statusCode = response.statusCode;
          const baseLog = {
            event: 'request.completed',
            component: 'http.server',
            message: 'Request completed',
            route: pathname,
            method,
            status_code: statusCode,
            duration_ms: durationMs,
            ...(responseReasonCode ? {reason_code: responseReasonCode} : {})
          };

          if (statusCode >= 500) {
            logger.error(baseLog);
          } else if (statusCode >= 400) {
            logger.warn(baseLog);
          } else {
            logger.info(baseLog);
          }
        }
      }
    );
  };

  return handleRequest;
};

export const createBrokerApiServer = (input: CreateBrokerApiServerInput): Server => {
  const handler = createBrokerApiRequestHandler(input);
  return createHttpServer((request, response) => {
    void handler(request, response);
  });
};
