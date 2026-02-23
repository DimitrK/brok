import {type IncomingMessage, type ServerResponse} from 'node:http';
import {createHash, randomUUID} from 'node:crypto';
import {lookup as dnsLookup} from 'node:dns/promises';
import {BlockList, isIP} from 'node:net';
import type {TLSSocket} from 'node:tls';

import type {AuditService} from '@broker-interceptor/audit';
import {
  extractWorkloadPrincipal,
  hashToken,
  verifyMtls,
  verifyBoundDpopProofJwt,
  verifySessionBinding,
} from '@broker-interceptor/auth';
import {
  createNoopLogger,
  runWithLogContext,
  setLogContextFields,
  type StructuredLogger
} from '@broker-interceptor/logging';
import {
  OpenApiAuditEventSchema,
  type OpenApiAuditEvent
} from '@broker-interceptor/schemas';
import type {FetchLike} from '@broker-interceptor/forwarder';
import {type DnsResolver} from '@broker-interceptor/ssrf-guard';

import type {ServiceConfig} from '../config';
import {isAppError, unauthorized, serviceUnavailable} from '../errors';
import {extractCorrelationId, sendError} from '../http';
import {DataPlaneRepository} from '../repository';
import {handleExecuteRoute} from './routes/executeRoute';
import {handleFallbackRoute} from './routes/fallbackRoute';
import {handleHealthRoute} from './routes/healthRoute';
import {handleManifestKeysRoute} from './routes/manifestKeysRoute';
import {handleSessionRoute} from './routes/sessionRoute';
import type {
  BrokerApiRouteHandlers,
  BrokerApiRouteKind,
  BrokerApiRouteLogicHandler,
  RequestHandlerState,
  RouteRuntime
} from './routes/types';
import {handleWorkloadManifestRoute} from './routes/workloadManifestRoute';

const getRawRequestUrl = (request: IncomingMessage) => {
  const requestWithRoutingContext = request as IncomingMessage & {
    originalUrl?: string;
    path?: string;
    baseUrl?: string;
    route?: {
      path?: string;
    };
  };
  const originalUrl = requestWithRoutingContext.originalUrl;
  if (typeof originalUrl === 'string' && originalUrl.length > 0) {
    return originalUrl;
  }

  const rawUrl = request.url ?? '/';
  if (rawUrl !== '/') {
    return rawUrl;
  }

  const path = requestWithRoutingContext.path;
  const baseUrl = requestWithRoutingContext.baseUrl;
  if (typeof path === 'string' && path.length > 0) {
    const safeBaseUrl = typeof baseUrl === 'string' ? baseUrl : '';
    const recomposed = `${safeBaseUrl}${path}`;
    // Express route-local requests often expose "/" as path; do not treat that
    // as a definitive URL because it masks the matched route path (e.g. "/healthz").
    if (recomposed.length > 0 && recomposed !== '/') {
      return recomposed;
    }
  }

  const routePath = requestWithRoutingContext.route?.path;
  if (typeof routePath === 'string' && routePath.startsWith('/')) {
    return routePath;
  }

  return request.url ?? '/';
};

const parseUrl = (request: IncomingMessage) => {
  const host = request.headers.host ?? 'localhost';
  return new URL(getRawRequestUrl(request), `https://${host}`);
};

const sanitizeRouteForLog = ({rawUrl}: {rawUrl: string | undefined}) => {
  if (!rawUrl) {
    return '/';
  }

  const routeWithoutQuery = rawUrl.split('?', 1)[0] ?? '';
  const routeWithoutFragment = routeWithoutQuery.split('#', 1)[0] ?? '';
  return routeWithoutFragment.length > 0 ? routeWithoutFragment : '/';
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
  const tlsSocket = request.socket as Partial<TLSSocket>;
  if (typeof tlsSocket.getPeerCertificate !== 'function') {
    throw unauthorized('mtls_required', 'mTLS authentication failed');
  }

  let principal;
  try {
    principal = extractWorkloadPrincipal({tlsSocket: tlsSocket as TLSSocket});
  } catch {
    throw unauthorized('mtls_required', 'mTLS authentication failed');
  }

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

const truncateForLog = ({value, maxLength}: {value: string; maxLength: number}) =>
  value.length <= maxLength ? value : `${value.slice(0, maxLength)}...`;

const describePersistenceError = (error: unknown) => {
  if (isAppError(error)) {
    return {
      reasonCode: error.code,
      details: {
        error_name: 'AppError',
        error_code: error.code,
        error_message: truncateForLog({value: error.message, maxLength: 240})
      }
    };
  }

  if (error instanceof Error) {
    const errorWithCode = error as Error & {code?: unknown};
    return {
      reasonCode: error.name,
      details: {
        error_name: error.name,
        ...(typeof errorWithCode.code === 'string' ? {error_code: errorWithCode.code} : {}),
        error_message: truncateForLog({value: error.message, maxLength: 240})
      }
    };
  }

  if (typeof error === 'object' && error !== null) {
    const candidate = error as {name?: unknown; code?: unknown; message?: unknown};
    return {
      reasonCode: typeof candidate.name === 'string' ? candidate.name : 'unknown_error',
      details: {
        ...(typeof candidate.name === 'string' ? {error_name: candidate.name} : {}),
        ...(typeof candidate.code === 'string' ? {error_code: candidate.code} : {}),
        ...(typeof candidate.message === 'string'
          ? {error_message: truncateForLog({value: candidate.message, maxLength: 240})}
          : {})
      }
    };
  }

  return {
    reasonCode: 'unknown_error',
    details: {
      error_name: 'unknown_error'
    }
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
  const diagnostics = describePersistenceError(error);
  logger.warn({
    event: 'repository.persistence.warning',
    component: 'repository.persistence',
    message: `Non-blocking persistence operation failed (${stage})`,
    correlation_id: correlationId,
    reason_code: diagnostics.reasonCode,
    metadata: {
      warning_code: 'BROKER_API_PERSISTENCE_WARNING',
      stage,
      ...diagnostics.details
    }
  });
};

const appendSsrfDecisionProjectionBestEffort = async ({
  repository,
  projection,
  logger,
  correlationId,
  stage
}: {
  repository: DataPlaneRepository;
  projection: Parameters<DataPlaneRepository['appendSsrfDecisionProjectionShared']>[0]['projection'];
  logger: StructuredLogger;
  correlationId: string;
  stage: string;
}) => {
  try {
    await repository.appendSsrfDecisionProjectionShared({projection});
  } catch (error) {
    reportPersistenceWarning({
      logger,
      stage,
      correlationId,
      error
    });
  }
};

export type CreateBrokerApiRequestHandlerInput = {
  config: ServiceConfig;
  repository: DataPlaneRepository;
  auditService: AuditService;
  logger?: StructuredLogger;
  fetchImpl?: FetchLike;
  dnsResolver?: DnsResolver;
  now?: () => Date;
};

export const createBrokerApiRouteHandlers = ({
  config,
  repository,
  auditService,
  logger = createNoopLogger(),
  fetchImpl,
  dnsResolver,
  now = () => new Date()
}: CreateBrokerApiRequestHandlerInput) => {
  const baseDnsResolver: DnsResolver =
    dnsResolver ??
    (async ({hostname}) => {
      const records = await dnsLookup(hostname, {all: true, verbatim: true});
      return records.map(record => record.address);
    });

  const requireMtlsContextWithLogging = async (input: Parameters<typeof requireMtlsContext>[0]) => {
    try {
      const mtls = await requireMtlsContext(input);
      logger.info({
        event: 'auth.mtls.verified',
        component: 'server.auth',
        message: 'mTLS authentication succeeded'
      });
      return mtls;
    } catch (error) {
      const reasonCode = isAppError(error) ? error.code : error instanceof Error ? error.name : 'mtls_auth_failed';
      logger.warn({
        event: 'auth.mtls.denied',
        component: 'server.auth',
        message: 'mTLS authentication failed',
        reason_code: reasonCode
      });
      throw error;
    }
  };

  const requireSessionContextWithLogging = async (input: Parameters<typeof requireSessionContext>[0]) => {
    try {
      const sessionContext = await requireSessionContext(input);
      logger.info({
        event: 'auth.session.verified',
        component: 'server.auth',
        message: 'Session authentication succeeded',
        metadata: {
          required_scope: input.requiredScope,
          dpop_bound: Boolean(sessionContext.session.dpop_jkt)
        }
      });

      if (sessionContext.session.dpop_jkt) {
        logger.info({
          event: 'auth.dpop.verified',
          component: 'server.auth',
          message: 'DPoP verification succeeded'
        });
      }

      return sessionContext;
    } catch (error) {
      const reasonCode = isAppError(error) ? error.code : error instanceof Error ? error.name : 'session_auth_failed';
      logger.warn({
        event: isDpopFailureReasonCode(reasonCode) ? 'auth.dpop.denied' : 'auth.session.denied',
        component: 'server.auth',
        message: 'Session authentication failed',
        reason_code: reasonCode
      });
      throw error;
    }
  };

  const runtime: RouteRuntime = {
    config,
    repository,
    auditService,
    logger,
    ...(fetchImpl ? {fetchImpl} : {}),
    baseDnsResolver,
    now,
    requireMtlsContextWithLogging,
    requireSessionContextWithLogging,
    buildPublicRouteUrl: ({pathname}) => buildPublicRouteUrl({config, pathname}),
    getSingleHeaderValue,
    isDpopRequiredForIdentity: ({tenantId, workloadId}) =>
      isDpopRequiredForIdentity({repository, tenantId, workloadId}),
    isDpopFailureReasonCode,
    buildAuditEvent: ({correlationId, tenantId, event}) =>
      buildAuditEvent({
        repository,
        correlationId,
        tenantId,
        event
      }),
    appendAuditEvent: ({event}) => appendAuditEvent({auditService, event}),
    appendDpopFailureAuditEvent: ({correlationId, tenantId, workloadId, reasonCode, eventType}) =>
      appendDpopFailureAuditEvent({
        repository,
        auditService,
        correlationId,
        tenantId,
        workloadId,
        reasonCode,
        eventType
      }),
    parseDestinationFromRequestUrl,
    appendSsrfDecisionProjectionBestEffort: ({projection, correlationId, stage}) =>
      appendSsrfDecisionProjectionBestEffort({
        repository,
        projection,
        logger,
        correlationId,
        stage
      }),
    reportPersistenceWarning: ({stage, correlationId, error}) =>
      reportPersistenceWarning({
        logger,
        stage,
        correlationId,
        error
      }),
    normalizeResolvedIps,
    ipSetsEqual,
    clamp,
    toForwarderIdempotencyFingerprint,
    decodedBase64ByteLength
  };

  const createRouteHandler = ({
    routeKind,
    routeLogicHandler
  }: {
    routeKind: BrokerApiRouteKind;
    routeLogicHandler: BrokerApiRouteLogicHandler;
  }) => {
    const executeRoute = (request: IncomingMessage, response: ServerResponse) => {
      const correlationId = extractCorrelationId(request);
      const requestId = randomUUID();
      const startedAtMs = now().getTime();
      const requestMethod = request.method ?? 'GET';
      const state: RequestHandlerState = {
        mtlsContext: null,
        executeAuditRecorded: false
      };

      return runWithLogContext(
        {
          correlation_id: correlationId,
          request_id: requestId,
          method: requestMethod
        },
        async () => {
          let method = requestMethod;
          let pathname = '/';
          let responseReasonCode: string | undefined;

          logger.info({
            event: 'request.received',
            component: 'http.server',
            message: 'Request received',
            route: sanitizeRouteForLog({rawUrl: getRawRequestUrl(request)}),
            method: requestMethod
          });

          try {
            const url = parseUrl(request);
            method = requestMethod;
            pathname = url.pathname;

            setLogContextFields({
              route: pathname,
              method
            });

            await routeLogicHandler({
              request,
              response,
              correlationId,
              method,
              pathname,
              state,
              runtime
            });
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

              const mtlsContext = state.mtlsContext;
              const shouldAppendExecuteRejectionAudit =
                routeKind === 'execute' && mtlsContext !== null && !state.executeAuditRecorded;
              if (shouldAppendExecuteRejectionAudit) {
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
                  state.executeAuditRecorded = true;
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

    return executeRoute;
  };

  const handlers: BrokerApiRouteHandlers = {
    health: createRouteHandler({routeKind: 'health', routeLogicHandler: handleHealthRoute}),
    manifestKeys: createRouteHandler({
      routeKind: 'manifestKeys',
      routeLogicHandler: handleManifestKeysRoute
    }),
    session: createRouteHandler({routeKind: 'session', routeLogicHandler: handleSessionRoute}),
    execute: createRouteHandler({routeKind: 'execute', routeLogicHandler: handleExecuteRoute}),
    workloadManifest: createRouteHandler({
      routeKind: 'workloadManifest',
      routeLogicHandler: handleWorkloadManifestRoute
    }),
    fallback: createRouteHandler({routeKind: 'fallback', routeLogicHandler: handleFallbackRoute})
  };

  return handlers;
};
