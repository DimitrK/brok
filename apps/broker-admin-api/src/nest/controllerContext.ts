import {createHmac, randomUUID, timingSafeEqual} from 'node:crypto'
import type {IncomingMessage} from 'node:http'

import {Inject, Injectable} from '@nestjs/common'
import type {Request, Response} from 'express'
import {
  createNoopLogger,
  runWithLogContext,
  setLogContextFields,
  type StructuredLogger
} from '@broker-interceptor/logging'
import {
  OpenApiAdminAccessRequestStatusSchema,
  OpenApiAdminRoleSchema,
  OpenApiAdminUserStatusSchema
} from '@broker-interceptor/schemas'
import {decodeJwt} from 'jose'
import {z} from 'zod'

import {requireTenantScope, type AdminPrincipal} from '../auth'
import type {OidcAuthConfig, ServiceConfig} from '../config'
import type {DependencyBridge} from '../dependencyBridge'
import {badRequest, isAppError, notFound} from '../errors'
import {
  approvalStatusFilterSchema,
  ControlPlaneRepository,
  type ApprovalStatusFilter
} from '../repository'
import {extractCorrelationId, sendError} from '../http'
import {
  BROKER_ADMIN_API_CONFIG,
  BROKER_ADMIN_API_DEPENDENCY_BRIDGE,
  BROKER_ADMIN_API_LOGGER,
  BROKER_ADMIN_API_REPOSITORY
} from './tokens'

const auth0HostSuffix = '.auth0.com'
const adminOAuthStateVersion = 1
const defaultAdminOAuthSessionTtlSeconds = 3600

export const listAccessRoles = ['owner', 'admin', 'auditor', 'operator'] as const
export const writeAccessRoles = ['owner', 'admin'] as const
export const approvalDecisionRoles = ['owner', 'admin', 'operator'] as const

export type RequestHandlerContext = {
  correlationId: string
  method: string
  pathname: string
  url: URL
}

export const approvalStatusQuerySchema = z
  .object({
    status: approvalStatusFilterSchema.optional()
  })
  .strict()

const adminListLimitQuerySchema = z.preprocess(value => {
  if (value === undefined) {
    return undefined
  }

  if (typeof value !== 'string') {
    return value
  }

  const parsed = Number.parseInt(value, 10)
  return Number.isNaN(parsed) ? value : parsed
}, z.number().int().min(1).max(100).optional())

export const adminUserListQuerySchema = z
  .object({
    status: OpenApiAdminUserStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: OpenApiAdminRoleSchema.optional(),
    search: z.string().min(1).optional(),
    limit: adminListLimitQuerySchema,
    cursor: z.string().min(1).optional()
  })
  .strict()

export const adminAccessRequestListQuerySchema = z
  .object({
    status: OpenApiAdminAccessRequestStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: OpenApiAdminRoleSchema.optional(),
    search: z.string().min(1).optional(),
    limit: adminListLimitQuerySchema,
    cursor: z.string().min(1).optional()
  })
  .strict()

const adminOAuthStatePayloadSchema = z
  .object({
    v: z.literal(adminOAuthStateVersion),
    provider: z.enum(['google', 'github']),
    redirect_uri: z.string().url(),
    nonce: z.string().min(16),
    iat: z.number().int(),
    exp: z.number().int()
  })
  .strict()

const oidcTokenResponseSchema = z
  .object({
    access_token: z.string().min(1).optional(),
    id_token: z.string().min(1).optional(),
    expires_in: z
      .union([
        z.number().int().positive(),
        z
          .string()
          .regex(/^\d+$/u)
          .transform(value => Number.parseInt(value, 10))
      ])
      .optional(),
    error: z.string().min(1).optional(),
    error_description: z.string().optional()
  })
  .passthrough()

export type OAuthTokenExchangeResult = {
  sessionToken: string
  idToken?: string
  expiresIn?: number
}

const sanitizeRouteForLog = ({rawUrl}: {rawUrl: string | undefined}) => {
  if (!rawUrl) {
    return '/'
  }

  const routeWithoutQuery = rawUrl.split('?', 1)[0] ?? ''
  const routeWithoutFragment = routeWithoutQuery.split('#', 1)[0] ?? ''
  return routeWithoutFragment.length > 0 ? routeWithoutFragment : '/'
}

const parseUrl = (request: IncomingMessage) => {
  try {
    const host = request.headers.host ?? 'localhost'
    return new URL(request.url ?? '/', `http://${host}`)
  } catch {
    throw badRequest('request_url_invalid', 'Request URL is invalid')
  }
}

const toAuthFailureReasonCode = (error: unknown) => (isAppError(error) ? error.code : 'auth_admin_invalid')

export const decodePathParam = (value: string) => {
  try {
    return decodeURIComponent(value)
  } catch {
    throw badRequest('path_param_invalid', 'Path parameter encoding is invalid')
  }
}

export const toDate = (value: string | undefined) => (value ? new Date(value) : undefined)

export const resolveAuditTenantId = ({principal, tenantId}: {principal: AdminPrincipal; tenantId?: string}) => {
  if (tenantId) {
    return tenantId
  }

  if (principal.tenantIds && principal.tenantIds.length > 0) {
    return principal.tenantIds[0]
  }

  return 'global'
}

const encodeBase64Url = (value: Buffer | string) => Buffer.from(value).toString('base64url')

const decodeBase64Url = (value: string) => Buffer.from(value, 'base64url')

@Injectable()
export class AdminApiControllerContext {
  private readonly logger: StructuredLogger

  public constructor(
    @Inject(BROKER_ADMIN_API_CONFIG) public readonly config: ServiceConfig,
    @Inject(BROKER_ADMIN_API_REPOSITORY) public readonly repository: ControlPlaneRepository,
    @Inject(BROKER_ADMIN_API_DEPENDENCY_BRIDGE) public readonly dependencyBridge: DependencyBridge,
    @Inject(BROKER_ADMIN_API_LOGGER) logger: StructuredLogger
  ) {
    this.logger = logger ?? createNoopLogger()
  }

  public appendAuditEventNonBlocking({
    event,
    correlationId
  }: {
    event: Parameters<ControlPlaneRepository['appendAuditEvent']>[0]['event']
    correlationId: string
  }) {
    void this.dependencyBridge.appendAuditEventWithAuditPackage({event}).catch(() => {
      this.logger.error({
        event: 'audit.emit.failed',
        component: 'server.audit',
        message: 'Audit emit failed',
        correlation_id: correlationId,
        reason_code: 'audit_emit_failed',
        metadata: {
          event_id: event.event_id
        }
      })
    })
  }

  public normalizeTenantAuditFilter({
    principal,
    requestedTenantId
  }: {
    principal: AdminPrincipal
    requestedTenantId?: string
  }) {
    if (principal.roles.includes('owner')) {
      return requestedTenantId
    }

    if (!principal.tenantIds || principal.tenantIds.length === 0) {
      throw notFound('tenant_not_found', 'No tenant scope is configured for this principal')
    }

    if (!requestedTenantId) {
      if (principal.tenantIds.length === 1) {
        return principal.tenantIds[0]
      }

      throw badRequest('tenant_filter_required', 'tenant_id query filter is required for multi-tenant principals')
    }

    if (!principal.tenantIds.includes(requestedTenantId)) {
      throw badRequest('tenant_filter_forbidden', 'tenant_id query filter is outside principal scope')
    }

    return requestedTenantId
  }

  public async requireWorkloadTenantScope({principal, workloadId}: {principal: AdminPrincipal; workloadId: string}) {
    const workload = await this.repository.getWorkload({workloadId})
    requireTenantScope({principal, tenantId: workload.tenant_id})
    return workload
  }

  public async requireIntegrationTenantScope({
    principal,
    integrationId
  }: {
    principal: AdminPrincipal
    integrationId: string
  }) {
    const integration = await this.repository.getIntegration({integrationId})
    requireTenantScope({principal, tenantId: integration.tenant_id})
    return integration
  }

  public getInteractiveOidcAuth(): (OidcAuthConfig & {oauth: OidcAuthConfig['oauth'] & {clientId: string}}) | null {
    if (this.config.auth.mode !== 'oidc') {
      return null
    }

    if (typeof this.config.auth.oauth.clientId !== 'string' || this.config.auth.oauth.clientId.length === 0) {
      return null
    }

    return {
      ...this.config.auth,
      oauth: {
        ...this.config.auth.oauth,
        clientId: this.config.auth.oauth.clientId
      }
    }
  }

  public isOidcInteractiveOAuthEnabled() {
    return this.getInteractiveOidcAuth() !== null
  }

  public resolveProviderConnectionHint({provider}: {provider: 'google' | 'github'}) {
    if (this.config.auth.mode !== 'oidc') {
      return undefined
    }

    const configured =
      provider === 'google'
        ? this.config.auth.oauth.providerConnections.google
        : this.config.auth.oauth.providerConnections.github
    if (configured) {
      return configured
    }

    const issuerHost = this.parseIssuerHost({issuer: this.config.auth.issuer})
    if (!issuerHost.endsWith(auth0HostSuffix)) {
      return undefined
    }

    if (provider === 'google') {
      return 'google-oauth2'
    }

    if (provider === 'github') {
      return 'github'
    }

    return undefined
  }

  public createAdminOAuthState({
    provider,
    redirectUri,
    nonce,
    now
  }: {
    provider: 'google' | 'github'
    redirectUri: string
    nonce: string
    now: Date
  }) {
    const payload = adminOAuthStatePayloadSchema.parse({
      v: adminOAuthStateVersion,
      provider,
      redirect_uri: redirectUri,
      nonce,
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + (this.config.auth.mode === 'oidc' ? this.config.auth.oauth.stateTtlSeconds : 600)
    })
    const encodedPayload = encodeBase64Url(JSON.stringify(payload))
    const signature = createHmac('sha256', this.config.secretKey).update(encodedPayload).digest()
    return `${encodedPayload}.${encodeBase64Url(signature)}`
  }

  public verifyAdminOAuthState({
    state,
    provider,
    redirectUri,
    now
  }: {
    state: string
    provider: 'google' | 'github'
    redirectUri: string
    now: Date
  }) {
    const [encodedPayload, encodedSignature] = state.split('.')
    if (!encodedPayload || !encodedSignature) {
      throw badRequest('admin_oauth_state_invalid', 'OAuth state is malformed')
    }

    const expectedSignature = createHmac('sha256', this.config.secretKey).update(encodedPayload).digest()
    const signature = decodeBase64Url(encodedSignature)
    if (signature.length !== expectedSignature.length || !timingSafeEqual(signature, expectedSignature)) {
      throw badRequest('admin_oauth_state_invalid', 'OAuth state signature is invalid')
    }

    let payload: z.infer<typeof adminOAuthStatePayloadSchema>
    try {
      payload = adminOAuthStatePayloadSchema.parse(JSON.parse(decodeBase64Url(encodedPayload).toString('utf8')))
    } catch {
      throw badRequest('admin_oauth_state_invalid', 'OAuth state payload is invalid')
    }

    if (payload.provider !== provider) {
      throw badRequest('admin_oauth_state_invalid', 'OAuth state provider mismatch')
    }
    if (payload.redirect_uri !== redirectUri) {
      throw badRequest('admin_oauth_state_invalid', 'OAuth state redirect_uri mismatch')
    }

    if (payload.exp <= Math.floor(now.getTime() / 1000)) {
      throw badRequest('admin_oauth_state_expired', 'OAuth state has expired')
    }

    return payload
  }

  public async exchangeOAuthAuthorizationCode({
    code,
    redirectUri,
    codeVerifier
  }: {
    code: string
    redirectUri: string
    codeVerifier: string
  }): Promise<OAuthTokenExchangeResult> {
    const oidcAuth = this.getInteractiveOidcAuth()
    if (!oidcAuth) {
      throw badRequest('admin_oauth_not_configured', 'OIDC OAuth client configuration is incomplete')
    }

    if (this.config.auth.mode !== 'oidc') {
      throw badRequest('admin_oauth_not_configured', 'OIDC token endpoint is not configured')
    }
    const tokenUrl = this.config.auth.oauth.tokenUrl

    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: oidcAuth.oauth.clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier
    })
    if (oidcAuth.oauth.clientSecret) {
      form.set('client_secret', oidcAuth.oauth.clientSecret)
    }

    const tokenResponse = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json'
      },
      body: form.toString()
    })

    let parsedBody: z.infer<typeof oidcTokenResponseSchema>
    try {
      parsedBody = oidcTokenResponseSchema.parse(await tokenResponse.json())
    } catch {
      throw badRequest('admin_oauth_callback_invalid', 'OAuth token endpoint returned an invalid payload')
    }

    if (!tokenResponse.ok || parsedBody.error) {
      throw badRequest(
        'admin_oauth_callback_invalid',
        parsedBody.error_description ?? parsedBody.error ?? 'OAuth code exchange failed'
      )
    }

    const sessionToken = parsedBody.access_token
    if (!sessionToken) {
      throw badRequest('admin_oauth_callback_invalid', 'OAuth token response did not include a usable access_token')
    }

    return {
      sessionToken,
      idToken: parsedBody.id_token,
      expiresIn: parsedBody.expires_in
    }
  }

  public resolveSessionExpiration({idToken, expiresIn, now}: {idToken?: string; expiresIn?: number; now: Date}) {
    if (typeof expiresIn === 'number' && Number.isFinite(expiresIn) && expiresIn > 0) {
      return new Date(now.getTime() + expiresIn * 1000).toISOString()
    }

    if (idToken) {
      try {
        const payload = decodeJwt(idToken)
        if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
          return new Date(payload.exp * 1000).toISOString()
        }
      } catch {
        // ignore and fall back to default ttl
      }
    }

    return new Date(now.getTime() + defaultAdminOAuthSessionTtlSeconds * 1000).toISOString()
  }

  public enrichPrincipalWithIdTokenEmailVerification({
    principal,
    idTokenPayload
  }: {
    principal: AdminPrincipal
    idTokenPayload?: ReturnType<typeof decodeJwt>
  }): AdminPrincipal {
    if (principal.authContext.mode !== 'oidc' || !idTokenPayload || principal.emailVerified === true) {
      return principal
    }

    if (idTokenPayload.email_verified !== true) {
      return principal
    }

    const idTokenSubject = typeof idTokenPayload.sub === 'string' ? idTokenPayload.sub : undefined
    const idTokenIssuer = typeof idTokenPayload.iss === 'string' ? idTokenPayload.iss : undefined
    const idTokenEmail = typeof idTokenPayload.email === 'string' ? idTokenPayload.email.toLowerCase() : undefined

    if (
      !idTokenSubject ||
      !idTokenIssuer ||
      !idTokenEmail ||
      idTokenSubject !== principal.subject ||
      this.normalizeIssuerForComparison(idTokenIssuer) !== this.normalizeIssuerForComparison(principal.issuer) ||
      idTokenEmail !== principal.email.toLowerCase()
    ) {
      return principal
    }

    return {
      ...principal,
      emailVerified: true
    }
  }

  public async authenticateFromAuthorizationHeader({
    authorizationHeader,
    context,
    transformAuthenticatedPrincipal
  }: {
    authorizationHeader: string | undefined
    context: 'oauth_callback' | 'request'
    transformAuthenticatedPrincipal?: (
      principal: Awaited<ReturnType<DependencyBridge['authenticateAdminPrincipal']>>
    ) =>
      | Awaited<ReturnType<DependencyBridge['authenticateAdminPrincipal']>>
      | Promise<Awaited<ReturnType<DependencyBridge['authenticateAdminPrincipal']>>
      >
  }) {
    let authenticatedPrincipal: Awaited<ReturnType<typeof this.dependencyBridge.authenticateAdminPrincipal>>
    try {
      authenticatedPrincipal = await this.dependencyBridge.authenticateAdminPrincipal({
        authorizationHeader
      })
    } catch (error) {
      this.logger.warn({
        event: 'auth.admin.denied',
        component: 'server.auth',
        message: context === 'oauth_callback' ? 'Admin authentication failed during oauth callback' : 'Admin authentication failed',
        reason_code: toAuthFailureReasonCode(error)
      })
      throw error
    }

    if (transformAuthenticatedPrincipal) {
      authenticatedPrincipal = await transformAuthenticatedPrincipal(authenticatedPrincipal)
    }

    const principal = await this.dependencyBridge.resolveAdminIdentityFromToken({
      principal: authenticatedPrincipal
    })
    this.logAdminAuthVerified({principal, context})
    if (principal.tenantIds && principal.tenantIds.length === 1) {
      setLogContextFields({
        tenant_id: principal.tenantIds[0]
      })
    }

    return principal
  }

  public async authenticateRequest({request}: {request: IncomingMessage}) {
    return this.authenticateFromAuthorizationHeader({
      authorizationHeader: request.headers.authorization,
      context: 'request'
    })
  }

  public async handleRequest({
    request,
    response,
    handler
  }: {
    request: Request
    response: Response
    handler: (context: RequestHandlerContext) => void | Promise<void>
  }) {
    const correlationId = extractCorrelationId(request)
    const requestId = randomUUID()
    const startedAtMs = Date.now()
    const requestMethod = request.method ?? 'GET'

    return runWithLogContext(
      {
        correlation_id: correlationId,
        request_id: requestId,
        method: requestMethod
      },
      async () => {
        let method = requestMethod
        let pathname = '/'
        let responseReasonCode: string | undefined

        this.logger.info({
          event: 'request.received',
          component: 'http.server',
          message: 'Request received',
          route: sanitizeRouteForLog({rawUrl: request.url}),
          method: requestMethod
        })

        try {
          method = requestMethod
          const url = parseUrl(request)
          pathname = url.pathname
          setLogContextFields({
            route: pathname,
            method
          })

          await handler({
            correlationId,
            method,
            pathname,
            url
          })
        } catch (error) {
          if (isAppError(error)) {
            responseReasonCode = error.code
            this.logger.warn({
              event: 'request.rejected',
              component: 'http.server',
              message: `Request rejected: ${error.code}`,
              reason_code: error.code,
              route: pathname,
              method
            })

            sendError({
              response,
              status: error.status,
              error: error.code,
              message: error.message,
              correlationId
            })
            return
          }

          responseReasonCode = 'internal_error'
          this.logger.error({
            event: 'request.failed',
            component: 'http.server',
            message: 'Unexpected internal error',
            reason_code: 'internal_error',
            route: pathname,
            method,
            metadata: {
              error
            }
          })

          sendError({
            response,
            status: 500,
            error: 'internal_error',
            message: 'Unexpected internal error',
            correlationId
          })
        } finally {
          const durationMs = Math.max(0, Date.now() - startedAtMs)
          const statusCode = response.statusCode
          const baseLog = {
            event: 'request.completed',
            component: 'http.server',
            message: 'Request completed',
            route: pathname,
            method,
            status_code: statusCode,
            duration_ms: durationMs,
            ...(responseReasonCode ? {reason_code: responseReasonCode} : {})
          }

          if (statusCode >= 500) {
            this.logger.error(baseLog)
          } else if (statusCode >= 400) {
            this.logger.warn(baseLog)
          } else {
            this.logger.info(baseLog)
          }
        }
      }
    )
  }

  private logAdminAuthVerified({
    principal,
    context
  }: {
    principal: AdminPrincipal
    context: 'oauth_callback' | 'request'
  }) {
    this.logger.info({
      event: 'auth.admin.verified',
      component: 'server.auth',
      message: 'Admin authentication succeeded',
      metadata: {
        auth_mode: principal.authContext.mode,
        role_count: principal.roles.length,
        tenant_count: principal.tenantIds?.length ?? 0,
        context
      }
    })
  }

  private normalizeIssuerForComparison(value: string) {
    return value.replace(/\/+$/u, '')
  }

  private parseIssuerHost({issuer}: {issuer: string}) {
    try {
      return new URL(issuer).hostname.toLowerCase()
    } catch {
      return ''
    }
  }
}

export type {ApprovalStatusFilter}
