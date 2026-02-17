import {createServer as createHttpServer, type IncomingMessage, type ServerResponse} from 'node:http';
import {createHmac, randomBytes, timingSafeEqual} from 'node:crypto';

import {
  OpenApiAdminAccessRequestApproveRequestSchema,
  OpenApiAdminAccessRequestDenyRequestSchema,
  OpenApiAdminAccessRequestListResponseSchema,
  OpenApiAdminAccessRequestStatusSchema,
  OpenApiAdminAccessRequestSchema,
  OpenApiAdminAuthProviderListResponseSchema,
  OpenApiAdminOAuthCallbackRequestSchema,
  OpenApiAdminOAuthCallbackResponseSchema,
  OpenApiAdminOAuthStartRequestSchema,
  OpenApiAdminOAuthStartResponseSchema,
  OpenApiAdminRoleSchema,
  OpenApiAdminSessionResponseSchema,
  OpenApiAdminSignupPolicySchema,
  OpenApiAdminSignupPolicyUpdateRequestSchema,
  OpenApiAdminUserListResponseSchema,
  OpenApiAdminUserStatusSchema,
  OpenApiAdminUserSchema,
  OpenApiAdminUserUpdateRequestSchema,
  OpenApiApprovalDecisionRequestSchema,
  OpenApiApprovalListResponseSchema,
  OpenApiApprovalResponseSchema,
  OpenApiAuditEventListResponseSchema,
  OpenApiIntegrationCreateResponseSchema,
  OpenApiIntegrationListResponseSchema,
  OpenApiIntegrationSchema,
  OpenApiIntegrationUpdateRequestSchema,
  OpenApiIntegrationWriteSchema,
  OpenApiManifestKeysSchema,
  OpenApiPolicyCreateResponseSchema,
  OpenApiPolicyListResponseSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateCreateResponseSchema,
  OpenApiTemplateListResponseSchema,
  OpenApiTemplateSchema,
  OpenApiTenantCreateRequestSchema,
  OpenApiTenantCreateResponseSchema,
  OpenApiTenantListResponseSchema,
  OpenApiWorkloadCreateRequestSchema,
  OpenApiWorkloadCreateResponseSchema,
  OpenApiWorkloadEnrollRequestSchema,
  OpenApiWorkloadEnrollResponseSchema,
  OpenApiWorkloadListResponseSchema,
  OpenApiWorkloadSchema,
  OpenApiWorkloadUpdateRequestSchema
} from '@broker-interceptor/schemas';
import {decodeJwt} from 'jose';
import {z} from 'zod';

import {requireAnyRole, requireTenantScope, type AdminPrincipal} from './auth';
import type {OidcAuthConfig, ServiceConfig} from './config';
import type {DependencyBridge} from './dependencyBridge';
import {badRequest, isAppError, notFound} from './errors';
import {
  approvalStatusFilterSchema,
  auditFilterSchema,
  ControlPlaneRepository,
  type ApprovalStatusFilter
} from './repository';
import {extractCorrelationId, parseJsonBody, parseQuery, sendError, sendJson, sendNoContent} from './http';

const tenantWorkloadsPathPattern = /^\/v1\/tenants\/([^/]+)\/workloads$/u;
const workloadEnrollPathPattern = /^\/v1\/workloads\/([^/]+)\/enroll$/u;
const workloadPathPattern = /^\/v1\/workloads\/([^/]+)$/u;
const tenantIntegrationsPathPattern = /^\/v1\/tenants\/([^/]+)\/integrations$/u;
const integrationPathPattern = /^\/v1\/integrations\/([^/]+)$/u;
const templateVersionPathPattern = /^\/v1\/templates\/([^/]+)\/versions\/([^/]+)$/u;
const policyPathPattern = /^\/v1\/policies\/([^/]+)$/u;
const approvalApprovePathPattern = /^\/v1\/approvals\/([^/]+)\/approve$/u;
const approvalDenyPathPattern = /^\/v1\/approvals\/([^/]+)\/deny$/u;
const adminUserPathPattern = /^\/v1\/admin\/users\/([^/]+)$/u;
const adminAccessRequestApprovePathPattern = /^\/v1\/admin\/access-requests\/([^/]+)\/approve$/u;
const adminAccessRequestDenyPathPattern = /^\/v1\/admin\/access-requests\/([^/]+)\/deny$/u;
const auth0HostSuffix = '.auth0.com';
const adminOAuthStateVersion = 1;
const defaultAdminOAuthSessionTtlSeconds = 3600;

const adminOAuthStatePayloadSchema = z
  .object({
    v: z.literal(adminOAuthStateVersion),
    provider: z.enum(['google', 'github']),
    redirect_uri: z.string().url(),
    nonce: z.string().min(16),
    iat: z.number().int(),
    exp: z.number().int()
  })
  .strict();

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
  .passthrough();

type OAuthTokenExchangeResult = {
  sessionToken: string;
  idToken?: string;
  expiresIn?: number;
};

const decodePathParam = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    throw badRequest('path_param_invalid', 'Path parameter encoding is invalid');
  }
};

const encodeBase64Url = (value: Buffer | string) => Buffer.from(value).toString('base64url');

const decodeBase64Url = (value: string) => Buffer.from(value, 'base64url');

const getInteractiveOidcAuth = ({
  config
}: {
  config: ServiceConfig;
}): (OidcAuthConfig & {oauth: OidcAuthConfig['oauth'] & {clientId: string}}) | null => {
  if (config.auth.mode !== 'oidc') {
    return null;
  }

  if (typeof config.auth.oauth.clientId !== 'string' || config.auth.oauth.clientId.length === 0) {
    return null;
  }

  return {
    ...config.auth,
    oauth: {
      ...config.auth.oauth,
      clientId: config.auth.oauth.clientId
    }
  };
};

const parseIssuerHost = ({issuer}: {issuer: string}) => {
  try {
    return new URL(issuer).hostname.toLowerCase();
  } catch {
    return '';
  }
};

const normalizeIssuerForComparison = (value: string) => value.replace(/\/+$/u, '');

const enrichPrincipalWithIdTokenEmailVerification = ({
  principal,
  idTokenPayload
}: {
  principal: AdminPrincipal;
  idTokenPayload?: ReturnType<typeof decodeJwt>;
}): AdminPrincipal => {
  if (principal.authContext.mode !== 'oidc' || !idTokenPayload || principal.emailVerified === true) {
    return principal;
  }

  if (idTokenPayload.email_verified !== true) {
    return principal;
  }

  const idTokenSubject = typeof idTokenPayload.sub === 'string' ? idTokenPayload.sub : undefined;
  const idTokenIssuer = typeof idTokenPayload.iss === 'string' ? idTokenPayload.iss : undefined;
  const idTokenEmail = typeof idTokenPayload.email === 'string' ? idTokenPayload.email.toLowerCase() : undefined;

  if (
    !idTokenSubject ||
    !idTokenIssuer ||
    !idTokenEmail ||
    idTokenSubject !== principal.subject ||
    normalizeIssuerForComparison(idTokenIssuer) !== normalizeIssuerForComparison(principal.issuer) ||
    idTokenEmail !== principal.email.toLowerCase()
  ) {
    return principal;
  }

  return {
    ...principal,
    emailVerified: true
  };
};

const resolveProviderConnectionHint = ({config, provider}: {config: ServiceConfig; provider: 'google' | 'github'}) => {
  if (config.auth.mode !== 'oidc') {
    return undefined;
  }

  const configured =
    provider === 'google' ? config.auth.oauth.providerConnections.google : config.auth.oauth.providerConnections.github;
  if (configured) {
    return configured;
  }

  const issuerHost = parseIssuerHost({issuer: config.auth.issuer});
  if (!issuerHost.endsWith(auth0HostSuffix)) {
    return undefined;
  }

  if (provider === 'google') {
    return 'google-oauth2';
  }

  if (provider === 'github') {
    return 'github';
  }

  return undefined;
};

const isOidcInteractiveOAuthEnabled = ({config}: {config: ServiceConfig}) => getInteractiveOidcAuth({config}) !== null;

const createAdminOAuthState = ({
  config,
  provider,
  redirectUri,
  nonce,
  now
}: {
  config: ServiceConfig;
  provider: 'google' | 'github';
  redirectUri: string;
  nonce: string;
  now: Date;
}) => {
  const payload = adminOAuthStatePayloadSchema.parse({
    v: adminOAuthStateVersion,
    provider,
    redirect_uri: redirectUri,
    nonce,
    iat: Math.floor(now.getTime() / 1000),
    exp: Math.floor(now.getTime() / 1000) + (config.auth.mode === 'oidc' ? config.auth.oauth.stateTtlSeconds : 600)
  });
  const encodedPayload = encodeBase64Url(JSON.stringify(payload));
  const signature = createHmac('sha256', config.secretKey).update(encodedPayload).digest();
  return `${encodedPayload}.${encodeBase64Url(signature)}`;
};

const verifyAdminOAuthState = ({
  config,
  state,
  provider,
  redirectUri,
  now
}: {
  config: ServiceConfig;
  state: string;
  provider: 'google' | 'github';
  redirectUri: string;
  now: Date;
}) => {
  const [encodedPayload, encodedSignature] = state.split('.');
  if (!encodedPayload || !encodedSignature) {
    throw badRequest('admin_oauth_state_invalid', 'OAuth state is malformed');
  }

  const expectedSignature = createHmac('sha256', config.secretKey).update(encodedPayload).digest();
  const signature = decodeBase64Url(encodedSignature);
  if (signature.length !== expectedSignature.length || !timingSafeEqual(signature, expectedSignature)) {
    throw badRequest('admin_oauth_state_invalid', 'OAuth state signature is invalid');
  }

  let payload: z.infer<typeof adminOAuthStatePayloadSchema>;
  try {
    payload = adminOAuthStatePayloadSchema.parse(JSON.parse(decodeBase64Url(encodedPayload).toString('utf8')));
  } catch {
    throw badRequest('admin_oauth_state_invalid', 'OAuth state payload is invalid');
  }

  if (payload.provider !== provider) {
    throw badRequest('admin_oauth_state_invalid', 'OAuth state provider mismatch');
  }
  if (payload.redirect_uri !== redirectUri) {
    throw badRequest('admin_oauth_state_invalid', 'OAuth state redirect_uri mismatch');
  }

  if (payload.exp <= Math.floor(now.getTime() / 1000)) {
    throw badRequest('admin_oauth_state_expired', 'OAuth state has expired');
  }

  return payload;
};

const resolveOAuthTokenUrl = ({config}: {config: ServiceConfig}) => {
  if (config.auth.mode !== 'oidc') {
    return undefined;
  }

  return config.auth.oauth.tokenUrl;
};

const exchangeOAuthAuthorizationCode = async ({
  config,
  code,
  redirectUri,
  codeVerifier
}: {
  config: ServiceConfig;
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<OAuthTokenExchangeResult> => {
  const oidcAuth = getInteractiveOidcAuth({config});
  if (!oidcAuth) {
    throw badRequest('admin_oauth_not_configured', 'OIDC OAuth client configuration is incomplete');
  }

  const tokenUrl = resolveOAuthTokenUrl({config});
  if (!tokenUrl) {
    throw badRequest('admin_oauth_not_configured', 'OIDC token endpoint is not configured');
  }

  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: oidcAuth.oauth.clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  });
  if (oidcAuth.oauth.clientSecret) {
    form.set('client_secret', oidcAuth.oauth.clientSecret);
  }

  const tokenResponse = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json'
    },
    body: form.toString()
  });

  let parsedBody: z.infer<typeof oidcTokenResponseSchema>;
  try {
    parsedBody = oidcTokenResponseSchema.parse(await tokenResponse.json());
  } catch {
    throw badRequest('admin_oauth_callback_invalid', 'OAuth token endpoint returned an invalid payload');
  }

  if (!tokenResponse.ok || parsedBody.error) {
    throw badRequest(
      'admin_oauth_callback_invalid',
      parsedBody.error_description ?? parsedBody.error ?? 'OAuth code exchange failed'
    );
  }

  const sessionToken = parsedBody.access_token;
  if (!sessionToken) {
    throw badRequest('admin_oauth_callback_invalid', 'OAuth token response did not include a usable access_token');
  }

  return {
    sessionToken,
    idToken: parsedBody.id_token,
    expiresIn: parsedBody.expires_in
  };
};

const resolveSessionExpiration = ({idToken, expiresIn, now}: {idToken?: string; expiresIn?: number; now: Date}) => {
  if (typeof expiresIn === 'number' && Number.isFinite(expiresIn) && expiresIn > 0) {
    return new Date(now.getTime() + expiresIn * 1000).toISOString();
  }

  if (idToken) {
    try {
      const payload = decodeJwt(idToken);
      if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
        return new Date(payload.exp * 1000).toISOString();
      }
    } catch {
      // ignore and fall back to default ttl
    }
  }

  return new Date(now.getTime() + defaultAdminOAuthSessionTtlSeconds * 1000).toISOString();
};

const toDate = (value: string | undefined) => (value ? new Date(value) : undefined);

const resolveAuditTenantId = ({principal, tenantId}: {principal: AdminPrincipal; tenantId?: string}) => {
  if (tenantId) {
    return tenantId;
  }

  if (principal.tenantIds && principal.tenantIds.length > 0) {
    return principal.tenantIds[0];
  }

  return 'global';
};

const listAccessRoles = ['owner', 'admin', 'auditor', 'operator'] as const;
const writeAccessRoles = ['owner', 'admin'] as const;
const approvalDecisionRoles = ['owner', 'admin', 'operator'] as const;

const approvalStatusQuerySchema = z
  .object({
    status: approvalStatusFilterSchema.optional()
  })
  .strict();

const adminListLimitQuerySchema = z.preprocess(value => {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'string') {
    return value;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? value : parsed;
}, z.number().int().min(1).max(100).optional());

const adminUserListQuerySchema = z
  .object({
    status: OpenApiAdminUserStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: OpenApiAdminRoleSchema.optional(),
    search: z.string().min(1).optional(),
    limit: adminListLimitQuerySchema,
    cursor: z.string().min(1).optional()
  })
  .strict();

const adminAccessRequestListQuerySchema = z
  .object({
    status: OpenApiAdminAccessRequestStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: OpenApiAdminRoleSchema.optional(),
    search: z.string().min(1).optional(),
    limit: adminListLimitQuerySchema,
    cursor: z.string().min(1).optional()
  })
  .strict();

const appendAuditEventNonBlocking = ({
  dependencyBridge,
  event,
  correlationId
}: {
  dependencyBridge: DependencyBridge;
  event: Parameters<ControlPlaneRepository['appendAuditEvent']>[0]['event'];
  correlationId: string;
}) => {
  void dependencyBridge.appendAuditEventWithAuditPackage({event}).catch(() => {
    console.error(
      JSON.stringify({
        level: 'error',
        message: 'audit_emit_failed',
        correlation_id: correlationId,
        event_id: event.event_id
      })
    );
  });
};

export type CreateAdminApiServerInput = {
  config: ServiceConfig;
  repository: ControlPlaneRepository;
  dependencyBridge: DependencyBridge;
};

const normalizeTenantAuditFilter = ({
  principal,
  requestedTenantId
}: {
  principal: AdminPrincipal;
  requestedTenantId?: string;
}) => {
  if (principal.roles.includes('owner')) {
    return requestedTenantId;
  }

  if (!principal.tenantIds || principal.tenantIds.length === 0) {
    throw notFound('tenant_not_found', 'No tenant scope is configured for this principal');
  }

  if (!requestedTenantId) {
    if (principal.tenantIds.length === 1) {
      return principal.tenantIds[0];
    }

    throw badRequest('tenant_filter_required', 'tenant_id query filter is required for multi-tenant principals');
  }

  if (!principal.tenantIds.includes(requestedTenantId)) {
    throw badRequest('tenant_filter_forbidden', 'tenant_id query filter is outside principal scope');
  }

  return requestedTenantId;
};

const parseUrl = (request: IncomingMessage) => {
  try {
    const host = request.headers.host ?? 'localhost';
    return new URL(request.url ?? '/', `http://${host}`);
  } catch {
    throw badRequest('request_url_invalid', 'Request URL is invalid');
  }
};

const requireWorkloadTenantScope = async ({
  repository,
  principal,
  workloadId
}: {
  repository: ControlPlaneRepository;
  principal: AdminPrincipal;
  workloadId: string;
}) => {
  const workload = await repository.getWorkload({workloadId});
  requireTenantScope({principal, tenantId: workload.tenant_id});
  return workload;
};

const requireIntegrationTenantScope = async ({
  repository,
  principal,
  integrationId
}: {
  repository: ControlPlaneRepository;
  principal: AdminPrincipal;
  integrationId: string;
}) => {
  const integration = await repository.getIntegration({integrationId});
  requireTenantScope({principal, tenantId: integration.tenant_id});
  return integration;
};

export const createAdminApiRequestHandler = ({config, repository, dependencyBridge}: CreateAdminApiServerInput) => {
  const handleRequest = async (request: IncomingMessage, response: ServerResponse) => {
    const correlationId = extractCorrelationId(request);

    try {
      const method = request.method ?? 'GET';
      const url = parseUrl(request);
      const pathname = url.pathname;

      if (method === 'GET' && pathname === '/healthz') {
        sendJson({
          response,
          status: 200,
          correlationId,
          payload: {status: 'ok'}
        });
        return;
      }

      if (method === 'GET' && pathname === '/v1/admin/auth/providers') {
        const interactiveOauthEnabled = isOidcInteractiveOAuthEnabled({config});
        const payload = OpenApiAdminAuthProviderListResponseSchema.parse({
          providers: [
            {
              provider: 'google',
              enabled: interactiveOauthEnabled
            },
            {
              provider: 'github',
              enabled: interactiveOauthEnabled
            }
          ]
        });

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      if (method === 'POST' && pathname === '/v1/admin/auth/oauth/start') {
        const oidcAuth = getInteractiveOidcAuth({config});
        if (!oidcAuth) {
          throw badRequest('admin_oauth_not_configured', 'OIDC OAuth interactive login is not configured');
        }

        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminOAuthStartRequestSchema,
          maxBodyBytes: config.maxBodyBytes,
          required: true
        });

        const now = new Date();
        const nonce = randomBytes(24).toString('base64url');
        const state = createAdminOAuthState({
          config,
          provider: body.provider,
          redirectUri: body.redirect_uri,
          nonce,
          now
        });

        const authorizationUrl = new URL(oidcAuth.oauth.authorizationUrl);
        authorizationUrl.searchParams.set('response_type', 'code');
        authorizationUrl.searchParams.set('client_id', oidcAuth.oauth.clientId);
        authorizationUrl.searchParams.set('redirect_uri', body.redirect_uri);
        authorizationUrl.searchParams.set('scope', oidcAuth.oauth.scope);
        authorizationUrl.searchParams.set('audience', oidcAuth.audience);
        authorizationUrl.searchParams.set('state', state);
        authorizationUrl.searchParams.set('nonce', nonce);
        authorizationUrl.searchParams.set('code_challenge', body.code_challenge);
        authorizationUrl.searchParams.set('code_challenge_method', body.code_challenge_method);

        const connectionHint = resolveProviderConnectionHint({
          config,
          provider: body.provider
        });
        if (connectionHint) {
          authorizationUrl.searchParams.set('connection', connectionHint);
        }

        const payload = OpenApiAdminOAuthStartResponseSchema.parse({
          authorization_url: authorizationUrl.toString(),
          state,
          nonce
        });
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      if (method === 'POST' && pathname === '/v1/admin/auth/oauth/callback') {
        if (!isOidcInteractiveOAuthEnabled({config})) {
          throw badRequest('admin_oauth_not_configured', 'OIDC OAuth interactive login is not configured');
        }

        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminOAuthCallbackRequestSchema,
          maxBodyBytes: config.maxBodyBytes,
          required: true
        });

        const now = new Date();
        const statePayload = verifyAdminOAuthState({
          config,
          state: body.state,
          provider: body.provider,
          redirectUri: body.redirect_uri,
          now
        });

        const tokenExchange = await exchangeOAuthAuthorizationCode({
          config,
          code: body.code,
          redirectUri: body.redirect_uri,
          codeVerifier: body.code_verifier
        });

        let idTokenPayload: ReturnType<typeof decodeJwt> | undefined;
        if (tokenExchange.idToken) {
          try {
            idTokenPayload = decodeJwt(tokenExchange.idToken);
          } catch {
            throw badRequest('admin_oauth_callback_invalid', 'OIDC id_token is malformed');
          }

          if (typeof idTokenPayload.nonce !== 'string' || idTokenPayload.nonce !== statePayload.nonce) {
            throw badRequest('admin_oauth_nonce_invalid', 'OIDC nonce validation failed');
          }
        }

        const authenticatedPrincipal = await dependencyBridge.authenticateAdminPrincipal({
          authorizationHeader: `Bearer ${tokenExchange.sessionToken}`
        });
        const principalForIdentityResolution = enrichPrincipalWithIdTokenEmailVerification({
          principal: authenticatedPrincipal,
          idTokenPayload
        });
        const principal = await dependencyBridge.resolveAdminIdentityFromToken({
          principal: principalForIdentityResolution
        });

        const payload = OpenApiAdminOAuthCallbackResponseSchema.parse({
          session_id: tokenExchange.sessionToken,
          expires_at: resolveSessionExpiration({
            idToken: tokenExchange.idToken,
            expiresIn: tokenExchange.expiresIn,
            now
          }),
          principal: {
            subject: principal.subject,
            issuer: principal.issuer,
            email: principal.email,
            ...(principal.name ? {name: principal.name} : {}),
            roles: principal.roles,
            tenant_ids: principal.tenantIds ?? []
          }
        });

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      const authenticatedPrincipal = await dependencyBridge.authenticateAdminPrincipal({
        authorizationHeader: request.headers.authorization
      });
      const principal = await dependencyBridge.resolveAdminIdentityFromToken({
        principal: authenticatedPrincipal
      });

      if (method === 'GET' && pathname === '/v1/admin/auth/session') {
        const payload = OpenApiAdminSessionResponseSchema.parse({
          authenticated: true,
          ...(principal.authContext.sid ? {session_id: principal.authContext.sid} : {}),
          principal: {
            subject: principal.subject,
            issuer: principal.issuer,
            email: principal.email,
            ...(principal.name ? {name: principal.name} : {}),
            roles: principal.roles,
            tenant_ids: principal.tenantIds ?? []
          }
        });

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      if (pathname === '/v1/admin/auth/signup-policy') {
        requireAnyRole({principal, allowed: ['owner', 'admin']});

        if (method === 'GET') {
          const policy = await repository.getAdminSignupPolicy();
          const payload = OpenApiAdminSignupPolicySchema.parse(policy);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });
          return;
        }

        if (method === 'PATCH') {
          if (!principal.roles.includes('owner')) {
            throw badRequest('admin_signup_policy_forbidden', 'Only owner role can update admin signup policy');
          }

          const body = await parseJsonBody({
            request,
            schema: OpenApiAdminSignupPolicyUpdateRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });

          const updated =
            body.require_verified_email === undefined && body.allowed_email_domains === undefined
              ? await dependencyBridge.setAdminSignupMode({
                  mode: body.new_user_mode,
                  actor: principal
                })
              : await repository.setAdminSignupPolicy({
                  policy: body,
                  actor: principal.subject
                });

          const payload = OpenApiAdminSignupPolicySchema.parse(updated);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'admin.signup_policy.update',
              tenantId: resolveAuditTenantId({principal}),
              message: `Admin signup mode updated to ${updated.new_user_mode}`
            })
          });
          return;
        }
      }

      if (method === 'GET' && pathname === '/v1/admin/users') {
        requireAnyRole({principal, allowed: ['owner']});

        const query = parseQuery({
          searchParams: url.searchParams,
          schema: adminUserListQuerySchema
        });
        const users = await dependencyBridge.listAdminUsers({
          actor: principal,
          ...(query.status ? {status: query.status} : {}),
          ...(query.tenant_id ? {tenantId: query.tenant_id} : {}),
          ...(query.role ? {role: query.role} : {}),
          ...(query.search ? {search: query.search} : {}),
          ...(typeof query.limit === 'number' ? {limit: query.limit} : {}),
          ...(query.cursor ? {cursor: query.cursor} : {})
        });

        const payload = OpenApiAdminUserListResponseSchema.parse(users);
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      {
        const match = pathname.match(adminUserPathPattern);
        if (match && method === 'PATCH') {
          requireAnyRole({principal, allowed: ['owner']});

          const identityId = decodePathParam(match[1]);
          const body = await parseJsonBody({
            request,
            schema: OpenApiAdminUserUpdateRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });

          if (body.status === undefined && body.roles === undefined && body.tenant_ids === undefined) {
            throw badRequest(
              'admin_user_update_invalid',
              'At least one of status, roles, or tenant_ids must be provided'
            );
          }

          const updatedUser = await dependencyBridge.updateAdminUser({
            identityId,
            actor: principal,
            ...(body.status !== undefined ? {status: body.status} : {}),
            ...(body.roles !== undefined ? {roles: body.roles} : {}),
            ...(body.tenant_ids !== undefined ? {tenantIds: body.tenant_ids} : {})
          });

          const payload = OpenApiAdminUserSchema.parse(updatedUser);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'admin.user.update',
              tenantId: resolveAuditTenantId({principal}),
              message: `Admin user ${identityId} updated`
            })
          });
          return;
        }
      }

      if (method === 'GET' && pathname === '/v1/admin/access-requests') {
        requireAnyRole({principal, allowed: ['owner']});

        const query = parseQuery({
          searchParams: url.searchParams,
          schema: adminAccessRequestListQuerySchema
        });
        const requests = await dependencyBridge.listAdminAccessRequests({
          actor: principal,
          ...(query.status ? {status: query.status} : {}),
          ...(query.tenant_id ? {tenantId: query.tenant_id} : {}),
          ...(query.role ? {role: query.role} : {}),
          ...(query.search ? {search: query.search} : {}),
          ...(typeof query.limit === 'number' ? {limit: query.limit} : {}),
          ...(query.cursor ? {cursor: query.cursor} : {})
        });

        const payload = OpenApiAdminAccessRequestListResponseSchema.parse(requests);
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      {
        const match = pathname.match(adminAccessRequestApprovePathPattern);
        if (match && method === 'POST') {
          requireAnyRole({principal, allowed: ['owner']});

          const requestId = decodePathParam(match[1]);
          const body = await parseJsonBody({
            request,
            schema: OpenApiAdminAccessRequestApproveRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });
          const approved = await dependencyBridge.approveAdminAccessRequestWithOverrides({
            requestId,
            actor: principal,
            ...(body.roles !== undefined ? {roles: body.roles} : {}),
            ...(body.tenant_ids !== undefined ? {tenantIds: body.tenant_ids} : {}),
            ...(body.reason !== undefined ? {reason: body.reason} : {})
          });

          const payload = OpenApiAdminAccessRequestSchema.parse(approved);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'admin.access_request.approve',
              tenantId: resolveAuditTenantId({principal}),
              message: `Admin access request ${requestId} approved`
            })
          });
          return;
        }
      }

      {
        const match = pathname.match(adminAccessRequestDenyPathPattern);
        if (match && method === 'POST') {
          requireAnyRole({principal, allowed: ['owner']});

          const requestId = decodePathParam(match[1]);
          const body = await parseJsonBody({
            request,
            schema: OpenApiAdminAccessRequestDenyRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });
          const denied = await dependencyBridge.denyAdminAccessRequest({
            requestId,
            actor: principal,
            reason: body.reason
          });

          const payload = OpenApiAdminAccessRequestSchema.parse(denied);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'admin.access_request.deny',
              tenantId: resolveAuditTenantId({principal}),
              message: `Admin access request ${requestId} denied`
            })
          });
          return;
        }
      }

      if (method === 'POST' && pathname === '/v1/tenants') {
        requireAnyRole({principal, allowed: [...writeAccessRoles]});
        if (!principal.roles.includes('owner')) {
          throw badRequest('tenant_create_forbidden', 'Only owner role can create tenants');
        }

        const body = await parseJsonBody({
          request,
          schema: OpenApiTenantCreateRequestSchema,
          maxBodyBytes: config.maxBodyBytes,
          required: true
        });

        const tenant = await repository.createTenant({name: body.name});
        const payload = OpenApiTenantCreateResponseSchema.parse({tenant_id: tenant.tenant_id});

        sendJson({
          response,
          status: 201,
          correlationId,
          payload
        });

        appendAuditEventNonBlocking({
          dependencyBridge,
          correlationId,
          event: repository.createAdminAuditEvent({
            actor: principal,
            correlationId,
            action: 'tenant.create',
            tenantId: tenant.tenant_id,
            message: `Tenant ${tenant.tenant_id} created`
          })
        });
        return;
      }

      if (method === 'GET' && pathname === '/v1/tenants') {
        requireAnyRole({principal, allowed: [...listAccessRoles]});

        const tenants = (await repository.listTenants()).filter(tenant =>
          principal.roles.includes('owner') || !principal.tenantIds
            ? true
            : principal.tenantIds.includes(tenant.tenant_id)
        );

        const payload = OpenApiTenantListResponseSchema.parse({tenants});
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      {
        const match = pathname.match(tenantWorkloadsPathPattern);
        if (match) {
          const tenantId = decodePathParam(match[1]);
          requireTenantScope({principal, tenantId});

          if (method === 'POST') {
            requireAnyRole({principal, allowed: [...writeAccessRoles]});

            const body = await parseJsonBody({
              request,
              schema: OpenApiWorkloadCreateRequestSchema,
              maxBodyBytes: config.maxBodyBytes,
              required: true
            });
            const enrollmentModeContext = await dependencyBridge.ensureEnrollmentModeSupported_INCOMPLETE({
              enrollmentMode: body.enrollment_mode,
              tenantId,
              workloadName: body.name
            });

            const created = await repository.createWorkload({
              tenantId,
              name: body.name,
              ipAllowlist: body.ip_allowlist,
              enrollmentMode: body.enrollment_mode
            });

            const payload = OpenApiWorkloadCreateResponseSchema.parse({
              workload_id: created.workload.workload_id,
              enrollment_token: created.enrollmentToken,
              mtls_ca_pem: enrollmentModeContext.mtlsCaPem ?? dependencyBridge.getMtlsCaPemFromAuthPackage()
            });

            sendJson({
              response,
              status: 201,
              correlationId,
              payload
            });

            appendAuditEventNonBlocking({
              dependencyBridge,
              correlationId,
              event: repository.createAdminAuditEvent({
                actor: principal,
                correlationId,
                action: 'workload.create',
                tenantId,
                workloadId: created.workload.workload_id,
                message: `Workload ${created.workload.workload_id} created`
              })
            });
            return;
          }

          if (method === 'GET') {
            requireAnyRole({principal, allowed: [...listAccessRoles]});
            const workloads = await repository.listWorkloads({tenantId});
            const payload = OpenApiWorkloadListResponseSchema.parse({workloads});
            sendJson({
              response,
              status: 200,
              correlationId,
              payload
            });
            return;
          }
        }
      }

      {
        const match = pathname.match(workloadPathPattern);
        if (match && method === 'PATCH') {
          requireAnyRole({principal, allowed: [...writeAccessRoles]});

          const workloadId = decodePathParam(match[1]);
          await requireWorkloadTenantScope({repository, principal, workloadId});

          const body = await parseJsonBody({
            request,
            schema: OpenApiWorkloadUpdateRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });

          const updated = await repository.updateWorkload({
            workloadId,
            enabled: body.enabled,
            ipAllowlist: body.ip_allowlist
          });

          const payload = OpenApiWorkloadSchema.parse(updated);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'workload.update',
              tenantId: updated.tenant_id,
              workloadId: updated.workload_id,
              message: `Workload ${updated.workload_id} updated`
            })
          });
          return;
        }
      }

      {
        const match = pathname.match(workloadEnrollPathPattern);
        if (match && method === 'POST') {
          requireAnyRole({principal, allowed: [...writeAccessRoles]});

          const workloadId = decodePathParam(match[1]);
          const workload = await requireWorkloadTenantScope({repository, principal, workloadId});

          const body = await parseJsonBody({
            request,
            schema: OpenApiWorkloadEnrollRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });

          if (body.requested_ttl_seconds > config.clientCertTtlSecondsMax) {
            throw badRequest(
              'requested_ttl_exceeds_max',
              `requested_ttl_seconds must be <= ${config.clientCertTtlSecondsMax}`
            );
          }

          await repository.consumeEnrollmentToken({
            workloadId,
            enrollmentToken: body.enrollment_token
          });

          await dependencyBridge.validateEnrollmentCsrWithAuthPackage({
            csrPem: body.csr_pem,
            expectedSanUri: workload.mtls_san_uri,
            requireClientAuthEku: true
          });

          const issued = await dependencyBridge.issueWorkloadCertificateWithAuthPackage({
            input: {
              csrPem: body.csr_pem,
              workloadId,
              sanUri: workload.mtls_san_uri,
              ttlSeconds: body.requested_ttl_seconds
            }
          });

          const payload = OpenApiWorkloadEnrollResponseSchema.parse({
            client_cert_pem: issued.clientCertPem,
            ca_chain_pem: issued.caChainPem,
            expires_at: issued.expiresAt
          });

          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'workload.enroll',
              tenantId: workload.tenant_id,
              workloadId,
              message: `Workload ${workloadId} enrolled with a new client certificate`
            })
          });
          return;
        }
      }

      {
        const match = pathname.match(tenantIntegrationsPathPattern);
        if (match) {
          const tenantId = decodePathParam(match[1]);
          requireTenantScope({principal, tenantId});

          if (method === 'POST') {
            requireAnyRole({principal, allowed: [...writeAccessRoles]});

            const body = await parseJsonBody({
              request,
              schema: OpenApiIntegrationWriteSchema,
              maxBodyBytes: config.maxBodyBytes,
              required: true
            });

            const integration = await repository.createIntegration({
              tenantId,
              payload: body,
              secretKey: config.secretKey,
              secretKeyId: config.secretKeyId
            });

            const payload = OpenApiIntegrationCreateResponseSchema.parse({
              integration_id: integration.integration_id
            });

            sendJson({
              response,
              status: 201,
              correlationId,
              payload
            });

            appendAuditEventNonBlocking({
              dependencyBridge,
              correlationId,
              event: repository.createAdminAuditEvent({
                actor: principal,
                correlationId,
                action: 'integration.create',
                tenantId,
                integrationId: integration.integration_id,
                message: `Integration ${integration.integration_id} created`
              })
            });
            return;
          }

          if (method === 'GET') {
            requireAnyRole({principal, allowed: [...listAccessRoles]});

            const integrations = await repository.listIntegrations({tenantId});
            const payload = OpenApiIntegrationListResponseSchema.parse({integrations});

            sendJson({
              response,
              status: 200,
              correlationId,
              payload
            });
            return;
          }
        }
      }

      {
        const match = pathname.match(integrationPathPattern);
        if (match && method === 'PATCH') {
          requireAnyRole({principal, allowed: [...writeAccessRoles]});

          const integrationId = decodePathParam(match[1]);
          const integration = await requireIntegrationTenantScope({repository, principal, integrationId});

          const body = await parseJsonBody({
            request,
            schema: OpenApiIntegrationUpdateRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });

          const updated = await repository.updateIntegration({
            integrationId,
            enabled: body.enabled,
            templateId: body.template_id
          });

          const payload = OpenApiIntegrationSchema.parse(updated);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'integration.update',
              tenantId: integration.tenant_id,
              integrationId,
              message: `Integration ${integrationId} updated`
            })
          });
          return;
        }
      }

      if (method === 'POST' && pathname === '/v1/templates') {
        requireAnyRole({principal, allowed: [...writeAccessRoles]});

        const body = await parseJsonBody({
          request,
          schema: OpenApiTemplateSchema,
          maxBodyBytes: config.maxBodyBytes,
          required: true
        });

        const created = await repository.createTemplate({payload: body});
        const payload = OpenApiTemplateCreateResponseSchema.parse(created);

        sendJson({
          response,
          status: 201,
          correlationId,
          payload
        });

        appendAuditEventNonBlocking({
          dependencyBridge,
          correlationId,
          event: repository.createAdminAuditEvent({
            actor: principal,
            correlationId,
            action: 'template.create',
            tenantId: resolveAuditTenantId({principal}),
            message: `Template ${created.template_id} v${created.version} created`
          })
        });
        return;
      }

      if (method === 'GET' && pathname === '/v1/templates') {
        requireAnyRole({principal, allowed: [...listAccessRoles]});

        const templates = await repository.listTemplates();
        const payload = OpenApiTemplateListResponseSchema.parse({templates});
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      {
        const match = pathname.match(templateVersionPathPattern);
        if (match && method === 'GET') {
          requireAnyRole({principal, allowed: [...listAccessRoles]});

          const templateId = decodePathParam(match[1]);
          const versionValue = Number.parseInt(decodePathParam(match[2]), 10);
          if (Number.isNaN(versionValue) || versionValue < 1) {
            throw badRequest('template_version_invalid', 'Template version must be a positive integer');
          }

          const template = await repository.getTemplateVersion({templateId, version: versionValue});
          const payload = OpenApiTemplateSchema.parse(template);
          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });
          return;
        }
      }

      if (method === 'POST' && pathname === '/v1/policies') {
        requireAnyRole({principal, allowed: [...writeAccessRoles]});

        const body = await parseJsonBody({
          request,
          schema: OpenApiPolicyRuleSchema,
          maxBodyBytes: config.maxBodyBytes,
          required: true
        });

        const policyPayload = dependencyBridge.validatePolicyRuleWithPolicyEngine({
          policy: body
        });
        requireTenantScope({principal, tenantId: policyPayload.scope.tenant_id});
        const created = await repository.createPolicy({payload: policyPayload});

        const payload = OpenApiPolicyCreateResponseSchema.parse({
          policy_id: created.policy_id ?? ''
        });

        sendJson({
          response,
          status: 201,
          correlationId,
          payload
        });

        appendAuditEventNonBlocking({
          dependencyBridge,
          correlationId,
          event: repository.createPolicyAuditEvent({
            actor: principal,
            correlationId,
            tenantId: created.scope.tenant_id,
            policy: created,
            action: 'created',
            message: `Policy ${created.policy_id} created`
          })
        });
        return;
      }

      if (method === 'GET' && pathname === '/v1/policies') {
        requireAnyRole({principal, allowed: [...listAccessRoles]});

        const policies = (await repository.listPolicies()).filter(policy =>
          principal.roles.includes('owner') || !principal.tenantIds
            ? true
            : principal.tenantIds.includes(policy.scope.tenant_id)
        );

        const payload = OpenApiPolicyListResponseSchema.parse({policies});
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      {
        const match = pathname.match(policyPathPattern);
        if (match && method === 'DELETE') {
          requireAnyRole({principal, allowed: [...writeAccessRoles]});

          const policyId = decodePathParam(match[1]);
          const policy = await repository.getPolicy({policyId});
          requireTenantScope({principal, tenantId: policy.scope.tenant_id});
          await repository.deletePolicy({policyId});

          sendNoContent({response, correlationId});

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createPolicyAuditEvent({
              actor: principal,
              correlationId,
              tenantId: policy.scope.tenant_id,
              policy,
              action: 'deleted',
              message: `Policy ${policyId} deleted`
            })
          });
          return;
        }
      }

      if (method === 'GET' && pathname === '/v1/approvals') {
        requireAnyRole({principal, allowed: [...listAccessRoles]});

        const query = parseQuery({searchParams: url.searchParams, schema: approvalStatusQuerySchema});
        const approvals = await repository.listApprovals({
          status: query.status as ApprovalStatusFilter | undefined
        });

        const scopedApprovals = approvals.filter(approval => {
          if (principal.roles.includes('owner')) {
            return true;
          }

          if (!principal.tenantIds || principal.tenantIds.length === 0) {
            return false;
          }

          return principal.tenantIds.includes(approval.canonical_descriptor.tenant_id);
        });

        const payload = OpenApiApprovalListResponseSchema.parse({approvals: scopedApprovals});

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      {
        const match = pathname.match(approvalApprovePathPattern);
        if (match && method === 'POST') {
          requireAnyRole({principal, allowed: [...approvalDecisionRoles]});

          const approvalId = decodePathParam(match[1]);
          const approval = await repository.getApproval({approvalId});
          requireTenantScope({
            principal,
            tenantId: approval.canonical_descriptor.tenant_id
          });

          const body = await parseJsonBody({
            request,
            schema: OpenApiApprovalDecisionRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: true
          });

          const result = await repository.decideApproval({
            approvalId,
            decision: 'approved',
            request: body
          });

          const payload = OpenApiApprovalResponseSchema.parse({
            approval_id: result.approval.approval_id,
            status: 'approved'
          });

          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'approval.approve',
              tenantId: result.approval.canonical_descriptor.tenant_id,
              message: `Approval ${result.approval.approval_id} approved`
            })
          });

          if (result.derivedPolicy) {
            appendAuditEventNonBlocking({
              dependencyBridge,
              correlationId,
              event: repository.createPolicyAuditEvent({
                actor: principal,
                correlationId,
                tenantId: result.derivedPolicy.scope.tenant_id,
                policy: result.derivedPolicy,
                action: 'derived',
                message: `Policy ${result.derivedPolicy.policy_id} derived from approval ${result.approval.approval_id}`
              })
            });
          }

          return;
        }
      }

      {
        const match = pathname.match(approvalDenyPathPattern);
        if (match && method === 'POST') {
          requireAnyRole({principal, allowed: [...approvalDecisionRoles]});

          const approvalId = decodePathParam(match[1]);
          const approval = await repository.getApproval({approvalId});
          requireTenantScope({
            principal,
            tenantId: approval.canonical_descriptor.tenant_id
          });

          const body = await parseJsonBody({
            request,
            schema: OpenApiApprovalDecisionRequestSchema,
            maxBodyBytes: config.maxBodyBytes,
            required: false
          });

          const decisionPayload =
            body ??
            OpenApiApprovalDecisionRequestSchema.parse({
              mode: 'once'
            });

          const result = await repository.decideApproval({
            approvalId,
            decision: 'denied',
            request: decisionPayload
          });

          const payload = OpenApiApprovalResponseSchema.parse({
            approval_id: result.approval.approval_id,
            status: 'denied'
          });

          sendJson({
            response,
            status: 200,
            correlationId,
            payload
          });

          appendAuditEventNonBlocking({
            dependencyBridge,
            correlationId,
            event: repository.createAdminAuditEvent({
              actor: principal,
              correlationId,
              action: 'approval.deny',
              tenantId: result.approval.canonical_descriptor.tenant_id,
              message: `Approval ${result.approval.approval_id} denied`
            })
          });

          if (result.derivedPolicy) {
            appendAuditEventNonBlocking({
              dependencyBridge,
              correlationId,
              event: repository.createPolicyAuditEvent({
                actor: principal,
                correlationId,
                tenantId: result.derivedPolicy.scope.tenant_id,
                policy: result.derivedPolicy,
                action: 'derived',
                message: `Policy ${result.derivedPolicy.policy_id} derived from denied approval ${result.approval.approval_id}`
              })
            });
          }

          return;
        }
      }

      if (method === 'GET' && pathname === '/v1/audit/events') {
        requireAnyRole({principal, allowed: ['owner', 'admin', 'auditor']});

        const query = parseQuery({searchParams: url.searchParams, schema: auditFilterSchema});
        const tenantId = normalizeTenantAuditFilter({
          principal,
          requestedTenantId: query.tenant_id
        });

        const timeMin = toDate(query.time_min);
        const timeMax = toDate(query.time_max);
        if (timeMin && timeMax && timeMin > timeMax) {
          throw badRequest('time_range_invalid', 'time_min must be <= time_max');
        }

        const events = await dependencyBridge.queryAuditEventsWithAuditPackage({
          query: {
            ...(query.time_min ? {time_min: query.time_min} : {}),
            ...(query.time_max ? {time_max: query.time_max} : {}),
            ...(tenantId ? {tenant_id: tenantId} : {}),
            ...(query.workload_id ? {workload_id: query.workload_id} : {}),
            ...(query.integration_id ? {integration_id: query.integration_id} : {}),
            ...(query.action_group ? {action_group: query.action_group} : {}),
            ...(query.decision ? {decision: query.decision} : {})
          }
        });

        const payload = OpenApiAuditEventListResponseSchema.parse({events});
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        });
        return;
      }

      if (method === 'GET' && pathname === '/v1/keys/manifest') {
        requireAnyRole({principal, allowed: [...listAccessRoles]});

        const manifestKeys = await repository.getManifestKeys();
        const payload = OpenApiManifestKeysSchema.parse(manifestKeys.payload);

        sendJson({
          response,
          status: 200,
          correlationId,
          payload,
          headers: {
            'cache-control': 'public, max-age=60, must-revalidate',
            etag: manifestKeys.etag
          }
        });
        return;
      }

      throw notFound('route_not_found', 'Route not found');
    } catch (error) {
      if (isAppError(error)) {
        sendError({
          response,
          status: error.status,
          error: error.code,
          message: error.message,
          correlationId
        });
        return;
      }

      sendError({
        response,
        status: 500,
        error: 'internal_error',
        message: 'Unexpected internal error',
        correlationId
      });
    }
  };

  return handleRequest;
};

export const createAdminApiServer = (input: CreateAdminApiServerInput) => {
  const handleRequest = createAdminApiRequestHandler(input);

  return createHttpServer((request: IncomingMessage, response: ServerResponse) => {
    void handleRequest(request, response);
  });
};
