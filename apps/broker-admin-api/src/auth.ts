import {timingSafeEqual} from 'node:crypto';

import {createRemoteJWKSet, jwtVerify, type JWTPayload} from 'jose';
import {z} from 'zod';

import type {AuthConfig, OidcAuthConfig, StaticAuthConfig} from './config';
import {adminRoleSchema, type AdminRole} from './contracts';
import {forbidden, unauthorized} from './errors';

export type AdminPrincipal = {
  subject: string;
  issuer: string;
  email: string;
  name?: string;
  emailVerified?: boolean;
  roles: AdminRole[];
  tenantIds?: string[];
  authContext: {
    mode: 'static' | 'oidc';
    issuer: string;
    amr?: string[];
    acr?: string;
    sid?: string;
  };
};

const bearerPrefix = 'Bearer ';
const STATIC_PRINCIPAL_ISSUER = 'https://broker-admin.local/static';

const parseBearerToken = (authorizationHeader: string | undefined) => {
  if (!authorizationHeader || !authorizationHeader.startsWith(bearerPrefix)) {
    throw unauthorized('admin_auth_missing', 'Missing bearer token');
  }

  const token = authorizationHeader.slice(bearerPrefix.length).trim();
  if (!token) {
    throw unauthorized('admin_auth_missing', 'Missing bearer token');
  }

  return token;
};

const timingSafeEquals = (a: string, b: string) => {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return timingSafeEqual(aBuffer, bBuffer);
};

const normalizeRoles = (input: unknown): AdminRole[] | null => {
  if (!Array.isArray(input)) {
    return null;
  }

  const parsed = adminRoleSchema.array().safeParse(input);
  return parsed.success ? parsed.data : null;
};

const normalizeTenantIds = (input: unknown): string[] | undefined => {
  if (!Array.isArray(input)) {
    return undefined;
  }

  const parsed = z.array(z.string().min(1)).safeParse(input);
  return parsed.success ? parsed.data : undefined;
};

const normalizeStaticEmail = (subject: string) => {
  const normalized = subject.trim().toLowerCase();
  if (normalized.includes('@')) {
    return normalized;
  }

  const sanitized = normalized.replace(/[^a-z0-9._-]/gu, '_');
  return `${sanitized || 'admin'}@local.invalid`;
};

const readClaimAsString = ({payload, claimName}: {payload: JWTPayload; claimName: string}) => {
  // eslint-disable-next-line security/detect-object-injection -- claimName is configuration-controlled and used for OIDC claim mapping.
  const claimValue = payload[claimName];
  if (typeof claimValue !== 'string' || claimValue.trim().length === 0) {
    return undefined;
  }

  return claimValue.trim();
};

const normalizeIssuerForComparison = (value: string) => value.replace(/\/+$/u, '');

const parseOidcPrincipal = ({payload, config}: {payload: JWTPayload; config: OidcAuthConfig}): AdminPrincipal => {
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw unauthorized('admin_auth_subject_invalid', 'OIDC token subject is missing');
  }

  const roles = normalizeRoles(payload[config.roleClaim]);
  if (!roles || roles.length === 0) {
    throw unauthorized('admin_auth_roles_missing', 'OIDC token does not include admin roles');
  }

  const issuer = readClaimAsString({payload, claimName: 'iss'});
  if (!issuer) {
    throw unauthorized('admin_auth_issuer_missing', 'OIDC token issuer is missing');
  }

  const email = readClaimAsString({payload, claimName: config.emailClaim});
  if (!email) {
    throw unauthorized('admin_auth_email_missing', 'OIDC token email is missing');
  }

  const name = readClaimAsString({payload, claimName: config.nameClaim});
  const tenantIds = normalizeTenantIds(payload[config.tenantClaim]);

  return {
    subject: payload.sub,
    issuer,
    email: email.toLowerCase(),
    ...(name ? {name} : {}),
    ...(typeof payload.email_verified === 'boolean' ? {emailVerified: payload.email_verified} : {}),
    roles,
    ...(tenantIds ? {tenantIds} : {}),
    authContext: {
      mode: 'oidc',
      issuer,
      amr: Array.isArray(payload.amr) ? payload.amr.filter(item => typeof item === 'string') : undefined,
      acr: typeof payload.acr === 'string' ? payload.acr : undefined,
      sid: typeof payload.sid === 'string' ? payload.sid : undefined
    }
  };
};

const authenticateStaticToken = ({token, config}: {token: string; config: StaticAuthConfig}): AdminPrincipal => {
  const match = config.tokens.find(item => timingSafeEquals(item.token, token));
  if (!match) {
    throw unauthorized('admin_auth_invalid', 'Bearer token is invalid');
  }

  return {
    subject: match.subject,
    issuer: STATIC_PRINCIPAL_ISSUER,
    email: normalizeStaticEmail(match.subject),
    roles: [...match.roles],
    ...(match.tenant_ids ? {tenantIds: [...match.tenant_ids]} : {}),
    authContext: {
      mode: 'static',
      issuer: STATIC_PRINCIPAL_ISSUER
    }
  };
};

const buildOidcVerifier = ({config}: {config: OidcAuthConfig}) => {
  const jwks = createRemoteJWKSet(new URL(config.jwksUri));

  return async (token: string): Promise<AdminPrincipal> => {
    try {
      const verified = await jwtVerify(token, jwks, {
        audience: config.audience
      });

      const tokenIssuer = readClaimAsString({payload: verified.payload, claimName: 'iss'});
      if (!tokenIssuer || normalizeIssuerForComparison(tokenIssuer) !== normalizeIssuerForComparison(config.issuer)) {
        throw unauthorized('admin_auth_invalid', 'OIDC token verification failed');
      }

      return parseOidcPrincipal({payload: verified.payload, config});
    } catch {
      throw unauthorized('admin_auth_invalid', 'OIDC token verification failed');
    }
  };
};

export class AdminAuthenticator {
  private readonly oidcVerify?: (token: string) => Promise<AdminPrincipal>;

  public constructor(private readonly config: AuthConfig) {
    this.oidcVerify = config.mode === 'oidc' ? buildOidcVerifier({config}) : undefined;
  }

  public async authenticate(authorizationHeader: string | undefined): Promise<AdminPrincipal> {
    const token = parseBearerToken(authorizationHeader);
    if (this.config.mode === 'static') {
      return authenticateStaticToken({token, config: this.config});
    }

    if (!this.oidcVerify) {
      throw unauthorized('admin_auth_invalid', 'OIDC verifier is not initialized');
    }

    return this.oidcVerify(token);
  }
}

export const requireAnyRole = ({principal, allowed}: {principal: AdminPrincipal; allowed: AdminRole[]}) => {
  const allowedSet = new Set(allowed);
  if (principal.roles.some(role => allowedSet.has(role))) {
    return;
  }

  throw forbidden('admin_forbidden', 'The authenticated principal is not allowed to perform this action');
};

export const requireTenantScope = ({principal, tenantId}: {principal: AdminPrincipal; tenantId: string}) => {
  if (principal.roles.includes('owner')) {
    return;
  }

  if (!principal.tenantIds || !principal.tenantIds.includes(tenantId)) {
    throw forbidden('admin_tenant_forbidden', 'The authenticated principal is not allowed to access this tenant');
  }
};
