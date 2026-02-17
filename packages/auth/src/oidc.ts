import {decodeProtectedHeader, jwtVerify, type JWTPayload} from 'jose';

import {
  OpenApiAdminRoleSchema,
  OpenApiAdminSessionPrincipalSchema,
  type OpenApiAdminRole
} from './contracts';

const DEFAULT_ALLOWED_OIDC_ALGORITHMS = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EDDSA'
]);

const DEFAULT_ROLE_CLAIM = 'roles';
const DEFAULT_TENANT_CLAIM = 'tenant_ids';
const DEFAULT_EMAIL_CLAIM = 'email';
const DEFAULT_NAME_CLAIM = 'name';
const DEFAULT_ISSUER_CLAIM = 'iss';
const DEFAULT_SUBJECT_CLAIM = 'sub';
const MAX_OIDC_JWT_LENGTH = 16_384;
const MAX_CLOCK_TOLERANCE_SECONDS = 300;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const toNonEmptyTrimmedString = (value: unknown) => {
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim();
  return normalized.length > 0 ? normalized : null;
};

const isAbsoluteUrlString = (value: string) => {
  try {
    // OIDC issuer identifiers are absolute URLs.
    new URL(value);
    return true;
  } catch {
    return false;
  }
};

const normalizeExpectedAudience = (value: string | readonly string[]) => {
  const items = (Array.isArray(value) ? value : [value])
    .map(item => toNonEmptyTrimmedString(item))
    .filter((item): item is string => item !== null);

  return items.length > 0 ? [...new Set(items)] : null;
};

const normalizeAudienceClaim = (value: unknown) => {
  if (typeof value === 'string') {
    const normalized = toNonEmptyTrimmedString(value);
    return normalized ? [normalized] : null;
  }

  if (!Array.isArray(value)) {
    return null;
  }

  const normalized = value
    .map(item => toNonEmptyTrimmedString(item))
    .filter((item): item is string => item !== null);

  return normalized.length > 0 ? [...new Set(normalized)] : null;
};

const normalizeStringListClaim = (value: unknown): string[] | null => {
  if (value === undefined) {
    return [];
  }

  if (typeof value === 'string') {
    const normalized = toNonEmptyTrimmedString(value);
    return normalized ? [normalized] : null;
  }

  if (!Array.isArray(value)) {
    return null;
  }

  const normalized = value
    .map(item => toNonEmptyTrimmedString(item))
    .filter((item): item is string => item !== null);

  return [...new Set(normalized)];
};

const isForbiddenOidcAlgorithm = (alg: string) => {
  const normalized = alg.toUpperCase();
  return normalized === 'NONE' || normalized.startsWith('HS');
};

const parseErrorCode = (error: unknown) =>
  isRecord(error) && typeof error.code === 'string' ? error.code : null;

const mapJoseVerifyError = (error: unknown) => {
  const code = parseErrorCode(error);

  if (code === 'ERR_JWT_EXPIRED') {
    return 'oidc_token_expired';
  }

  if (
    code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' ||
    code === 'ERR_JWKS_NO_MATCHING_KEY' ||
    code === 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'
  ) {
    return 'oidc_signature_invalid';
  }

  if (code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
    return 'oidc_token_claims_invalid';
  }

  return 'oidc_token_invalid';
};

const parseClaimName = (value: unknown) => toNonEmptyTrimmedString(value);
const readClaim = (payload: Record<string, unknown>, claimName: string) => Reflect.get(payload, claimName);

const normalizeAllowedAlgorithms = (allowedAlgorithms?: readonly string[]) => {
  if (allowedAlgorithms === undefined) {
    return {ok: true as const, value: DEFAULT_ALLOWED_OIDC_ALGORITHMS};
  }

  const normalized = allowedAlgorithms
    .map(value => toNonEmptyTrimmedString(value)?.toUpperCase() ?? null)
    .filter((value): value is string => value !== null);

  if (normalized.length === 0) {
    return {ok: false as const};
  }

  if (normalized.some(algorithm => isForbiddenOidcAlgorithm(algorithm))) {
    return {ok: false as const};
  }

  return {ok: true as const, value: new Set(normalized)};
};

const isValidDate = (value: Date) => value instanceof Date && !Number.isNaN(value.getTime());

export type ValidateIssuerAudienceInput = {
  issuer: unknown;
  audience: unknown;
  expectedIssuer: string;
  expectedAudience: string | readonly string[];
  authorizedParty?: unknown;
  expectedAuthorizedParty?: string;
  requireAzpWhenMultipleAudiences?: boolean;
};

export type ValidateIssuerAudienceResult =
  | {ok: true; issuer: string; audience: string[]; authorizedParty?: string}
  | {ok: false; error: string};

export const validateIssuerAudience = ({
  issuer,
  audience,
  expectedIssuer,
  expectedAudience,
  authorizedParty,
  expectedAuthorizedParty,
  requireAzpWhenMultipleAudiences = true
}: ValidateIssuerAudienceInput): ValidateIssuerAudienceResult => {
  const normalizedExpectedIssuer = toNonEmptyTrimmedString(expectedIssuer);
  const normalizedExpectedAudience = normalizeExpectedAudience(expectedAudience);

  if (!normalizedExpectedIssuer || !normalizedExpectedAudience) {
    return {ok: false, error: 'oidc_verifier_config_invalid'};
  }

  if (!isAbsoluteUrlString(normalizedExpectedIssuer)) {
    return {ok: false, error: 'oidc_verifier_config_invalid'};
  }

  const normalizedIssuer = toNonEmptyTrimmedString(issuer);
  if (!normalizedIssuer) {
    return {ok: false, error: 'oidc_issuer_missing'};
  }

  if (!isAbsoluteUrlString(normalizedIssuer)) {
    return {ok: false, error: 'oidc_issuer_invalid'};
  }

  if (normalizedIssuer !== normalizedExpectedIssuer) {
    return {ok: false, error: 'oidc_issuer_mismatch'};
  }

  const normalizedAudience = normalizeAudienceClaim(audience);
  if (!normalizedAudience) {
    return {ok: false, error: 'oidc_audience_missing'};
  }

  const hasExpectedAudience = normalizedAudience.some(item => normalizedExpectedAudience.includes(item));
  if (!hasExpectedAudience) {
    return {ok: false, error: 'oidc_audience_mismatch'};
  }

  const normalizedExpectedAuthorizedParty = toNonEmptyTrimmedString(expectedAuthorizedParty);
  const normalizedAuthorizedParty = toNonEmptyTrimmedString(authorizedParty);

  if (normalizedExpectedAuthorizedParty) {
    if (!normalizedAuthorizedParty) {
      return {ok: false, error: 'oidc_azp_missing'};
    }

    if (normalizedAuthorizedParty !== normalizedExpectedAuthorizedParty) {
      return {ok: false, error: 'oidc_azp_mismatch'};
    }
  } else if (requireAzpWhenMultipleAudiences && normalizedAudience.length > 1 && !normalizedAuthorizedParty) {
    return {ok: false, error: 'oidc_azp_missing'};
  }

  return {
    ok: true,
    issuer: normalizedIssuer,
    audience: normalizedAudience,
    ...(normalizedAuthorizedParty ? {authorizedParty: normalizedAuthorizedParty} : {})
  };
};

export type AdminClaims = {
  issuer: string;
  subject: string;
  email: string;
  name?: string;
  roles: OpenApiAdminRole[];
  tenantIds: string[];
};

export type ExtractAdminClaimsInput = {
  payload: JWTPayload | Record<string, unknown>;
  roleClaim?: string;
  tenantClaim?: string;
  emailClaim?: string;
  nameClaim?: string;
  issuerClaim?: string;
  subjectClaim?: string;
  requireTenantScope?: boolean;
};

export type ExtractAdminClaimsResult = {ok: true; claims: AdminClaims} | {ok: false; error: string};

export const extractAdminClaims = ({
  payload,
  roleClaim = DEFAULT_ROLE_CLAIM,
  tenantClaim = DEFAULT_TENANT_CLAIM,
  emailClaim = DEFAULT_EMAIL_CLAIM,
  nameClaim = DEFAULT_NAME_CLAIM,
  issuerClaim = DEFAULT_ISSUER_CLAIM,
  subjectClaim = DEFAULT_SUBJECT_CLAIM,
  requireTenantScope = false
}: ExtractAdminClaimsInput): ExtractAdminClaimsResult => {
  if (!isRecord(payload)) {
    return {ok: false, error: 'admin_claims_payload_invalid'};
  }

  const normalizedRoleClaim = parseClaimName(roleClaim);
  const normalizedTenantClaim = parseClaimName(tenantClaim);
  const normalizedEmailClaim = parseClaimName(emailClaim);
  const normalizedNameClaim = parseClaimName(nameClaim);
  const normalizedIssuerClaim = parseClaimName(issuerClaim);
  const normalizedSubjectClaim = parseClaimName(subjectClaim);

  if (
    !normalizedRoleClaim ||
    !normalizedTenantClaim ||
    !normalizedEmailClaim ||
    !normalizedNameClaim ||
    !normalizedIssuerClaim ||
    !normalizedSubjectClaim
  ) {
    return {ok: false, error: 'admin_claims_mapping_invalid'};
  }

  const subject = toNonEmptyTrimmedString(readClaim(payload, normalizedSubjectClaim));
  if (!subject) {
    return {ok: false, error: 'admin_claims_subject_missing'};
  }

  const issuer = toNonEmptyTrimmedString(readClaim(payload, normalizedIssuerClaim));
  if (!issuer) {
    return {ok: false, error: 'admin_claims_issuer_missing'};
  }

  const email = toNonEmptyTrimmedString(readClaim(payload, normalizedEmailClaim));
  if (!email) {
    return {ok: false, error: 'admin_claims_email_missing'};
  }

  const parsedRoles = normalizeStringListClaim(readClaim(payload, normalizedRoleClaim));
  if (parsedRoles === null) {
    return {ok: false, error: 'admin_claims_roles_invalid'};
  }

  const normalizedRoles = parsedRoles
    .map(role => OpenApiAdminRoleSchema.safeParse(role))
    .filter((result): result is {success: true; data: OpenApiAdminRole} => result.success)
    .map(result => result.data);

  if (normalizedRoles.length !== parsedRoles.length || normalizedRoles.length === 0) {
    return {ok: false, error: 'admin_claims_roles_invalid'};
  }

  const parsedTenantIds = normalizeStringListClaim(readClaim(payload, normalizedTenantClaim));
  if (parsedTenantIds === null) {
    return {ok: false, error: 'admin_claims_tenant_scope_invalid'};
  }

  if (requireTenantScope && parsedTenantIds.length === 0) {
    return {ok: false, error: 'admin_claims_tenant_scope_missing'};
  }

  const name = toNonEmptyTrimmedString(readClaim(payload, normalizedNameClaim)) ?? undefined;

  const principalParse = OpenApiAdminSessionPrincipalSchema.safeParse({
    subject,
    issuer,
    email,
    ...(name ? {name} : {}),
    roles: normalizedRoles,
    tenant_ids: parsedTenantIds
  });

  if (!principalParse.success) {
    const topLevelPath = principalParse.error.issues[0]?.path[0];
    if (topLevelPath === 'email') {
      return {ok: false, error: 'admin_claims_email_invalid'};
    }

    if (topLevelPath === 'issuer') {
      return {ok: false, error: 'admin_claims_issuer_invalid'};
    }

    return {ok: false, error: 'admin_claims_invalid'};
  }

  return {
    ok: true,
    claims: {
      subject: principalParse.data.subject,
      issuer: principalParse.data.issuer,
      email: principalParse.data.email,
      ...(principalParse.data.name ? {name: principalParse.data.name} : {}),
      roles: principalParse.data.roles,
      tenantIds: principalParse.data.tenant_ids
    }
  };
};

export type OidcJwtKeyResolver = NonNullable<Parameters<typeof jwtVerify>[1]>;

export type VerifyOidcAccessTokenInput = {
  token: string;
  keyResolver: OidcJwtKeyResolver;
  expectedIssuer: string;
  expectedAudience: string | readonly string[];
  expectedAuthorizedParty?: string;
  requireAzpWhenMultipleAudiences?: boolean;
  now?: Date;
  clockToleranceSeconds?: number;
  allowedAlgorithms?: readonly string[];
};

export type VerifyOidcAccessTokenResult =
  | {
      ok: true;
      payload: JWTPayload & Record<string, unknown>;
      protectedHeader: Record<string, unknown>;
    }
  | {ok: false; error: string};

export const verifyOidcAccessToken = async ({
  token,
  keyResolver,
  expectedIssuer,
  expectedAudience,
  expectedAuthorizedParty,
  requireAzpWhenMultipleAudiences = true,
  now = new Date(),
  clockToleranceSeconds = 60,
  allowedAlgorithms
}: VerifyOidcAccessTokenInput): Promise<VerifyOidcAccessTokenResult> => {
  const normalizedToken = toNonEmptyTrimmedString(token);
  if (!normalizedToken || normalizedToken.length > MAX_OIDC_JWT_LENGTH) {
    return {ok: false, error: 'oidc_token_invalid'};
  }

  if (!keyResolver) {
    return {ok: false, error: 'oidc_verifier_config_invalid'};
  }

  if (!isValidDate(now)) {
    return {ok: false, error: 'oidc_now_invalid'};
  }

  if (
    !Number.isInteger(clockToleranceSeconds) ||
    clockToleranceSeconds < 0 ||
    clockToleranceSeconds > MAX_CLOCK_TOLERANCE_SECONDS
  ) {
    return {ok: false, error: 'oidc_verifier_config_invalid'};
  }

  const parsedAllowedAlgorithms = normalizeAllowedAlgorithms(allowedAlgorithms);
  if (!parsedAllowedAlgorithms.ok) {
    return {ok: false, error: 'oidc_verifier_config_invalid'};
  }

  let protectedHeader: Record<string, unknown>;
  try {
    protectedHeader = decodeProtectedHeader(normalizedToken) as Record<string, unknown>;
  } catch {
    return {ok: false, error: 'oidc_token_invalid'};
  }

  const algorithm = toNonEmptyTrimmedString(protectedHeader.alg);
  if (!algorithm) {
    return {ok: false, error: 'oidc_alg_invalid'};
  }

  const normalizedAlgorithm = algorithm.toUpperCase();
  if (isForbiddenOidcAlgorithm(normalizedAlgorithm)) {
    return {ok: false, error: 'oidc_alg_forbidden'};
  }

  if (!parsedAllowedAlgorithms.value.has(normalizedAlgorithm)) {
    return {ok: false, error: 'oidc_alg_not_allowed'};
  }

  let payload: JWTPayload & Record<string, unknown>;
  try {
    const verified = await jwtVerify(normalizedToken, keyResolver, {
      currentDate: now,
      clockTolerance: clockToleranceSeconds
    });
    payload = verified.payload as JWTPayload & Record<string, unknown>;
  } catch (error) {
    return {ok: false, error: mapJoseVerifyError(error)};
  }

  const issuerAudienceValidation = validateIssuerAudience({
    issuer: payload.iss,
    audience: payload.aud,
    authorizedParty: payload.azp,
    expectedIssuer,
    expectedAudience,
    expectedAuthorizedParty,
    requireAzpWhenMultipleAudiences
  });

  if (!issuerAudienceValidation.ok) {
    return issuerAudienceValidation;
  }

  return {
    ok: true,
    payload,
    protectedHeader
  };
};
