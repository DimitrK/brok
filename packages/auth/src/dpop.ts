import crypto from 'crypto';
import {
  calculateJwkThumbprint as joseCalculateJwkThumbprint,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK
} from 'jose';

import {dpopPayloadSchema, jwkSchema} from './contracts';
import type {JtiStore} from './types';

const ALLOWED_DPOP_ALGS = new Set([
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512',
  'RS256',
  'RS384',
  'RS512',
  'EdDSA'
]);

const ALLOWED_HTU_PROTOCOLS = new Set(['https:', 'http:']);
const HTTP_TOKEN_METHOD_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const JWK_THUMBPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_DPOP_JWT_LENGTH = 16_384;
const MAX_JTI_LENGTH = 512;
const MAX_REPLAY_SCOPE_LENGTH = 256;
const MAX_DPOP_WINDOW_SECONDS = 3_600;

export type DpopPayload = {
  htm: string;
  htu: string;
  iat: number;
  jti: string;
};

export type DpopVerifyError = {ok: false; error: string};
export type DpopVerifySuccess = {ok: true};
export type DpopVerifyResult = DpopVerifySuccess | DpopVerifyError;

export type VerifyDpopProofJwtInput = {
  dpopJwt: string;
  method: string;
  url: string;
  now?: Date;
  maxSkewSeconds?: number;
  replayTtlSeconds?: number;
  jtiStore?: JtiStore;
  tenantId?: string;
  sessionId?: string;
  replayScope?: string;
  expectedJkt?: string;
  accessToken?: string;
};

export type VerifyDpopProofJwtSuccess = {
  ok: true;
  payload: DpopPayload & {ath?: string} & Record<string, unknown>;
  jkt: string;
};

export type VerifyDpopProofJwtResult = VerifyDpopProofJwtSuccess | DpopVerifyError;

export const normalizeHtu = (urlString: string) => {
  if (typeof urlString !== 'string' || urlString.trim().length === 0) {
    throw new TypeError('dpop_htu_invalid');
  }

  const url = new URL(urlString);
  if (!ALLOWED_HTU_PROTOCOLS.has(url.protocol)) {
    throw new TypeError('dpop_htu_invalid');
  }

  if (url.username || url.password) {
    throw new TypeError('dpop_htu_invalid');
  }

  url.search = '';
  url.hash = '';
  url.hostname = url.hostname.toLowerCase();
  const isDefaultPort =
    (url.protocol === 'https:' && url.port === '443') || (url.protocol === 'http:' && url.port === '80');
  if (isDefaultPort) {
    url.port = '';
  }

  return url.toString();
};

const base64UrlEncode = (value: Buffer) =>
  value.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

const sha256Base64Url = (value: string) => base64UrlEncode(crypto.createHash('sha256').update(value, 'utf8').digest());

const hasPrivateJwkParams = (jwk: Record<string, unknown>) =>
  ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some(param => param in jwk);

const isAllowedAlg = (alg: unknown): alg is string => typeof alg === 'string' && ALLOWED_DPOP_ALGS.has(alg);
const isValidDate = (value: Date) => value instanceof Date && !Number.isNaN(value.getTime());
const isValidWindowSeconds = (value: number) =>
  Number.isInteger(value) && value > 0 && value <= MAX_DPOP_WINDOW_SECONDS;

const normalizeMethod = (value: string) => {
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim().toUpperCase();
  if (normalized.length === 0 || normalized.length > 32 || !HTTP_TOKEN_METHOD_PATTERN.test(normalized)) {
    return null;
  }

  return normalized;
};

const parseOptionalString = (value: unknown): {ok: true; value?: string} | {ok: false} => {
  if (value === undefined) {
    return {ok: true, value: undefined};
  }

  if (typeof value !== 'string') {
    return {ok: false};
  }

  const normalized = value.trim();
  if (normalized.length === 0) {
    return {ok: false};
  }

  return {ok: true, value: normalized};
};

export const calculateJwkThumbprint = async (jwk: Record<string, unknown>) => {
  try {
    return await joseCalculateJwkThumbprint(jwk as JWK, 'sha256');
  } catch {
    return null;
  }
};

const isWithinSkew = ({iat, now, maxSkewSeconds}: {iat: number; now: Date; maxSkewSeconds: number}) => {
  const issuedAt = new Date(iat * 1000);
  const diffSeconds = Math.abs(now.getTime() - issuedAt.getTime()) / 1000;
  return diffSeconds <= maxSkewSeconds;
};

const buildReplayScope = ({
  replayScope,
  tenantId,
  sessionId,
  expectedJkt
}: {
  replayScope?: string;
  tenantId?: string;
  sessionId?: string;
  expectedJkt?: string;
}) => {
  if (replayScope) {
    return replayScope.trim();
  }

  const parts = [tenantId, sessionId, expectedJkt]
    .filter((part): part is string => typeof part === 'string')
    .map(part => part.trim())
    .filter(part => part.length > 0);

  if (parts.length > 0) {
    return parts.join(':');
  }

  return undefined;
};

const enforceReplayProtection = async ({
  jti,
  now,
  replayTtlSeconds,
  jtiStore,
  replayScope
}: {
  jti: string;
  now: Date;
  replayTtlSeconds: number;
  jtiStore?: JtiStore;
  replayScope?: string;
}): Promise<DpopVerifyResult> => {
  if (!jtiStore) {
    return {ok: true};
  }

  const replayKey = replayScope ? `${replayScope}:${jti}` : jti;
  const expiresAt = new Date(now.getTime() + replayTtlSeconds * 1000);
  const accepted = await jtiStore.checkAndStore(replayKey, expiresAt);
  if (!accepted) {
    return {ok: false, error: 'dpop_replay'};
  }

  return {ok: true};
};

export const verifyDpopClaimsOnly = async ({
  payload,
  method,
  url,
  now = new Date(),
  maxSkewSeconds = 300,
  replayTtlSeconds = maxSkewSeconds,
  jtiStore,
  replayScope,
  enforceReplay = true
}: {
  payload: DpopPayload;
  method: string;
  url: string;
  now?: Date;
  maxSkewSeconds?: number;
  replayTtlSeconds?: number;
  jtiStore?: JtiStore;
  replayScope?: string;
  enforceReplay?: boolean;
}): Promise<DpopVerifyResult> => {
  if (!isValidDate(now)) {
    return {ok: false, error: 'dpop_now_invalid'};
  }

  if (!isValidWindowSeconds(maxSkewSeconds) || !isValidWindowSeconds(replayTtlSeconds)) {
    return {ok: false, error: 'dpop_config_invalid'};
  }

  const normalizedMethod = normalizeMethod(method);
  if (!normalizedMethod) {
    return {ok: false, error: 'dpop_method_invalid'};
  }

  const parsedReplayScope = parseOptionalString(replayScope);
  if (!parsedReplayScope.ok) {
    return {ok: false, error: 'dpop_replay_scope_invalid'};
  }
  const normalizedReplayScope = parsedReplayScope.value;

  if (normalizedReplayScope && normalizedReplayScope.length > MAX_REPLAY_SCOPE_LENGTH) {
    return {ok: false, error: 'dpop_replay_scope_invalid'};
  }

  const parsedPayload = dpopPayloadSchema.safeParse(payload);
  if (!parsedPayload.success) {
    return {ok: false, error: 'dpop_missing_claims'};
  }

  const claims = parsedPayload.data;
  if (claims.jti.length > MAX_JTI_LENGTH) {
    return {ok: false, error: 'dpop_jti_invalid'};
  }

  const normalizedClaimMethod = normalizeMethod(claims.htm);
  if (!normalizedClaimMethod) {
    return {ok: false, error: 'dpop_missing_claims'};
  }

  const methodMatch = normalizedClaimMethod === normalizedMethod;
  if (!methodMatch) {
    return {ok: false, error: 'dpop_method_mismatch'};
  }

  let normalizedHtu: string;
  let normalizedUrl: string;
  try {
    normalizedHtu = normalizeHtu(claims.htu);
    normalizedUrl = normalizeHtu(url);
  } catch {
    return {ok: false, error: 'dpop_htu_invalid'};
  }

  if (normalizedHtu !== normalizedUrl) {
    return {ok: false, error: 'dpop_htu_mismatch'};
  }

  if (!isWithinSkew({iat: claims.iat, now, maxSkewSeconds})) {
    return {ok: false, error: 'dpop_iat_skew'};
  }

  if (enforceReplay) {
    const replayResult = await enforceReplayProtection({
      jti: claims.jti,
      now,
      replayTtlSeconds,
      jtiStore,
      replayScope: normalizedReplayScope
    });
    if (!replayResult.ok) {
      return replayResult;
    }
  }

  return {ok: true};
};

export const verifyDpopProofJwt = async ({
  dpopJwt,
  method,
  url,
  now = new Date(),
  maxSkewSeconds = 300,
  replayTtlSeconds = maxSkewSeconds,
  jtiStore,
  tenantId,
  sessionId,
  replayScope,
  expectedJkt,
  accessToken
}: VerifyDpopProofJwtInput): Promise<VerifyDpopProofJwtResult> => {
  if (typeof dpopJwt !== 'string' || dpopJwt.length === 0 || dpopJwt.length > MAX_DPOP_JWT_LENGTH) {
    return {ok: false, error: 'dpop_malformed_jwt'};
  }

  if (!isValidDate(now)) {
    return {ok: false, error: 'dpop_now_invalid'};
  }

  if (!isValidWindowSeconds(maxSkewSeconds) || !isValidWindowSeconds(replayTtlSeconds)) {
    return {ok: false, error: 'dpop_config_invalid'};
  }

  const normalizedMethod = normalizeMethod(method);
  if (!normalizedMethod) {
    return {ok: false, error: 'dpop_method_invalid'};
  }

  const parsedExpectedJkt = parseOptionalString(expectedJkt);
  if (!parsedExpectedJkt.ok) {
    return {ok: false, error: 'dpop_jkt_invalid'};
  }
  const normalizedExpectedJkt = parsedExpectedJkt.value;
  if (normalizedExpectedJkt && !JWK_THUMBPRINT_PATTERN.test(normalizedExpectedJkt)) {
    return {ok: false, error: 'dpop_jkt_invalid'};
  }

  const parsedAccessToken = parseOptionalString(accessToken);
  if (!parsedAccessToken.ok) {
    return {ok: false, error: 'dpop_access_token_invalid'};
  }
  const normalizedAccessToken = parsedAccessToken.value;

  const parsedReplayScope = parseOptionalString(replayScope);
  if (!parsedReplayScope.ok) {
    return {ok: false, error: 'dpop_replay_scope_invalid'};
  }
  const normalizedReplayScope = parsedReplayScope.value;

  if (normalizedReplayScope && normalizedReplayScope.length > MAX_REPLAY_SCOPE_LENGTH) {
    return {ok: false, error: 'dpop_replay_scope_invalid'};
  }

  const parsedTenantId = parseOptionalString(tenantId);
  if (!parsedTenantId.ok) {
    return {ok: false, error: 'dpop_scope_invalid'};
  }
  const normalizedTenantId = parsedTenantId.value;

  const parsedSessionId = parseOptionalString(sessionId);
  if (!parsedSessionId.ok) {
    return {ok: false, error: 'dpop_scope_invalid'};
  }
  const normalizedSessionId = parsedSessionId.value;

  const effectiveReplayScope = buildReplayScope({
    replayScope: normalizedReplayScope,
    tenantId: normalizedTenantId,
    sessionId: normalizedSessionId,
    expectedJkt: normalizedExpectedJkt
  });

  if (effectiveReplayScope && effectiveReplayScope.length > MAX_REPLAY_SCOPE_LENGTH) {
    return {ok: false, error: 'dpop_replay_scope_invalid'};
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(dpopJwt);
  } catch {
    return {ok: false, error: 'dpop_malformed_jwt'};
  }

  const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
  if (typ !== 'dpop+jwt') {
    return {ok: false, error: 'dpop_bad_typ'};
  }

  if (!isAllowedAlg(header.alg)) {
    return {ok: false, error: 'dpop_alg_forbidden'};
  }

  const parsedJwk = jwkSchema.safeParse(header.jwk);
  if (!parsedJwk.success) {
    return {ok: false, error: 'dpop_jwk_missing'};
  }

  const jwk = parsedJwk.data;

  if (hasPrivateJwkParams(jwk)) {
    return {ok: false, error: 'dpop_jwk_private'};
  }

  const jkt = await calculateJwkThumbprint(jwk);
  if (!jkt) {
    return {ok: false, error: 'dpop_jwk_thumbprint_failed'};
  }

  if (normalizedExpectedJkt && jkt !== normalizedExpectedJkt) {
    return {ok: false, error: 'dpop_jkt_mismatch'};
  }

  let payload: unknown;
  try {
    const key = await importJWK(jwk as JWK, header.alg);
    const verified = await jwtVerify(dpopJwt, key, {
      algorithms: [header.alg]
    });
    payload = verified.payload;
  } catch {
    return {ok: false, error: 'dpop_signature_invalid'};
  }

  const parsedPayload = dpopPayloadSchema.safeParse(payload);
  if (!parsedPayload.success) {
    return {ok: false, error: 'dpop_missing_claims'};
  }

  const verifiedPayload = parsedPayload.data;
  const claims: DpopPayload = {
    htm: verifiedPayload.htm,
    htu: verifiedPayload.htu,
    iat: verifiedPayload.iat,
    jti: verifiedPayload.jti
  };

  const claimsResult = await verifyDpopClaimsOnly({
    payload: claims,
    method: normalizedMethod,
    url,
    now,
    maxSkewSeconds,
    replayTtlSeconds,
    replayScope: effectiveReplayScope,
    enforceReplay: false
  });
  if (!claimsResult.ok) {
    return claimsResult;
  }

  if (normalizedAccessToken) {
    const ath = verifiedPayload.ath ?? '';
    if (!ath) {
      return {ok: false, error: 'dpop_ath_missing'};
    }

    if (ath !== sha256Base64Url(normalizedAccessToken)) {
      return {ok: false, error: 'dpop_ath_mismatch'};
    }
  }

  const replayResult = await enforceReplayProtection({
    jti: claims.jti,
    now,
    replayTtlSeconds,
    jtiStore,
    replayScope: effectiveReplayScope ?? normalizedExpectedJkt ?? jkt
  });
  if (!replayResult.ok) {
    return replayResult;
  }

  return {ok: true, payload: verifiedPayload as DpopPayload & {ath?: string} & Record<string, unknown>, jkt};
};

export type VerifyBoundDpopProofJwtInput = Omit<VerifyDpopProofJwtInput, 'expectedJkt' | 'accessToken' | 'jtiStore'> & {
  expectedJkt: string;
  accessToken: string;
  jtiStore: JtiStore;
};

export const verifyBoundDpopProofJwt = async (
  input: VerifyBoundDpopProofJwtInput
): Promise<VerifyDpopProofJwtResult> => {
  if (!input.jtiStore) {
    return {ok: false, error: 'dpop_replay_store_required'};
  }

  return verifyDpopProofJwt(input);
};
