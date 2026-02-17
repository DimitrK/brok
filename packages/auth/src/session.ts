import crypto from 'crypto';

import {OpenApiSessionRequestSchema} from './contracts';
import type {SessionIssueResult, SessionRecord} from './types';

const MIN_SESSION_TOKEN_BYTES = 32;
const MAX_SESSION_TOKEN_BYTES = 64;
const DPOP_JWK_THUMBPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const base64Url = (value: Buffer) =>
  value
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const addSeconds = (time: Date, seconds: number) => new Date(time.getTime() + seconds * 1000);

export const hashToken = (token: string) =>
  crypto.createHash('sha256').update(token).digest('hex');

export class SessionInputValidationError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.name = 'SessionInputValidationError';
    this.code = code;
  }
}

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;
const isValidDate = (value: Date) => value instanceof Date && !Number.isNaN(value.getTime());

const assertValidTokenBytes = (tokenBytes: number) => {
  if (!Number.isInteger(tokenBytes) || tokenBytes < MIN_SESSION_TOKEN_BYTES || tokenBytes > MAX_SESSION_TOKEN_BYTES) {
    throw new SessionInputValidationError('session_token_bytes_invalid');
  }
};

export const createOpaqueToken = ({bytes = MIN_SESSION_TOKEN_BYTES}: {bytes?: number}) => {
  assertValidTokenBytes(bytes);
  return base64Url(crypto.randomBytes(bytes));
};

const buildSessionRecord = ({
  workloadId,
  tenantId,
  certFingerprint256,
  tokenHash,
  expiresAt,
  dpopKeyThumbprint
}: {
  workloadId: string;
  tenantId: string;
  certFingerprint256: string;
  tokenHash: string;
  expiresAt: string;
  dpopKeyThumbprint?: string;
}): SessionRecord => ({
  sessionId: crypto.randomUUID(),
  workloadId,
  tenantId,
  certFingerprint256,
  tokenHash,
  expiresAt,
  dpopKeyThumbprint
});

export type IssueSessionInput = {
  workloadId: string;
  tenantId: string;
  certFingerprint256: string;
  ttlSeconds: number;
  now?: Date;
  tokenBytes?: number;
  dpopKeyThumbprint?: string;
};

const assertIssueSessionInput = ({
  workloadId,
  tenantId,
  certFingerprint256,
  ttlSeconds,
  now,
  tokenBytes,
  dpopKeyThumbprint
}: {
  workloadId: string;
  tenantId: string;
  certFingerprint256: string;
  ttlSeconds: number;
  now: Date;
  tokenBytes: number;
  dpopKeyThumbprint?: string;
}) => {
  if (!isNonEmptyString(workloadId)) {
    throw new SessionInputValidationError('session_workload_id_invalid');
  }

  if (!isNonEmptyString(tenantId)) {
    throw new SessionInputValidationError('session_tenant_id_invalid');
  }

  if (!isNonEmptyString(certFingerprint256)) {
    throw new SessionInputValidationError('session_cert_fingerprint_invalid');
  }

  if (!isValidDate(now)) {
    throw new SessionInputValidationError('session_now_invalid');
  }

  if (!Number.isInteger(ttlSeconds)) {
    throw new SessionInputValidationError('session_ttl_invalid');
  }

  const parsedTtl = OpenApiSessionRequestSchema.safeParse({requested_ttl_seconds: ttlSeconds});
  if (!parsedTtl.success || parsedTtl.data.requested_ttl_seconds === undefined) {
    throw new SessionInputValidationError('session_ttl_invalid');
  }

  assertValidTokenBytes(tokenBytes);

  if (dpopKeyThumbprint !== undefined) {
    const normalizedDpopKeyThumbprint = dpopKeyThumbprint.trim();
    if (
      normalizedDpopKeyThumbprint.length === 0 ||
      !DPOP_JWK_THUMBPRINT_PATTERN.test(normalizedDpopKeyThumbprint)
    ) {
      throw new SessionInputValidationError('session_dpop_jkt_invalid');
    }
  }
};

export const issueSession = ({
  workloadId,
  tenantId,
  certFingerprint256,
  ttlSeconds,
  now = new Date(),
  tokenBytes = MIN_SESSION_TOKEN_BYTES,
  dpopKeyThumbprint
}: IssueSessionInput): SessionIssueResult => {
  assertIssueSessionInput({
    workloadId,
    tenantId,
    certFingerprint256,
    ttlSeconds,
    now,
    tokenBytes,
    dpopKeyThumbprint
  });

  const normalizedWorkloadId = workloadId.trim();
  const normalizedTenantId = tenantId.trim();
  const normalizedCertFingerprint256 = certFingerprint256.trim();
  const normalizedDpopKeyThumbprint = dpopKeyThumbprint?.trim();

  const token = createOpaqueToken({bytes: tokenBytes});
  const tokenHash = hashToken(token);
  const expiresAt = addSeconds(now, ttlSeconds).toISOString();
  const session = buildSessionRecord({
    workloadId: normalizedWorkloadId,
    tenantId: normalizedTenantId,
    certFingerprint256: normalizedCertFingerprint256,
    tokenHash,
    expiresAt,
    dpopKeyThumbprint: normalizedDpopKeyThumbprint
  });

  return {token, session};
};

export const verifySessionBinding = ({
  session,
  certFingerprint256,
  dpopKeyThumbprint,
  now = new Date()
}: {
  session: SessionRecord;
  certFingerprint256: string;
  dpopKeyThumbprint?: string;
  now?: Date;
}) => {
  const expiresAt = new Date(session.expiresAt);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= now) {
    return {ok: false, error: 'session_expired'};
  }

  if (session.certFingerprint256 !== certFingerprint256) {
    return {ok: false, error: 'session_cert_mismatch'};
  }

  if (session.dpopKeyThumbprint) {
    if (!dpopKeyThumbprint) {
      return {ok: false, error: 'session_dpop_required'};
    }

    if (session.dpopKeyThumbprint !== dpopKeyThumbprint) {
      return {ok: false, error: 'session_dpop_mismatch'};
    }
  }

  return {ok: true};
};
