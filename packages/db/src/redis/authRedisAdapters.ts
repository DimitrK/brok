import {z} from 'zod';

import {OpenApiWorkloadSchema, SessionRecordSchema, type Workload} from '../contracts.js';
import {DbRepositoryError, mapDatabaseError} from '../errors.js';
import type {DatabaseClient} from '../types.js';
import {assertNonEmptyString, sha256Hex} from '../utils.js';
import type {RedisClient} from './types.js';

const TokenHashSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const SessionIdSchema = z.string().uuid();

const EnrollmentTokenRecordSchema = z
  .object({
    tokenHash: TokenHashSchema,
    workloadId: z.string().min(1),
    expiresAt: z.iso.datetime({offset: true})
  })
  .strict();
export type EnrollmentTokenRecord = z.infer<typeof EnrollmentTokenRecordSchema>;

const ReplayReservationSchema = z
  .object({
    replayScope: z.string().min(1).max(256),
    jti: z.string().min(1).max(512),
    expiresAt: z.date()
  })
  .strict();

type AuthRedisAdapterOptions = {
  keyPrefix?: string;
  now?: () => Date;
  enrollmentConsumeLockSeconds?: number;
};

export type AuthSessionStoreAdapter = {
  upsertSession: (input: {
    session: z.infer<typeof SessionRecordSchema>;
    redisClient: RedisClient;
    transactionClient?: unknown;
  }) => Promise<void> | void;
  getSessionByTokenHash: (input: {
    tokenHash: string;
    redisClient: RedisClient;
    transactionClient?: unknown;
  }) => Promise<z.infer<typeof SessionRecordSchema> | null> | z.infer<typeof SessionRecordSchema> | null;
  revokeSessionById: (input: {
    sessionId: string;
    redisClient: RedisClient;
    transactionClient?: unknown;
  }) => Promise<void> | void;
};

export type AuthEnrollmentTokenStoreAdapter = {
  issueEnrollmentToken: (input: {
    record: EnrollmentTokenRecord;
    redisClient: RedisClient;
    transactionClient?: unknown;
  }) => Promise<void> | void;
  consumeEnrollmentTokenByHash: (input: {
    tokenHash: string;
    redisClient: RedisClient;
    transactionClient?: unknown;
  }) => Promise<EnrollmentTokenRecord | null> | EnrollmentTokenRecord | null;
};

export type AuthReplayStoreAdapter = {
  reserveDpopJti: (input: {
    replayScope: string;
    jti: string;
    expiresAt: Date;
    redisClient: RedisClient;
    transactionClient?: unknown;
  }) => Promise<boolean> | boolean;
};

export type AuthWorkloadStoreAdapter = {
  getWorkloadBySanUri: (input: {
    sanUri: string;
    postgresClient: DatabaseClient;
    transactionClient?: DatabaseClient;
  }) => Promise<Workload | null> | Workload | null;
};

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return 'broker:auth:';
  }

  return trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
};

const parseExpiresAt = (value: string, fieldName: string): Date => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new DbRepositoryError('validation_error', `${fieldName} must be a valid ISO timestamp`);
  }

  return parsed;
};

const computeTtlSeconds = (expiresAt: Date, now: Date, fieldName: string): number => {
  const ttlMs = expiresAt.getTime() - now.getTime();
  if (ttlMs <= 0) {
    throw new DbRepositoryError('validation_error', `${fieldName} must be in the future`);
  }

  return Math.max(1, Math.ceil(ttlMs / 1000));
};

const sessionTokenKey = (prefix: string, tokenHash: string): string => `${prefix}sess:token:${tokenHash}`;
const sessionIdKey = (prefix: string, sessionId: string): string => `${prefix}sess:id:${sessionId}`;
const enrollmentTokenKey = (prefix: string, tokenHash: string): string => `${prefix}enroll:${tokenHash}`;
const enrollmentConsumeLockKey = (prefix: string, tokenHash: string): string => `${prefix}enroll:lock:${tokenHash}`;
const replayKey = (prefix: string, replayScope: string, jti: string): string =>
  `${prefix}dpop:${sha256Hex(`${replayScope}|${jti}`)}`;

const parseSessionRecord = (value: string): z.infer<typeof SessionRecordSchema> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new DbRepositoryError('validation_error', 'Invalid session cache entry payload');
  }

  return SessionRecordSchema.parse(parsed);
};

export const createAuthRedisStores = (
  options: AuthRedisAdapterOptions = {}
): {
  sessionStore: AuthSessionStoreAdapter;
  enrollmentTokenStore: AuthEnrollmentTokenStoreAdapter;
  replayStore: AuthReplayStoreAdapter;
} => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);
  const nowProvider = options.now ?? (() => new Date());
  const enrollmentLockSeconds = options.enrollmentConsumeLockSeconds ?? 5;

  return {
    sessionStore: {
      upsertSession: async ({session, redisClient}) => {
        const parsedSession = SessionRecordSchema.parse(session);
        const expiresAt = parseExpiresAt(parsedSession.expiresAt, 'expiresAt');
        const ttlSeconds = computeTtlSeconds(expiresAt, nowProvider(), 'expiresAt');
        const tokenKey = sessionTokenKey(prefix, parsedSession.tokenHash);
        const idKey = sessionIdKey(prefix, parsedSession.sessionId);
        const payload = JSON.stringify(parsedSession);

        const setTokenResult = await redisClient.set(tokenKey, payload, {EX: ttlSeconds});
        if (!setTokenResult) {
          throw new DbRepositoryError('unexpected_error', 'Failed to persist session token record');
        }

        const setIdResult = await redisClient.set(idKey, parsedSession.tokenHash, {EX: ttlSeconds});
        if (!setIdResult) {
          throw new DbRepositoryError('unexpected_error', 'Failed to persist session index record');
        }
      },
      getSessionByTokenHash: async ({tokenHash, redisClient}) => {
        const parsedTokenHash = TokenHashSchema.safeParse(tokenHash);
        if (!parsedTokenHash.success) {
          throw new DbRepositoryError('validation_error', 'tokenHash must be a 64-char lowercase hex string');
        }

        const tokenKey = sessionTokenKey(prefix, parsedTokenHash.data);
        const payload = await redisClient.get(tokenKey);
        if (!payload) {
          return null;
        }

        const record = parseSessionRecord(payload);
        const expiresAt = parseExpiresAt(record.expiresAt, 'expiresAt');
        if (expiresAt.getTime() <= nowProvider().getTime()) {
          await redisClient.del(tokenKey);
          await redisClient.del(sessionIdKey(prefix, record.sessionId));
          return null;
        }

        return record;
      },
      revokeSessionById: async ({sessionId, redisClient}) => {
        const parsedSessionId = SessionIdSchema.safeParse(sessionId);
        if (!parsedSessionId.success) {
          throw new DbRepositoryError('validation_error', 'sessionId must be a valid UUID');
        }

        const idKey = sessionIdKey(prefix, parsedSessionId.data);
        const tokenHash = await redisClient.get(idKey);
        if (tokenHash) {
          await redisClient.del(idKey, sessionTokenKey(prefix, tokenHash));
          return;
        }

        await redisClient.del(idKey);
      }
    },
    enrollmentTokenStore: {
      issueEnrollmentToken: async ({record, redisClient}) => {
        const parsedRecord = EnrollmentTokenRecordSchema.parse(record);
        const expiresAt = parseExpiresAt(parsedRecord.expiresAt, 'expiresAt');
        const ttlSeconds = computeTtlSeconds(expiresAt, nowProvider(), 'expiresAt');
        const key = enrollmentTokenKey(prefix, parsedRecord.tokenHash);

        const setResult = await redisClient.set(key, JSON.stringify(parsedRecord), {
          EX: ttlSeconds,
          NX: true
        });
        if (!setResult) {
          throw new DbRepositoryError('conflict', 'Enrollment token already exists');
        }
      },
      consumeEnrollmentTokenByHash: async ({tokenHash, redisClient}) => {
        const parsedTokenHash = TokenHashSchema.safeParse(tokenHash);
        if (!parsedTokenHash.success) {
          throw new DbRepositoryError('validation_error', 'tokenHash must be a 64-char lowercase hex string');
        }

        const key = enrollmentTokenKey(prefix, parsedTokenHash.data);
        const lockKey = enrollmentConsumeLockKey(prefix, parsedTokenHash.data);
        const lockResult = await redisClient.set(lockKey, '1', {
          NX: true,
          EX: enrollmentLockSeconds
        });
        if (!lockResult) {
          return null;
        }

        try {
          const payload = await redisClient.get(key);
          if (!payload) {
            return null;
          }

          let parsedRecord: EnrollmentTokenRecord;
          try {
            parsedRecord = EnrollmentTokenRecordSchema.parse(JSON.parse(payload));
          } catch {
            throw new DbRepositoryError('validation_error', 'Invalid enrollment token cache entry payload');
          }

          const expiresAt = parseExpiresAt(parsedRecord.expiresAt, 'expiresAt');
          if (expiresAt.getTime() <= nowProvider().getTime()) {
            await redisClient.del(key);
            return null;
          }

          await redisClient.del(key);
          return parsedRecord;
        } finally {
          await redisClient.del(lockKey);
        }
      }
    },
    replayStore: {
      reserveDpopJti: async ({replayScope, jti, expiresAt, redisClient}) => {
        const parsedInput = ReplayReservationSchema.safeParse({replayScope, jti, expiresAt});
        if (!parsedInput.success) {
          throw new DbRepositoryError(
            'validation_error',
            parsedInput.error.issues[0]?.message ?? 'Invalid replay input'
          );
        }

        const ttlSeconds = computeTtlSeconds(parsedInput.data.expiresAt, nowProvider(), 'expiresAt');
        const key = replayKey(prefix, parsedInput.data.replayScope, parsedInput.data.jti);
        const setResult = await redisClient.set(key, '1', {
          NX: true,
          EX: ttlSeconds
        });

        return setResult === 'OK';
      }
    }
  };
};

export const createAuthWorkloadStoreAdapter = (input: {dbClient: DatabaseClient}): AuthWorkloadStoreAdapter => ({
  getWorkloadBySanUri: async ({sanUri, postgresClient, transactionClient}) => {
    const trimmedSanUri = assertNonEmptyString(sanUri, 'sanUri');
    const dbClient = transactionClient ?? postgresClient ?? input.dbClient;

    try {
      const record = await dbClient.workload.findUnique({
        where: {
          mtlsSanUri: trimmedSanUri
        }
      });

      if (!record) {
        return null;
      }

      return OpenApiWorkloadSchema.parse({
        workload_id: record.workloadId,
        tenant_id: record.tenantId,
        name: record.name,
        mtls_san_uri: record.mtlsSanUri,
        enabled: record.enabled,
        ip_allowlist: record.ipAllowlist,
        created_at: record.createdAt.toISOString()
      });
    } catch (error) {
      return mapDatabaseError(error);
    }
  }
});
