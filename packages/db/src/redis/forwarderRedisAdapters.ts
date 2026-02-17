import {randomUUID} from 'node:crypto';

import {z} from 'zod';

import {DbRepositoryError} from '../errors.js';
import type {RedisEvalClient} from './types.js';

const NonEmptyStringSchema = z.string().trim().min(1);
const IdempotencyKeySchema = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9._:-]{1,128}$/u);
const FingerprintSchema = z.string().trim().min(32);

const ForwarderScopeSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    action_group: NonEmptyStringSchema
  })
  .strict();

const ForwarderIdempotencyScopeSchema = ForwarderScopeSchema.extend({
  idempotency_key: IdempotencyKeySchema
}).strict();

const ForwarderExecutionLockAcquireInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    ttl_ms: z.number().int().min(1_000).max(60_000)
  })
  .strict();

const ForwarderExecutionLockReleaseInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    lock_token: NonEmptyStringSchema
  })
  .strict();

const ForwarderIdempotencyRecordInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    request_fingerprint_sha256: FingerprintSchema,
    correlation_id: NonEmptyStringSchema,
    expires_at: z.iso.datetime({offset: true})
  })
  .strict();

const ForwarderIdempotencyLookupInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema
  })
  .strict();

const ForwarderIdempotencyCompleteInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    correlation_id: NonEmptyStringSchema,
    upstream_status_code: z.number().int().min(100).max(599),
    response_bytes: z.number().int().min(0)
  })
  .strict();

const ForwarderIdempotencyFailInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    correlation_id: NonEmptyStringSchema,
    error_code: NonEmptyStringSchema
  })
  .strict();

const ForwarderIdempotencyRecordSchema = z
  .object({
    state: z.enum(['in_progress', 'completed', 'failed']),
    request_fingerprint_sha256: FingerprintSchema,
    correlation_id: NonEmptyStringSchema,
    created_at: z.iso.datetime({offset: true}),
    expires_at: z.iso.datetime({offset: true}),
    expires_at_epoch_ms: z.number().int().min(1).optional(),
    upstream_status_code: z.number().int().min(100).max(599).optional(),
    response_bytes: z.number().int().min(0).optional(),
    error_code: NonEmptyStringSchema.optional()
  })
  .strict();

type ForwarderRedisAdapterOptions = {
  keyPrefix?: string;
  now?: () => Date;
};

export type ForwarderExecutionLockAcquireOutput = {
  acquired: boolean;
  lock_token: string;
};

export type ForwarderExecutionLockReleaseOutput = {
  released: boolean;
};

export type ForwarderIdempotencyRecordCreateOutput = {
  created: boolean;
  conflict: null | 'key_exists' | 'fingerprint_mismatch';
};

export type ForwarderIdempotencyRecordUpdateOutput = {
  updated: boolean;
};

export type ForwarderRedisAdapter = {
  acquireForwarderExecutionLock: (input: {
    scope: z.infer<typeof ForwarderIdempotencyScopeSchema>;
    ttl_ms: number;
    context: {clients: {redis?: RedisEvalClient}};
  }) => Promise<ForwarderExecutionLockAcquireOutput>;
  releaseForwarderExecutionLock: (input: {
    scope: z.infer<typeof ForwarderIdempotencyScopeSchema>;
    lock_token: string;
    context: {clients: {redis?: RedisEvalClient}};
  }) => Promise<ForwarderExecutionLockReleaseOutput>;
  createForwarderIdempotencyRecord: (input: {
    scope: z.infer<typeof ForwarderIdempotencyScopeSchema>;
    request_fingerprint_sha256: string;
    correlation_id: string;
    expires_at: string;
    context: {clients: {redis?: RedisEvalClient}};
  }) => Promise<ForwarderIdempotencyRecordCreateOutput>;
  getForwarderIdempotencyRecord: (input: {
    scope: z.infer<typeof ForwarderIdempotencyScopeSchema>;
    context: {clients: {redis?: RedisEvalClient}};
  }) => Promise<Record<string, unknown> | null>;
  completeForwarderIdempotencyRecord: (input: {
    scope: z.infer<typeof ForwarderIdempotencyScopeSchema>;
    correlation_id: string;
    upstream_status_code: number;
    response_bytes: number;
    context: {clients: {redis?: RedisEvalClient}};
  }) => Promise<ForwarderIdempotencyRecordUpdateOutput>;
  failForwarderIdempotencyRecord: (input: {
    scope: z.infer<typeof ForwarderIdempotencyScopeSchema>;
    correlation_id: string;
    error_code: string;
    context: {clients: {redis?: RedisEvalClient}};
  }) => Promise<ForwarderIdempotencyRecordUpdateOutput>;
};

const MIN_IDEMPOTENCY_TTL_SECONDS = 60;
const MAX_IDEMPOTENCY_TTL_SECONDS = 60 * 60 * 24;

const LOCK_RELEASE_SCRIPT = [
  '-- forwarder_lock_release',
  'if redis.call("GET", KEYS[1]) == ARGV[1] then',
  '  return redis.call("DEL", KEYS[1])',
  'end',
  'return 0'
].join('\n');

const IDEMPOTENCY_UPDATE_SCRIPT = [
  '-- forwarder_idem_update',
  'local payload = redis.call("GET", KEYS[1])',
  'if not payload then return 0 end',
  'local data = cjson.decode(payload)',
  'if data["state"] ~= "in_progress" then return 0 end',
  'if data["correlation_id"] ~= ARGV[2] then return 0 end',
  'data["state"] = ARGV[1]',
  'if ARGV[1] == "completed" then',
  '  data["upstream_status_code"] = tonumber(ARGV[3])',
  '  data["response_bytes"] = tonumber(ARGV[4])',
  '  data["error_code"] = nil',
  'else',
  '  data["error_code"] = ARGV[5]',
  '  data["upstream_status_code"] = nil',
  '  data["response_bytes"] = nil',
  'end',
  'local ttl = redis.call("PTTL", KEYS[1])',
  'if ttl <= 0 then',
  '  local expiresAt = data["expires_at_epoch_ms"]',
  '  if not expiresAt then return 0 end',
  '  local nowParts = redis.call("TIME")',
  '  local nowMs = (tonumber(nowParts[1]) * 1000) + math.floor(tonumber(nowParts[2]) / 1000)',
  '  ttl = tonumber(expiresAt) - nowMs',
  '  if ttl <= 0 then',
  '    redis.call("DEL", KEYS[1])',
  '    return 0',
  '  end',
  'end',
  'redis.call("SET", KEYS[1], cjson.encode(data), "PX", ttl)',
  'return 1'
].join('\n');

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return 'broker:fw:';
  }

  return trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
};

const resolveRedisClient = (context: {clients: {redis?: RedisEvalClient}}): RedisEvalClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for forwarder idempotency');
  }

  if (typeof client.eval !== 'function') {
    throw new DbRepositoryError('dependency_missing', 'Redis client must support eval for forwarder idempotency');
  }

  return client;
};

const parseExpiresAt = (value: string, fieldName: string): Date => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new DbRepositoryError('validation_error', `${fieldName} must be a valid ISO timestamp`);
  }

  return parsed;
};

const computeIdempotencyTtlSeconds = (expiresAt: Date, now: Date): number => {
  const ttlMs = expiresAt.getTime() - now.getTime();
  if (ttlMs <= 0) {
    throw new DbRepositoryError('validation_error', 'expires_at must be in the future');
  }

  const ttlSeconds = Math.ceil(ttlMs / 1000);
  if (ttlSeconds < MIN_IDEMPOTENCY_TTL_SECONDS || ttlSeconds > MAX_IDEMPOTENCY_TTL_SECONDS) {
    throw new DbRepositoryError('validation_error', 'expires_at must be between 60s and 24h in the future');
  }

  return ttlSeconds;
};

const idempotencyKey = (prefix: string, scope: z.infer<typeof ForwarderIdempotencyScopeSchema>): string => {
  return `${prefix}idem:${scope.tenant_id}:${scope.workload_id}:${scope.integration_id}:${scope.action_group}:${scope.idempotency_key}`;
};

const lockKey = (prefix: string, scope: z.infer<typeof ForwarderIdempotencyScopeSchema>): string => {
  return `${prefix}lock:${scope.tenant_id}:${scope.workload_id}:${scope.integration_id}:${scope.action_group}:${scope.idempotency_key}`;
};

const parseIdempotencyRecord = (payload: string): z.infer<typeof ForwarderIdempotencyRecordSchema> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    throw new DbRepositoryError('validation_error', 'Invalid forwarder idempotency record payload');
  }

  return ForwarderIdempotencyRecordSchema.parse(parsed);
};

export const createForwarderRedisAdapter = (options: ForwarderRedisAdapterOptions = {}): ForwarderRedisAdapter => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);
  const nowProvider = options.now ?? (() => new Date());

  return {
    acquireForwarderExecutionLock: async ({scope, ttl_ms, context}) => {
      const parsedInput = ForwarderExecutionLockAcquireInputSchema.parse({scope, ttl_ms});
      const redis = resolveRedisClient(context);
      const token = randomUUID();
      const key = lockKey(prefix, parsedInput.scope);
      const result = await redis.set(key, token, {NX: true, PX: parsedInput.ttl_ms});
      return {acquired: Boolean(result), lock_token: token};
    },
    releaseForwarderExecutionLock: async ({scope, lock_token, context}) => {
      const parsedInput = ForwarderExecutionLockReleaseInputSchema.parse({scope, lock_token});
      const redis = resolveRedisClient(context);
      const key = lockKey(prefix, parsedInput.scope);
      const result = await redis.eval(LOCK_RELEASE_SCRIPT, [key], [parsedInput.lock_token]);
      return {released: Number(result) > 0};
    },
    createForwarderIdempotencyRecord: async ({
      scope,
      request_fingerprint_sha256,
      correlation_id,
      expires_at,
      context
    }) => {
      const parsedInput = ForwarderIdempotencyRecordInputSchema.parse({
        scope,
        request_fingerprint_sha256,
        correlation_id,
        expires_at
      });
      const redis = resolveRedisClient(context);
      const key = idempotencyKey(prefix, parsedInput.scope);
      const expiresAt = parseExpiresAt(parsedInput.expires_at, 'expires_at');
      const ttlSeconds = computeIdempotencyTtlSeconds(expiresAt, nowProvider());
      const payload = JSON.stringify({
        state: 'in_progress',
        request_fingerprint_sha256: parsedInput.request_fingerprint_sha256,
        correlation_id: parsedInput.correlation_id,
        created_at: nowProvider().toISOString(),
        expires_at: parsedInput.expires_at,
        expires_at_epoch_ms: expiresAt.getTime()
      });

      const result = await redis.set(key, payload, {NX: true, EX: ttlSeconds});
      if (result) {
        return {created: true, conflict: null};
      }

      const existingPayload = await redis.get(key);
      if (!existingPayload) {
        const retryResult = await redis.set(key, payload, {NX: true, EX: ttlSeconds});
        if (retryResult) {
          return {created: true, conflict: null};
        }

        return {created: false, conflict: 'key_exists'};
      }

      let existing: z.infer<typeof ForwarderIdempotencyRecordSchema> | null = null;
      try {
        existing = parseIdempotencyRecord(existingPayload);
      } catch {
        await redis.del(key);
        const retryResult = await redis.set(key, payload, {NX: true, EX: ttlSeconds});
        if (retryResult) {
          return {created: true, conflict: null};
        }

        return {created: false, conflict: 'key_exists'};
      }

      if (existing.request_fingerprint_sha256 !== parsedInput.request_fingerprint_sha256) {
        return {created: false, conflict: 'fingerprint_mismatch'};
      }

      return {created: false, conflict: 'key_exists'};
    },
    getForwarderIdempotencyRecord: async ({scope, context}) => {
      const parsedInput = ForwarderIdempotencyLookupInputSchema.parse({scope});
      const redis = resolveRedisClient(context);
      const key = idempotencyKey(prefix, parsedInput.scope);
      const payload = await redis.get(key);
      if (!payload) {
        return null;
      }

      try {
        return parseIdempotencyRecord(payload);
      } catch {
        await redis.del(key);
        return null;
      }
    },
    completeForwarderIdempotencyRecord: async ({
      scope,
      correlation_id,
      upstream_status_code,
      response_bytes,
      context
    }) => {
      const parsedInput = ForwarderIdempotencyCompleteInputSchema.parse({
        scope,
        correlation_id,
        upstream_status_code,
        response_bytes
      });
      const redis = resolveRedisClient(context);
      const key = idempotencyKey(prefix, parsedInput.scope);
      const result = await redis.eval(
        IDEMPOTENCY_UPDATE_SCRIPT,
        [key],
        ['completed', parsedInput.correlation_id, parsedInput.upstream_status_code, parsedInput.response_bytes, '']
      );
      return {updated: Number(result) > 0};
    },
    failForwarderIdempotencyRecord: async ({scope, correlation_id, error_code, context}) => {
      const parsedInput = ForwarderIdempotencyFailInputSchema.parse({scope, correlation_id, error_code});
      const redis = resolveRedisClient(context);
      const key = idempotencyKey(prefix, parsedInput.scope);
      const result = await redis.eval(
        IDEMPOTENCY_UPDATE_SCRIPT,
        [key],
        ['failed', parsedInput.correlation_id, '', 0, parsedInput.error_code]
      );
      return {updated: Number(result) > 0};
    }
  };
};
