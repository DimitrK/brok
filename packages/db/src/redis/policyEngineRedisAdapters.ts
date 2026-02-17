import {z} from 'zod';

import {OpenApiPolicyRuleSchema} from '../contracts.js';
import {DbRepositoryError} from '../errors.js';
import type {RedisEvalClient} from './types.js';

const RateLimitInputSchema = z
  .object({
    key: z.string().min(1),
    rule: OpenApiPolicyRuleSchema,
    now: z.date()
  })
  .strict();

type PolicyEngineRedisAdapterOptions = {
  keyPrefix?: string;
};

export type PolicyEngineRateLimitStoreAdapter = {
  checkAndConsumePolicyRateLimit: (input: {
    descriptor: unknown;
    rule: z.infer<typeof OpenApiPolicyRuleSchema>;
    key: string;
    now: Date;
    context: {
      clients: {
        redis?: RedisEvalClient;
      };
    };
  }) => Promise<{allowed: boolean; remaining?: number; reset_at?: string}>;
};

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return 'broker:pe:';
  }

  return trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
};

const RATE_LIMIT_SCRIPT = [
  'local current = redis.call("INCR", KEYS[1])',
  'local ttl = redis.call("PTTL", KEYS[1])',
  'if ttl < 0 then',
  '  redis.call("PEXPIRE", KEYS[1], tonumber(ARGV[1]))',
  '  ttl = tonumber(ARGV[1])',
  'end',
  'return {current, ttl}'
].join('\n');

const parseEvalResult = (value: unknown): {count: number; ttlMs: number} => {
  if (!Array.isArray(value) || value.length < 2) {
    throw new DbRepositoryError('unexpected_error', 'Invalid rate limit response payload');
  }

  const values = value as unknown[];
  const countRaw = values[0];
  const ttlRaw = values[1];
  const count = Number(countRaw);
  const ttlMs = Number(ttlRaw);
  if (!Number.isFinite(count) || !Number.isFinite(ttlMs)) {
    throw new DbRepositoryError('unexpected_error', 'Invalid rate limit response payload');
  }

  return {count, ttlMs};
};

const resolveRedisClient = (context: {clients: {redis?: RedisEvalClient}}): RedisEvalClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for rate limit checks');
  }

  if (typeof client.eval !== 'function') {
    throw new DbRepositoryError('dependency_missing', 'Redis client must support eval for rate limit checks');
  }

  return client;
};

export const createPolicyEngineRedisRateLimitStore = (
  options: PolicyEngineRedisAdapterOptions = {}
): PolicyEngineRateLimitStoreAdapter => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);

  return {
    checkAndConsumePolicyRateLimit: async ({rule, key, now, context}) => {
      const parsedInput = RateLimitInputSchema.parse({
        key,
        rule,
        now
      });

      if (parsedInput.rule.rule_type !== 'rate_limit' || !parsedInput.rule.rate_limit) {
        throw new DbRepositoryError('validation_error', 'rate_limit rule must include a non-null rate_limit payload');
      }

      const {max_requests, interval_seconds} = parsedInput.rule.rate_limit;
      if (!Number.isInteger(max_requests) || max_requests < 1) {
        throw new DbRepositoryError('validation_error', 'rate_limit.max_requests must be >= 1');
      }

      if (!Number.isInteger(interval_seconds) || interval_seconds < 1) {
        throw new DbRepositoryError('validation_error', 'rate_limit.interval_seconds must be >= 1');
      }

      const redis = resolveRedisClient(context);
      const redisKey = `${prefix}rl:v1:${parsedInput.key}`;
      const intervalMs = interval_seconds * 1000;

      const result = await redis.eval(RATE_LIMIT_SCRIPT, [redisKey], [intervalMs]);
      const {count, ttlMs} = parseEvalResult(result);

      const remaining = Math.max(0, max_requests - count);
      const resetAt = new Date(parsedInput.now.getTime() + Math.max(0, ttlMs)).toISOString();

      return {
        allowed: count <= max_requests,
        remaining,
        reset_at: resetAt
      };
    }
  };
};
