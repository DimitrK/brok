import {randomUUID} from 'node:crypto';
import {z} from 'zod';

import {DbRepositoryError} from '../errors.js';
import type {RedisEvalClient} from './types.js';

const CryptoRotationLockNameSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9:_-]+$/u);

const AcquireCryptoRotationLockInputSchema = z
  .object({
    lock_name: CryptoRotationLockNameSchema,
    ttl_ms: z.number().int().gte(1).lte(900_000)
  })
  .strict();

const ReleaseCryptoRotationLockInputSchema = z
  .object({
    lock_name: CryptoRotationLockNameSchema,
    token: z.string().uuid()
  })
  .strict();

const LOCK_RELEASE_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`;

type CryptoRedisAdapterOptions = {
  keyPrefix?: string;
};

export type CryptoRotationLockAdapter = {
  acquireCryptoRotationLock: (input: {
    lock_name: string;
    ttl_ms: number;
    context: {
      clients: {
        redis?: RedisEvalClient;
      };
    };
  }) => Promise<{acquired: boolean; token: string}>;
  releaseCryptoRotationLock: (input: {
    lock_name: string;
    token: string;
    context: {
      clients: {
        redis?: RedisEvalClient;
      };
    };
  }) => Promise<{released: boolean}>;
};

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return 'broker:crypto:';
  }

  return trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
};

const resolveRedisClient = (context: {clients: {redis?: RedisEvalClient}}): RedisEvalClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for crypto rotation locks');
  }

  if (typeof client.set !== 'function' || typeof client.eval !== 'function') {
    throw new DbRepositoryError(
      'dependency_missing',
      'Redis client must support set and eval for crypto rotation locks'
    );
  }

  return client;
};

const rotationLockKey = (prefix: string, lockName: string): string => `${prefix}rotation-lock:v1:${lockName}`;

export const createCryptoRedisRotationLockAdapter = (
  options: CryptoRedisAdapterOptions = {}
): CryptoRotationLockAdapter => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);

  return {
    acquireCryptoRotationLock: async ({lock_name, ttl_ms, context}) => {
      const parsedInput = AcquireCryptoRotationLockInputSchema.parse({
        lock_name,
        ttl_ms
      });

      const redis = resolveRedisClient(context);
      const token = randomUUID();
      const key = rotationLockKey(prefix, parsedInput.lock_name);
      const result = await redis.set(key, token, {NX: true, PX: parsedInput.ttl_ms});
      return {acquired: Boolean(result), token};
    },
    releaseCryptoRotationLock: async ({lock_name, token, context}) => {
      const parsedInput = ReleaseCryptoRotationLockInputSchema.parse({
        lock_name,
        token
      });

      const redis = resolveRedisClient(context);
      const key = rotationLockKey(prefix, parsedInput.lock_name);
      const result = await redis.eval(LOCK_RELEASE_SCRIPT, [key], [parsedInput.token]);
      return {released: Number(result) > 0};
    }
  };
};
