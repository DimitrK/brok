import {z} from 'zod';

import {CanonicalRequestDescriptorSchema, OpenApiTemplateSchema} from '../contracts.js';
import {DbRepositoryError} from '../errors.js';
import {assertNonEmptyString, descriptorHash, normalizeHost, normalizeMethod} from '../utils.js';
import type {RedisClient, RedisEvalClient} from './types.js';

const ApprovalCacheRecordSchema = z
  .object({
    approval_id: z.string().min(1),
    status: z.enum(['pending', 'approved', 'denied', 'expired', 'executed', 'canceled']),
    expires_at: z.iso.datetime({offset: true}),
    template_id: z.string().min(1),
    template_version: z.number().int().gte(1)
  })
  .strict();

const RateLimitInputSchema = z
  .object({
    tenant_id: z.string().min(1),
    workload_id: z.string().min(1),
    integration_id: z.string().min(1),
    action_group: z.string().min(1),
    method: z.string().min(1),
    host: z.string().min(1),
    interval_seconds: z.number().int().gte(1),
    max_requests: z.number().int().gte(1)
  })
  .strict();

type CanonicalizerRedisAdapterOptions = {
  keyPrefix?: string;
  templateCacheTtlSeconds?: number;
};

export type CanonicalizerCacheStoreAdapter = {
  getTemplateCache: (input: {
    tenant_id: string;
    template_id: string;
    version: number;
    context: {clients: {redis?: RedisClient}};
  }) => Promise<z.infer<typeof OpenApiTemplateSchema> | null>;
  setTemplateCache: (input: {
    tenant_id: string;
    template_id: string;
    version: number;
    template: z.infer<typeof OpenApiTemplateSchema>;
    context: {clients: {redis?: RedisClient}};
  }) => Promise<void>;
  getApprovalOnceCache: (input: {
    descriptor: z.infer<typeof CanonicalRequestDescriptorSchema>;
    context: {clients: {redis?: RedisClient}};
  }) => Promise<z.infer<typeof ApprovalCacheRecordSchema> | null>;
  setApprovalOnceCache: (input: {
    descriptor: z.infer<typeof CanonicalRequestDescriptorSchema>;
    value: z.infer<typeof ApprovalCacheRecordSchema>;
    ttl_seconds: number;
    context: {clients: {redis?: RedisClient}};
  }) => Promise<void>;
  incrementRateLimitCounter: (input: {
    tenant_id: string;
    workload_id: string;
    integration_id: string;
    action_group: string;
    method: string;
    host: string;
    interval_seconds: number;
    max_requests: number;
    context: {clients: {redis?: RedisEvalClient}};
  }) => Promise<{allowed: boolean; remaining: number; reset_at: string}>;
};

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return 'broker:canon:';
  }

  return trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
};

const ensurePositiveInt = (value: number, fieldName: string): number => {
  if (!Number.isInteger(value) || value < 1) {
    throw new DbRepositoryError('validation_error', `${fieldName} must be a positive integer`);
  }

  return value;
};

const resolveRedisClient = (context: {clients: {redis?: RedisClient}}): RedisClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for canonicalizer cache');
  }

  return client;
};

const resolveRedisEvalClient = (context: {clients: {redis?: RedisEvalClient}}): RedisEvalClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for canonicalizer rate limits');
  }

  if (typeof client.eval !== 'function') {
    throw new DbRepositoryError('dependency_missing', 'Redis client must support eval for rate limits');
  }

  return client;
};

const templateCacheKey = (prefix: string, tenantId: string, templateId: string, version: number): string =>
  `${prefix}template:${tenantId}:${templateId}:${version}`;

const approvalOnceKey = (prefix: string, descriptor: z.infer<typeof CanonicalRequestDescriptorSchema>): string => {
  const hash = descriptorHash(descriptor);
  return `${prefix}approval:once:${descriptor.tenant_id}:${descriptor.workload_id}:${descriptor.integration_id}:${hash}`;
};

const rateLimitKey = (
  prefix: string,
  input: {
    tenant_id: string;
    workload_id: string;
    integration_id: string;
    action_group: string;
    method: string;
    host: string;
  }
): string => {
  const actionGroup = assertNonEmptyString(input.action_group, 'action_group');
  const method = normalizeMethod(input.method);
  const host = normalizeHost(input.host);

  return `${prefix}rl:${input.tenant_id}:${input.workload_id}:${input.integration_id}:${actionGroup}:${method}:${host}`;
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

export const createCanonicalizerRedisCacheStore = (
  options: CanonicalizerRedisAdapterOptions = {}
): CanonicalizerCacheStoreAdapter => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);
  const templateCacheTtlSeconds = options.templateCacheTtlSeconds ?? 300;
  ensurePositiveInt(templateCacheTtlSeconds, 'templateCacheTtlSeconds');

  return {
    getTemplateCache: async ({tenant_id, template_id, version, context}) => {
      const parsedVersion = ensurePositiveInt(version, 'version');
      const parsedTenant = assertNonEmptyString(tenant_id, 'tenant_id');
      const parsedTemplate = assertNonEmptyString(template_id, 'template_id');
      const redis = resolveRedisClient(context);
      const key = templateCacheKey(prefix, parsedTenant, parsedTemplate, parsedVersion);
      const payload = await redis.get(key);
      if (!payload) {
        return null;
      }

      let decoded: unknown;
      try {
        decoded = JSON.parse(payload);
      } catch {
        await redis.del(key);
        return null;
      }

      const parsedTemplatePayload = OpenApiTemplateSchema.safeParse(decoded);
      if (!parsedTemplatePayload.success) {
        await redis.del(key);
        return null;
      }

      return parsedTemplatePayload.data;
    },
    setTemplateCache: async ({tenant_id, template_id, version, template, context}) => {
      const parsedVersion = ensurePositiveInt(version, 'version');
      const parsedTenant = assertNonEmptyString(tenant_id, 'tenant_id');
      const parsedTemplateId = assertNonEmptyString(template_id, 'template_id');
      const parsedTemplate = OpenApiTemplateSchema.parse(template);
      const redis = resolveRedisClient(context);
      const key = templateCacheKey(prefix, parsedTenant, parsedTemplateId, parsedVersion);
      const payload = JSON.stringify(parsedTemplate);

      const result = await redis.set(key, payload, {EX: templateCacheTtlSeconds});
      if (!result) {
        throw new DbRepositoryError('unexpected_error', 'Failed to persist template cache entry');
      }
    },
    getApprovalOnceCache: async ({descriptor, context}) => {
      const parsedDescriptor = CanonicalRequestDescriptorSchema.parse(descriptor);
      const redis = resolveRedisClient(context);
      const key = approvalOnceKey(prefix, parsedDescriptor);
      const payload = await redis.get(key);
      if (!payload) {
        return null;
      }

      let decoded: unknown;
      try {
        decoded = JSON.parse(payload);
      } catch {
        await redis.del(key);
        return null;
      }

      const parsedRecord = ApprovalCacheRecordSchema.safeParse(decoded);
      if (!parsedRecord.success) {
        await redis.del(key);
        return null;
      }

      return parsedRecord.data;
    },
    setApprovalOnceCache: async ({descriptor, value, ttl_seconds, context}) => {
      const parsedDescriptor = CanonicalRequestDescriptorSchema.parse(descriptor);
      const parsedValue = ApprovalCacheRecordSchema.parse(value);
      const ttlSeconds = ensurePositiveInt(ttl_seconds, 'ttl_seconds');
      const redis = resolveRedisClient(context);
      const key = approvalOnceKey(prefix, parsedDescriptor);
      const payload = JSON.stringify(parsedValue);

      const result = await redis.set(key, payload, {EX: ttlSeconds});
      if (!result) {
        throw new DbRepositoryError('unexpected_error', 'Failed to persist approval cache entry');
      }
    },
    incrementRateLimitCounter: async input => {
      const {context, ...rawInput} = input;
      const parsedInput = RateLimitInputSchema.parse(rawInput);
      if (!context) {
        throw new DbRepositoryError('dependency_missing', 'Redis client is required for canonicalizer rate limits');
      }
      const redis = resolveRedisEvalClient(context);
      const redisKey = rateLimitKey(prefix, parsedInput);
      const intervalMs = parsedInput.interval_seconds * 1000;
      const result = await redis.eval(RATE_LIMIT_SCRIPT, [redisKey], [intervalMs]);
      const {count, ttlMs} = parseEvalResult(result);
      const remaining = Math.max(0, parsedInput.max_requests - count);
      const resetAt = new Date(Date.now() + Math.max(0, ttlMs)).toISOString();

      return {
        allowed: count <= parsedInput.max_requests,
        remaining,
        reset_at: resetAt
      };
    }
  };
};
