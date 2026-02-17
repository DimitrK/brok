import {createHash} from 'node:crypto';

import {z} from 'zod';

import {OpenApiAuditEventSchema, type AuditEvent} from '../contracts.js';
import {DbRepositoryError} from '../errors.js';
import {assertNonEmptyString} from '../utils.js';
import type {RedisScanClient} from './types.js';

const AuditSearchDecisionSchema = z.enum(['allowed', 'denied', 'approval_required', 'throttled']);

const AuditEventSearchFilterSchema = z
  .object({
    time_min: z.date().optional(),
    time_max: z.date().optional(),
    tenant_id: z.string().optional(),
    workload_id: z.string().optional(),
    integration_id: z.string().optional(),
    action_group: z.string().optional(),
    decision: AuditSearchDecisionSchema.optional()
  })
  .strict();

const TypedAuditEventSchema: z.ZodType<AuditEvent> = OpenApiAuditEventSchema;

const AuditQueryCachePayloadSchema: z.ZodType<{events: AuditEvent[]}> = z
  .object({
    events: z.array(TypedAuditEventSchema)
  })
  .strict();

type AuditRedisCacheOptions = {
  redisClient: RedisScanClient;
  keyPrefix?: string;
  cacheTtlSeconds?: number;
  ttlJitterSeconds?: number;
  scanCount?: number;
};

export type AuditRedisCacheAdapter = {
  getJson: (input: {key: string; db_context?: unknown}) => Promise<Record<string, unknown> | null>;
  setJson: (input: {key: string; value: unknown; ttl_seconds: number; db_context?: unknown}) => Promise<void>;
  deleteByPrefix: (input: {prefix: string; db_context?: unknown}) => Promise<void>;
  buildAuditQueryCacheKey: (input: {tenant_id: string; filter: z.infer<typeof AuditEventSearchFilterSchema>}) => string;
  getAuditQueryCachePrefixForTenant: (tenant_id: string) => string;
  getCachedAuditQuery: (input: {
    tenant_id: string;
    filter: z.infer<typeof AuditEventSearchFilterSchema>;
  }) => Promise<AuditEvent[] | null>;
  setCachedAuditQuery: (input: {
    tenant_id: string;
    filter: z.infer<typeof AuditEventSearchFilterSchema>;
    events: AuditEvent[];
    ttl_seconds?: number;
  }) => Promise<void>;
  getOrSetAuditQuery: (input: {
    tenant_id: string;
    filter: z.infer<typeof AuditEventSearchFilterSchema>;
    loader: () => Promise<AuditEvent[]>;
    ttl_seconds?: number;
  }) => Promise<AuditEvent[]>;
  invalidateAuditQueryCacheByTenant: (input: {tenant_id: string; db_context?: unknown}) => Promise<void>;
};

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return '';
  }

  return trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
};

const ensurePositiveInt = (value: number, fieldName: string): number => {
  if (!Number.isInteger(value) || value < 1) {
    throw new DbRepositoryError('validation_error', `${fieldName} must be a positive integer`);
  }

  return value;
};

const toStableHashInput = (value: unknown): string => {
  if (typeof value === 'undefined') {
    return '"__undefined__"';
  }
  if (value === null || typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }
  if (Array.isArray(value)) {
    return `[${value.map(item => toStableHashInput(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey))
      .map(([key, entry]) => `${JSON.stringify(key)}:${toStableHashInput(entry)}`)
      .join(',');
    return `{${entries}}`;
  }
  if (typeof value === 'bigint') {
    return JSON.stringify(value.toString());
  }
  if (typeof value === 'symbol') {
    throw new DbRepositoryError('validation_error', 'Audit filter must not include symbol values');
  }
  if (typeof value === 'function') {
    throw new DbRepositoryError('validation_error', 'Audit filter must not include function values');
  }
  return JSON.stringify(null);
};

const toCachePayload = (events: AuditEvent[]): Record<string, unknown> => ({events});

const toAuditQueryCacheKey = (input: {prefix: string; tenant_id: string; filter: unknown}): string => {
  const tenantId = assertNonEmptyString(input.tenant_id, 'tenant_id');
  const filterHash = createHash('sha256').update(toStableHashInput(input.filter)).digest('hex');
  return `${input.prefix}audit:${tenantId}:query:${filterHash}`;
};

const toAuditQueryCachePrefix = (prefix: string, tenantId: string): string => `${prefix}audit:${tenantId}:query:`;

const parseAuditEvents = (value: unknown): AuditEvent[] => {
  if (!Array.isArray(value)) {
    throw new DbRepositoryError('validation_error', 'Audit cache payload must be an array');
  }

  const parsedEvents: AuditEvent[] = [];
  for (const event of value) {
    const parsedEvent = TypedAuditEventSchema.parse(event);
    parsedEvents.push(parsedEvent);
  }

  return parsedEvents;
};

const parseCachedEvents = (value: Record<string, unknown> | null): AuditEvent[] | null => {
  if (!value) {
    return null;
  }

  const parsed = AuditQueryCachePayloadSchema.safeParse(value);
  if (!parsed.success) {
    return null;
  }

  return parseAuditEvents(parsed.data.events);
};

const computeTtlSeconds = ({baseSeconds, jitterSeconds}: {baseSeconds: number; jitterSeconds: number}): number => {
  const base = ensurePositiveInt(baseSeconds, 'cacheTtlSeconds');
  if (!Number.isInteger(jitterSeconds) || jitterSeconds < 0) {
    throw new DbRepositoryError('validation_error', 'ttlJitterSeconds must be >= 0');
  }

  if (jitterSeconds === 0) {
    return base;
  }

  const jitter = Math.floor(Math.random() * (jitterSeconds + 1));
  return base + jitter;
};

const DELETE_BY_PREFIX_SCRIPT = [
  '-- audit_delete_by_prefix',
  'local cursor = "0"',
  'local total = 0',
  'local pattern = ARGV[1]',
  'local count = tonumber(ARGV[2])',
  'repeat',
  '  local result = redis.call("SCAN", cursor, "MATCH", pattern, "COUNT", count)',
  '  cursor = result[1]',
  '  local keys = result[2]',
  '  if #keys > 0 then',
  '    total = total + redis.call("DEL", unpack(keys))',
  '  end',
  'until cursor == "0"',
  'return total'
].join('\n');

const deleteByPrefix = async (redis: RedisScanClient, prefix: string, scanCount: number): Promise<void> => {
  const pattern = `${prefix}*`;
  let cursor = '0';
  const count = ensurePositiveInt(scanCount, 'scanCount');

  if (typeof (redis as {eval?: unknown}).eval === 'function') {
    await (redis as RedisScanClient & {eval: (script: string, keys: string[], args: Array<string | number>) => unknown}).eval(
      DELETE_BY_PREFIX_SCRIPT,
      [],
      [pattern, count]
    );
    return;
  }

  do {
    const [nextCursor, keys] = await redis.scan(cursor, {MATCH: pattern, COUNT: count});
    cursor = nextCursor;
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } while (cursor !== '0');
};

export const createAuditRedisCacheAdapter = (options: AuditRedisCacheOptions): AuditRedisCacheAdapter => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);
  const cacheTtlSeconds = options.cacheTtlSeconds ?? 30;
  const ttlJitterSeconds = options.ttlJitterSeconds ?? 5;
  const scanCount = options.scanCount ?? 100;
  const redis = options.redisClient;
  if (!redis) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for audit cache');
  }
  if (typeof redis.scan !== 'function') {
    throw new DbRepositoryError('dependency_missing', 'Redis client must support scan for audit cache invalidation');
  }

  const buildKey = (tenant_id: string, filter: z.infer<typeof AuditEventSearchFilterSchema>): string =>
    toAuditQueryCacheKey({prefix, tenant_id, filter});

  const readCachedAuditQuery = async ({
    tenant_id,
    filter
  }: {
    tenant_id: string;
    filter: z.infer<typeof AuditEventSearchFilterSchema>;
  }): Promise<AuditEvent[] | null> => {
    const parsedFilter = AuditEventSearchFilterSchema.parse(filter);
    const key = buildKey(tenant_id, parsedFilter);
    const cached = await redis.get(key);
    if (!cached) {
      return null;
    }

    let parsedPayload: Record<string, unknown> | null = null;
    try {
      parsedPayload = JSON.parse(cached) as Record<string, unknown>;
    } catch {
      await redis.del(key);
      return null;
    }

    const parsedEvents = parseCachedEvents(parsedPayload);
    if (!parsedEvents) {
      await redis.del(key);
      return null;
    }

    return parsedEvents;
  };

  const writeCachedAuditQuery = async ({
    tenant_id,
    filter,
    events,
    ttl_seconds
  }: {
    tenant_id: string;
    filter: z.infer<typeof AuditEventSearchFilterSchema>;
    events: AuditEvent[];
    ttl_seconds?: number;
  }): Promise<void> => {
    const parsedFilter = AuditEventSearchFilterSchema.parse(filter);
    const parsedEvents = parseAuditEvents(events);
    const key = buildKey(tenant_id, parsedFilter);
    const ttlSeconds = computeTtlSeconds({
      baseSeconds: ttl_seconds ?? cacheTtlSeconds,
      jitterSeconds: ttlJitterSeconds
    });
    const payload = JSON.stringify(toCachePayload(parsedEvents));
    const result = await redis.set(key, payload, {EX: ttlSeconds});
    if (!result) {
      throw new DbRepositoryError('unexpected_error', 'Failed to persist audit query cache entry');
    }
  };

  return {
    getJson: async ({key, db_context}) => {
      void db_context;
      const payload = await redis.get(key);
      if (!payload) {
        return null;
      }

      try {
        return JSON.parse(payload) as Record<string, unknown>;
      } catch {
        await redis.del(key);
        return null;
      }
    },
    setJson: async ({key, value, ttl_seconds, db_context}) => {
      void db_context;
      const ttlSeconds = ensurePositiveInt(ttl_seconds, 'ttl_seconds');
      const payload = JSON.stringify(value);
      const result = await redis.set(key, payload, {EX: ttlSeconds});
      if (!result) {
        throw new DbRepositoryError('unexpected_error', 'Failed to persist audit cache entry');
      }
    },
    deleteByPrefix: async ({prefix: targetPrefix, db_context}) => {
      void db_context;
      await deleteByPrefix(redis, targetPrefix, scanCount);
    },
    buildAuditQueryCacheKey: ({tenant_id, filter}) => {
      const parsedFilter = AuditEventSearchFilterSchema.parse(filter);
      return buildKey(tenant_id, parsedFilter);
    },
    getAuditQueryCachePrefixForTenant: tenant_id => {
      const parsedTenantId = assertNonEmptyString(tenant_id, 'tenant_id');
      return toAuditQueryCachePrefix(prefix, parsedTenantId);
    },
    getCachedAuditQuery: async ({tenant_id, filter}) => {
      return readCachedAuditQuery({tenant_id, filter});
    },
    setCachedAuditQuery: async ({tenant_id, filter, events, ttl_seconds}) => {
      await writeCachedAuditQuery({tenant_id, filter, events, ttl_seconds});
    },
    getOrSetAuditQuery: async ({tenant_id, filter, loader, ttl_seconds}) => {
      const cached = await readCachedAuditQuery({tenant_id, filter});
      if (cached) {
        return cached;
      }

      const events = await loader();
      // Defensive parse in case the loader returns unvalidated data.
      const parsedEvents = parseAuditEvents(events);
      try {
        await writeCachedAuditQuery({tenant_id, filter, events: parsedEvents, ttl_seconds});
      } catch {
        // Best-effort cache write; source-of-truth remains Postgres.
      }

      return parsedEvents;
    },
    invalidateAuditQueryCacheByTenant: async ({tenant_id}) => {
      const prefixKey = toAuditQueryCachePrefix(prefix, assertNonEmptyString(tenant_id, 'tenant_id'));
      await deleteByPrefix(redis, prefixKey, scanCount);
    }
  };
};
