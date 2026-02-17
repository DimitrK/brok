import {BlockList, isIP} from 'node:net';

import {z} from 'zod';

import {DbRepositoryError} from '../errors.js';
import type {RedisClient, RedisEvalClient, RedisPubSubClient} from './types.js';

const MAX_NORMALIZED_HOST_LENGTH = 253;
const DNS_CACHE_TTL_SECONDS_MIN = 1;
const DNS_CACHE_TTL_SECONDS_MAX = 60;
const PRIVATE_CIDR_RANGES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '100.64.0.0/10',
  '198.18.0.0/15',
  'fc00::/7'
] as const;
const LOOPBACK_CIDR_RANGES = ['127.0.0.0/8', '::1/128'] as const;
const LINK_LOCAL_CIDR_RANGES = ['169.254.0.0/16', 'fe80::/10'] as const;
const METADATA_CIDR_RANGES = ['169.254.169.254/32', 'fd00:ec2::254/128'] as const;

type IpFamily = 'ipv4' | 'ipv6';
type CidrRange = `${string}/${number}`;

const NonEmptyStringSchema = z.string().trim().min(1);

const normalizeHost = (raw: string): string => {
  const trimmed = raw.trim().toLowerCase();
  if (trimmed.endsWith('.')) {
    return trimmed.slice(0, -1);
  }

  return trimmed;
};

const isAscii = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 33 || code > 126) {
      return false;
    }
  }

  return true;
};

const isAlphaNumeric = (value: string): boolean => {
  const code = value.charCodeAt(0);
  return (code >= 48 && code <= 57) || (code >= 97 && code <= 122);
};

const isValidDnsLabel = (value: string): boolean => {
  if (value.length < 1 || value.length > 63) {
    return false;
  }

  if (!isAlphaNumeric(value.charAt(0)) || !isAlphaNumeric(value.charAt(value.length - 1))) {
    return false;
  }

  for (let index = 0; index < value.length; index += 1) {
    const char = value.charAt(index);
    const code = char.charCodeAt(0);
    const isHyphen = code === 45;
    const isNumeric = code >= 48 && code <= 57;
    const isLowerAlpha = code >= 97 && code <= 122;
    if (!isHyphen && !isNumeric && !isLowerAlpha) {
      return false;
    }
  }

  return true;
};

const isValidNormalizedHost = (value: string): boolean => {
  if (isIP(value) > 0) {
    return true;
  }

  if (value.length > MAX_NORMALIZED_HOST_LENGTH || !isAscii(value) || value.includes('..')) {
    return false;
  }

  const labels = value.split('.');
  if (labels.length === 0) {
    return false;
  }

  for (const label of labels) {
    if (!isValidDnsLabel(label)) {
      return false;
    }
  }

  return true;
};

export const NormalizedHostSchema = z
  .string()
  .trim()
  .min(1)
  .transform(value => normalizeHost(value))
  .refine(value => value.length >= 1 && value.length <= MAX_NORMALIZED_HOST_LENGTH, {
    message: `normalized_host must be between 1 and ${MAX_NORMALIZED_HOST_LENGTH} characters`
  })
  .refine(value => isValidNormalizedHost(value), {
    message: 'normalized_host must be a lower-case ASCII FQDN or IP literal'
  });

const IpLiteralSchema = z.string().trim().refine(value => isIP(value) > 0, {
  message: 'IP address must be a valid IPv4 or IPv6 literal'
});

const getIpFamily = (value: string): IpFamily | null => {
  const version = isIP(value);
  if (version === 4) {
    return 'ipv4';
  }
  if (version === 6) {
    return 'ipv6';
  }
  return null;
};

const parseCidrRange = (value: CidrRange): {network: string; prefix: number; family: IpFamily} => {
  const [network, prefixValue] = value.split('/', 2);
  const family = getIpFamily(network);
  const prefix = Number.parseInt(prefixValue ?? '', 10);
  if (!family || !Number.isInteger(prefix)) {
    throw new DbRepositoryError('unexpected_error', `Invalid CIDR range: ${value}`);
  }

  const maxPrefix = family === 'ipv4' ? 32 : 128;
  if (prefix < 0 || prefix > maxPrefix) {
    throw new DbRepositoryError('unexpected_error', `Invalid CIDR prefix: ${value}`);
  }

  return {network, prefix, family};
};

const buildBlockList = (ranges: readonly CidrRange[]): BlockList => {
  const blockList = new BlockList();
  for (const range of ranges) {
    const parsed = parseCidrRange(range);
    blockList.addSubnet(parsed.network, parsed.prefix, parsed.family);
  }
  return blockList;
};

const PRIVATE_BLOCKLIST = buildBlockList(PRIVATE_CIDR_RANGES);
const LOOPBACK_BLOCKLIST = buildBlockList(LOOPBACK_CIDR_RANGES);
const LINK_LOCAL_BLOCKLIST = buildBlockList(LINK_LOCAL_CIDR_RANGES);
const METADATA_BLOCKLIST = buildBlockList(METADATA_CIDR_RANGES);

const isDeniedResolvedIp = (value: string): boolean => {
  const family = getIpFamily(value);
  if (!family) {
    return true;
  }

  return (
    METADATA_BLOCKLIST.check(value, family) ||
    LOOPBACK_BLOCKLIST.check(value, family) ||
    LINK_LOCAL_BLOCKLIST.check(value, family) ||
    PRIVATE_BLOCKLIST.check(value, family)
  );
};

export const DnsResolutionCacheEntrySchema = z
  .object({
    resolved_ips: z.array(IpLiteralSchema).min(1),
    resolved_at_epoch_ms: z.number().int().gte(0),
    ttl_seconds: z.number().int().gte(DNS_CACHE_TTL_SECONDS_MIN).lte(DNS_CACHE_TTL_SECONDS_MAX)
  })
  .superRefine((value, context) => {
    for (const address of value.resolved_ips) {
      if (isDeniedResolvedIp(address)) {
        context.addIssue({
          code: 'custom',
          message: `resolved_ips contains denylisted address: ${address}`,
          path: ['resolved_ips']
        });
        break;
      }
    }
  })
  .strict();

export const DnsRebindingObservationSchema = z
  .object({
    ip_set_hash: NonEmptyStringSchema,
    resolved_ips: z.array(IpLiteralSchema).min(1),
    observed_at_epoch_ms: z.number().int().gte(0)
  })
  .strict();

const DnsRebindingHistorySchema = z.array(DnsRebindingObservationSchema);

export const TemplateInvalidationSignalSchema = z
  .object({
    template_id: NonEmptyStringSchema,
    version: z.number().int().gte(1),
    tenant_id: NonEmptyStringSchema,
    updated_at: z.iso.datetime({offset: true})
  })
  .strict();

const ReadDnsResolutionCacheInputSchema = z
  .object({
    normalized_host: NormalizedHostSchema
  })
  .strict();

const UpsertDnsResolutionCacheInputSchema = z
  .object({
    normalized_host: NormalizedHostSchema,
    entry: DnsResolutionCacheEntrySchema
  })
  .strict();

const AppendDnsRebindingObservationInputSchema = z
  .object({
    normalized_host: NormalizedHostSchema,
    observation: DnsRebindingObservationSchema
  })
  .strict();

const ReadDnsRebindingObservationHistoryInputSchema = z
  .object({
    normalized_host: NormalizedHostSchema
  })
  .strict();

const PublishTemplateInvalidationSignalInputSchema = z
  .object({
    signal: TemplateInvalidationSignalSchema
  })
  .strict();

const SubscribeTemplateInvalidationSignalInputSchema = z
  .object({
    onSignal: z.custom<(signal: TemplateInvalidationSignal) => void>(
      value => typeof value === 'function',
      'onSignal must be a function'
    )
  })
  .strict();

type SsrfGuardRedisAdapterOptions = {
  keyPrefix?: string;
  dnsHistoryTtlSeconds?: number;
  dnsHistoryMaxEntries?: number;
};

export type DnsResolutionCacheEntry = z.infer<typeof DnsResolutionCacheEntrySchema>;
export type DnsRebindingObservation = z.infer<typeof DnsRebindingObservationSchema>;
export type TemplateInvalidationSignal = z.infer<typeof TemplateInvalidationSignalSchema>;
export type DnsCacheWriteOutcome = 'applied' | 'skipped_stale';

export type SsrfGuardRedisAdapter = {
  readDnsResolutionCache: (input: {
    normalized_host: string;
    context: {
      clients: {
        redis?: RedisClient;
      };
    };
  }) => Promise<DnsResolutionCacheEntry | null>;
  upsertDnsResolutionCache: (input: {
    normalized_host: string;
    entry: DnsResolutionCacheEntry;
    context: {
      clients: {
        redis?: RedisEvalClient;
      };
    };
  }) => Promise<{outcome: DnsCacheWriteOutcome; applied: boolean; entry: DnsResolutionCacheEntry}>;
  appendDnsRebindingObservation: (input: {
    normalized_host: string;
    observation: DnsRebindingObservation;
    context: {
      clients: {
        redis?: RedisEvalClient;
      };
    };
  }) => Promise<{observation: DnsRebindingObservation; history_size: number}>;
  readDnsRebindingObservationHistory: (input: {
    normalized_host: string;
    context: {
      clients: {
        redis?: RedisClient;
      };
    };
  }) => Promise<DnsRebindingObservation[]>;
  publishTemplateInvalidationSignal: (input: {
    signal: TemplateInvalidationSignal;
    context: {
      clients: {
        redis?: RedisPubSubClient;
      };
    };
  }) => Promise<void>;
  subscribeTemplateInvalidationSignal: (input: {
    onSignal: (signal: TemplateInvalidationSignal) => void;
    context: {
      clients: {
        redis?: RedisPubSubClient;
      };
    };
  }) => () => void;
};

const DNS_CACHE_CAS_SCRIPT = [
  '-- ssrf_dns_cache_cas',
  'local payload = ARGV[1]',
  'local ttl = tonumber(ARGV[2])',
  'local newResolvedAtMs = tonumber(ARGV[3])',
  'local existing = redis.call("GET", KEYS[1])',
  'if not existing then',
  '  redis.call("SET", KEYS[1], payload, "EX", ttl)',
  '  return "applied"',
  'end',
  'local ok, parsed = pcall(cjson.decode, existing)',
  'if not ok or type(parsed) ~= "table" then',
  '  redis.call("SET", KEYS[1], payload, "EX", ttl)',
  '  return "applied"',
  'end',
  'local existingResolvedAtMs = tonumber(parsed["resolved_at_epoch_ms"])',
  'if not existingResolvedAtMs or newResolvedAtMs >= existingResolvedAtMs then',
  '  redis.call("SET", KEYS[1], payload, "EX", ttl)',
  '  return "applied"',
  'end',
  'return "skipped_stale"'
].join('\n');

const DNS_REBINDING_APPEND_SCRIPT = [
  '-- ssrf_dns_history_append',
  'local payload = ARGV[1]',
  'local ttl = tonumber(ARGV[2])',
  'local maxEntries = tonumber(ARGV[3])',
  'local existing = redis.call("GET", KEYS[1])',
  'local history = {}',
  'if existing then',
  '  local ok, parsed = pcall(cjson.decode, existing)',
  '  if ok and type(parsed) == "table" then',
  '    history = parsed',
  '  end',
  'end',
  'local observation = cjson.decode(payload)',
  'table.insert(history, observation)',
  'while #history > maxEntries do',
  '  table.remove(history, 1)',
  'end',
  'redis.call("SET", KEYS[1], cjson.encode(history), "EX", ttl)',
  'return #history'
].join('\n');

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return 'broker:ssrf:';
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
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for SSRF storage');
  }

  return client;
};

const resolveRedisEvalClient = (context: {clients: {redis?: RedisEvalClient}}): RedisEvalClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for SSRF storage');
  }

  if (typeof client.eval !== 'function') {
    throw new DbRepositoryError('dependency_missing', 'Redis client must support eval for SSRF storage');
  }

  return client;
};

const resolveRedisPubSubClient = (context: {clients: {redis?: RedisPubSubClient}}): RedisPubSubClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for SSRF invalidation');
  }

  if (typeof client.publish !== 'function' || typeof client.subscribe !== 'function') {
    throw new DbRepositoryError('dependency_missing', 'Redis client must support pub/sub for SSRF invalidation');
  }

  return client;
};

const dnsCacheKey = (prefix: string, normalizedHost: string): string => `${prefix}dns:v1:${normalizedHost}`;

const dnsHistoryKey = (prefix: string, normalizedHost: string): string =>
  `${prefix}dns-history:v1:${normalizedHost}`;

const parseDnsCacheEntry = (value: string): DnsResolutionCacheEntry | null => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }

  const result = DnsResolutionCacheEntrySchema.safeParse(parsed);
  if (!result.success) {
    return null;
  }

  return result.data;
};

const parseDnsRebindingHistory = (value: string): DnsRebindingObservation[] | null => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }

  const result = DnsRebindingHistorySchema.safeParse(parsed);
  if (!result.success) {
    return null;
  }

  return result.data;
};

const decodeInvalidationSignal = (payload: string): TemplateInvalidationSignal | null => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }

  const result = TemplateInvalidationSignalSchema.safeParse(parsed);
  if (!result.success) {
    return null;
  }

  return result.data;
};

const parseDnsWriteOutcome = (value: unknown): DnsCacheWriteOutcome => {
  if (value === 'applied' || value === 'skipped_stale') {
    return value;
  }

  throw new DbRepositoryError('unexpected_error', 'Unexpected DNS cache CAS response payload');
};

const parseHistorySize = (value: unknown): number => {
  const historySize = Number(value);
  if (!Number.isInteger(historySize) || historySize < 0) {
    throw new DbRepositoryError('unexpected_error', 'Unexpected DNS history append response payload');
  }

  return historySize;
};

export const createSsrfGuardRedisAdapter = (options: SsrfGuardRedisAdapterOptions = {}): SsrfGuardRedisAdapter => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);
  const dnsHistoryTtlSeconds = ensurePositiveInt(options.dnsHistoryTtlSeconds ?? 60 * 60 * 24, 'dnsHistoryTtlSeconds');
  const dnsHistoryMaxEntries = ensurePositiveInt(options.dnsHistoryMaxEntries ?? 100, 'dnsHistoryMaxEntries');
  const invalidationChannel = `${prefix}invalidation:v1`;

  return {
    readDnsResolutionCache: async ({normalized_host, context}) => {
      const parsedInput = ReadDnsResolutionCacheInputSchema.parse({normalized_host});
      const redis = resolveRedisClient(context);
      const key = dnsCacheKey(prefix, parsedInput.normalized_host);
      const payload = await redis.get(key);
      if (!payload) {
        return null;
      }

      const parsed = parseDnsCacheEntry(payload);
      if (!parsed) {
        await redis.del(key);
        return null;
      }

      return parsed;
    },
    upsertDnsResolutionCache: async ({normalized_host, entry, context}) => {
      const parsedInput = UpsertDnsResolutionCacheInputSchema.parse({normalized_host, entry});
      const redis = resolveRedisEvalClient(context);
      const key = dnsCacheKey(prefix, parsedInput.normalized_host);
      const result = await redis.eval(DNS_CACHE_CAS_SCRIPT, [key], [
        JSON.stringify(parsedInput.entry),
        parsedInput.entry.ttl_seconds,
        parsedInput.entry.resolved_at_epoch_ms
      ]);

      const outcome = parseDnsWriteOutcome(result);
      return {
        outcome,
        applied: outcome === 'applied',
        entry: parsedInput.entry
      };
    },
    appendDnsRebindingObservation: async ({normalized_host, observation, context}) => {
      const parsedInput = AppendDnsRebindingObservationInputSchema.parse({
        normalized_host,
        observation
      });
      const redis = resolveRedisEvalClient(context);
      const key = dnsHistoryKey(prefix, parsedInput.normalized_host);
      const result = await redis.eval(DNS_REBINDING_APPEND_SCRIPT, [key], [
        JSON.stringify(parsedInput.observation),
        dnsHistoryTtlSeconds,
        dnsHistoryMaxEntries
      ]);

      return {
        observation: parsedInput.observation,
        history_size: parseHistorySize(result)
      };
    },
    readDnsRebindingObservationHistory: async ({normalized_host, context}) => {
      const parsedInput = ReadDnsRebindingObservationHistoryInputSchema.parse({normalized_host});
      const redis = resolveRedisClient(context);
      const key = dnsHistoryKey(prefix, parsedInput.normalized_host);
      const payload = await redis.get(key);
      if (!payload) {
        return [];
      }

      const parsed = parseDnsRebindingHistory(payload);
      if (!parsed) {
        await redis.del(key);
        return [];
      }

      return parsed;
    },
    publishTemplateInvalidationSignal: async ({signal, context}) => {
      const parsedInput = PublishTemplateInvalidationSignalInputSchema.parse({signal});
      const redis = resolveRedisPubSubClient(context);
      await redis.publish(invalidationChannel, JSON.stringify(parsedInput.signal));
    },
    subscribeTemplateInvalidationSignal: ({onSignal, context}) => {
      SubscribeTemplateInvalidationSignalInputSchema.parse({onSignal});
      const redis = resolveRedisPubSubClient(context);
      let closed = false;
      let subscribed = false;

      const handler = (message: string) => {
        const signal = decodeInvalidationSignal(message);
        if (!signal) {
          return;
        }

        onSignal(signal);
      };

      const detach = () => {
        if (typeof redis.unsubscribe === 'function') {
          void redis.unsubscribe(invalidationChannel, handler);
        }
      };

      const subscribeResult = redis.subscribe(invalidationChannel, handler);
      if (subscribeResult instanceof Promise) {
        void subscribeResult.then(() => {
          subscribed = true;
          if (closed) {
            detach();
          }
        });
        void subscribeResult.catch(() => {
          if (!closed) {
            detach();
          }
        });
      } else {
        subscribed = true;
      }

      return () => {
        closed = true;
        if (subscribed) {
          detach();
        }
      };
    }
  };
};
