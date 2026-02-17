import {createHash, randomUUID} from 'node:crypto';
import {isIP} from 'node:net';
import {z} from 'zod';

import {DbRepositoryError} from './errors.js';
import type {DatabaseClient, RepositoryOperationContext} from './types.js';

export const createDomainId = (prefix: string): string => `${prefix}${randomUUID().replace(/-/gu, '')}`;

export const toIsoString = (date: Date): string => date.toISOString();

const trimString = (value: string): string => value.trim();

export const TrimmedStringSchema = z.string().transform(trimString);
export type TrimmedString = z.infer<typeof TrimmedStringSchema>;

export const NonEmptyTrimmedStringSchema = TrimmedStringSchema.pipe(z.string().min(1));
export type NonEmptyTrimmedString = z.infer<typeof NonEmptyTrimmedStringSchema>;

export const assertNonEmptyString = (value: string, fieldName: string): string => {
  const parsed = NonEmptyTrimmedStringSchema.safeParse(value);
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', `${fieldName} cannot be empty`);
  }

  return parsed.data;
};

export const NormalizedUniqueStringListSchema = z.array(z.string()).transform((values, context) => {
  const normalizedSet = new Set<string>();

  for (const value of values) {
    const normalized = trimString(value);
    if (normalized.length === 0) {
      context.addIssue({
        code: 'custom',
        message: 'List values cannot be empty'
      });
      return z.NEVER;
    }

    if (normalizedSet.has(normalized)) {
      context.addIssue({
        code: 'custom',
        message: `Duplicate value "${normalized}" is not allowed`
      });
      return z.NEVER;
    }

    normalizedSet.add(normalized);
  }

  return [...normalizedSet].sort();
});
export type NormalizedUniqueStringList = z.infer<typeof NormalizedUniqueStringListSchema>;

export const normalizeUniqueStringList = (values: string[]): string[] => {
  const parsed = NormalizedUniqueStringListSchema.safeParse(values);
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', parsed.error.issues[0]?.message ?? 'Invalid string list');
  }

  return parsed.data;
};

const isValidIpOrCidr = (value: string): boolean => {
  const directIpVersion = isIP(value);
  if (directIpVersion !== 0) {
    return true;
  }

  const [ip, prefix] = value.split('/');
  if (!ip || !prefix || value.split('/').length !== 2) {
    return false;
  }

  const ipVersion = isIP(ip);
  if (ipVersion === 0 || !/^\d+$/u.test(prefix)) {
    return false;
  }

  const prefixValue = Number.parseInt(prefix, 10);
  const maxPrefix = ipVersion === 4 ? 32 : 128;
  return prefixValue >= 0 && prefixValue <= maxPrefix;
};

export const normalizeIpAllowlist = (values: string[]): string[] => {
  const parsed = NormalizedIpAllowlistSchema.safeParse(values);
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', parsed.error.issues[0]?.message ?? 'Invalid IP allowlist');
  }

  return parsed.data;
};

export const NormalizedIpAllowlistSchema = NormalizedUniqueStringListSchema.superRefine((values, context) => {
  for (const value of values) {
    if (!isValidIpOrCidr(value)) {
      context.addIssue({
        code: 'custom',
        message: `Invalid IP/CIDR entry: ${value}`
      });
      return;
    }
  }
});
export type NormalizedIpAllowlist = z.infer<typeof NormalizedIpAllowlistSchema>;

const HttpMethodEnumSchema = z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
export type NormalizedHttpMethod = z.infer<typeof HttpMethodEnumSchema>;

export const NormalizedHttpMethodSchema = z
  .string()
  .transform(value => trimString(value).toUpperCase())
  .pipe(HttpMethodEnumSchema);

export const normalizeMethod = (rawMethod: string): NormalizedHttpMethod => {
  const parsed = NormalizedHttpMethodSchema.safeParse(rawMethod);
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', `Invalid HTTP method: ${rawMethod}`);
  }

  return parsed.data;
};

export const NormalizedHostSchema = z
  .string()
  .transform(trimString)
  .superRefine((host, context) => {
    if (host.length === 0) {
      context.addIssue({
        code: 'custom',
        message: 'Policy host cannot be empty'
      });
      return;
    }

    if (
      host.includes('*') ||
      host.includes('://') ||
      host.includes('/') ||
      host.includes('?') ||
      host.includes('#') ||
      host.includes('@')
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Policy host must be an exact bare host without wildcard, scheme, path, query, fragment, or userinfo'
      });
      return;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(`https://${host}`);
    } catch {
      context.addIssue({
        code: 'custom',
        message: `Invalid policy host: ${host}`
      });
      return;
    }

    if (parsedUrl.pathname !== '/' || parsedUrl.port.length > 0 || parsedUrl.username || parsedUrl.password) {
      context.addIssue({
        code: 'custom',
        message: `Invalid policy host: ${host}`
      });
      return;
    }

    const normalizedHost = parsedUrl.hostname.toLowerCase();
    if (normalizedHost.length === 0 || normalizedHost.endsWith('.')) {
      context.addIssue({
        code: 'custom',
        message: `Invalid policy host: ${host}`
      });
    }
  })
  .transform(host => new URL(`https://${host}`).hostname.toLowerCase());
export type NormalizedHost = z.infer<typeof NormalizedHostSchema>;

export const normalizeHost = (rawHost: string): string => {
  const parsed = NormalizedHostSchema.safeParse(rawHost);
  if (!parsed.success) {
    throw new DbRepositoryError(
      'validation_error',
      parsed.error.issues[0]?.message ?? `Invalid policy host: ${rawHost}`
    );
  }

  return parsed.data;
};

export const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

export const descriptorHash = (descriptor: unknown): string => sha256Hex(JSON.stringify(descriptor));

export const Base64PayloadSchema = z
  .string()
  .transform(trimString)
  .superRefine((normalized, context) => {
    if (normalized.length === 0 || normalized.length % 4 !== 0) {
      context.addIssue({
        code: 'custom',
        message: 'Invalid base64 payload'
      });
      return;
    }

    if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(normalized)) {
      context.addIssue({
        code: 'custom',
        message: 'Invalid base64 payload'
      });
      return;
    }

    const decoded = Buffer.from(normalized, 'base64');
    if (decoded.toString('base64') !== normalized) {
      context.addIssue({
        code: 'custom',
        message: 'Invalid base64 payload'
      });
    }
  });
export type Base64Payload = z.infer<typeof Base64PayloadSchema>;

export const decodeBase64ByteLength = (value: string): number => {
  const parsed = Base64PayloadSchema.safeParse(value);
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', 'Invalid base64 payload');
  }

  const decoded = Buffer.from(parsed.data, 'base64');
  return decoded.byteLength;
};

export const ensureEnvelopeBounds = ({
  wrapped_data_key_b64,
  aad_b64,
  ciphertext_b64
}: {
  wrapped_data_key_b64: string;
  aad_b64?: string;
  ciphertext_b64: string;
}) => {
  const wrappedDataKeyLength = decodeBase64ByteLength(wrapped_data_key_b64);
  if (wrappedDataKeyLength < 1 || wrappedDataKeyLength > 16_384) {
    throw new DbRepositoryError('validation_error', 'wrapped_data_key_b64 exceeds allowed bounds');
  }

  if (aad_b64) {
    const aadLength = decodeBase64ByteLength(aad_b64);
    if (aadLength < 1 || aadLength > 16_384) {
      throw new DbRepositoryError('validation_error', 'aad_b64 exceeds allowed bounds');
    }
  }

  const ciphertextLength = decodeBase64ByteLength(ciphertext_b64);
  if (ciphertextLength < 1 || ciphertextLength > 1_048_576) {
    throw new DbRepositoryError('validation_error', 'ciphertext_b64 exceeds allowed bounds');
  }
};

export const encodeCursor = (value: string): string => Buffer.from(value, 'utf8').toString('base64url');

export const decodeCursor = (value: string): string => {
  try {
    return Buffer.from(value, 'base64url').toString('utf8');
  } catch {
    throw new DbRepositoryError('validation_error', 'Invalid cursor token');
  }
};

export const CursorPairSchema = z
  .object({
    timestamp: z.iso.datetime({offset: true}),
    event_id: NonEmptyTrimmedStringSchema,
    tenant_id: NonEmptyTrimmedStringSchema
  })
  .strict();
export type CursorPair = z.infer<typeof CursorPairSchema>;

export const parseCursorPair = (cursor: string): CursorPair => {
  const decoded = decodeCursor(cursor);
  const parts = decoded.split('|');

  if (parts.length !== 3) {
    throw new DbRepositoryError('validation_error', 'Invalid cursor payload');
  }

  const [timestamp, event_id, tenant_id] = parts;

  const parsed = CursorPairSchema.safeParse({
    timestamp,
    event_id,
    tenant_id
  });
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', 'Invalid cursor payload');
  }

  return parsed.data;
};

type DatabaseClientModelKey = Exclude<keyof DatabaseClient, '$transaction'>;

type DatabaseClientMethodRequirement = {
  model: DatabaseClientModelKey;
  method: string;
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null;

const firstMissingRequirement = (
  candidate: Record<string, unknown>,
  requirements: DatabaseClientMethodRequirement[]
): DatabaseClientMethodRequirement | null => {
  for (const requirement of requirements) {
    const model = candidate[requirement.model];
    if (!isRecord(model) || typeof model[requirement.method] !== 'function') {
      return requirement;
    }
  }

  return null;
};

export const resolveRepositoryDbClient = (
  defaultClient: DatabaseClient,
  context: RepositoryOperationContext | undefined,
  requirements: DatabaseClientMethodRequirement[]
): DatabaseClient => {
  const transactionClient = context?.transaction_client;
  if (transactionClient === undefined) {
    return defaultClient;
  }

  if (!isRecord(transactionClient)) {
    throw new DbRepositoryError('validation_error', 'transaction_client must be an object when provided');
  }

  const missingRequirement = firstMissingRequirement(transactionClient, requirements);
  if (missingRequirement) {
    throw new DbRepositoryError(
      'validation_error',
      `transaction_client is missing required method ${missingRequirement.model}.${missingRequirement.method}`
    );
  }

  return transactionClient as DatabaseClient;
};
