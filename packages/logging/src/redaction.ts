const DEFAULT_SENSITIVE_SUBSTRINGS = [
  'token',
  'secret',
  'authorization',
  'cookie',
  'dpop',
  'privatekey',
  'private_key',
  'ciphertext',
  'auth_tag',
  'body',
  'body_base64'
] as const;

const REDACTED_VALUE = '[REDACTED]';
const MAX_RECURSION_DEPTH = 12;

const normalizeKey = (value: string) => value.trim().toLowerCase().replace(/[^a-z0-9_]/gu, '');

const isSensitiveKey = ({
  key,
  extraSensitiveKeys
}: {
  key: string;
  extraSensitiveKeys: Set<string>;
}) => {
  const normalized = normalizeKey(key);
  if (extraSensitiveKeys.has(normalized)) {
    return true;
  }

  return DEFAULT_SENSITIVE_SUBSTRINGS.some(entry => normalized.includes(entry));
};

const sanitizeErrorForLog = (error: Error) => ({
  name: error.name,
  message: error.message,
  ...(error.stack ? {stack: error.stack} : {})
});

const sanitizeInternal = ({
  value,
  depth,
  seen,
  extraSensitiveKeys
}: {
  value: unknown;
  depth: number;
  seen: WeakSet<object>;
  extraSensitiveKeys: Set<string>;
}): unknown => {
  if (depth > MAX_RECURSION_DEPTH) {
    return '[TRUNCATED]';
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean' ||
    typeof value === 'bigint'
  ) {
    return value;
  }

  if (typeof value === 'symbol') {
    return value.toString();
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (value instanceof Error) {
    return sanitizeErrorForLog(value);
  }

  if (Array.isArray(value)) {
    return value.map(item =>
      sanitizeInternal({
        value: item,
        depth: depth + 1,
        seen,
        extraSensitiveKeys
      })
    );
  }

  if (typeof value === 'object') {
    if (seen.has(value)) {
      return '[CIRCULAR]';
    }

    seen.add(value);

    const entries = Object.entries(value as Record<string, unknown>);
    const nextEntries = entries.map(([key, entryValue]) => {
      if (isSensitiveKey({key, extraSensitiveKeys})) {
        return [key, REDACTED_VALUE] as const;
      }

      return [
        key,
        sanitizeInternal({
          value: entryValue,
          depth: depth + 1,
          seen,
          extraSensitiveKeys
        })
      ] as const;
    });

    return Object.fromEntries(nextEntries);
  }

  if (typeof value === 'function') {
    return '[FUNCTION]';
  }

  return Object.prototype.toString.call(value);
};

export const sanitizeForLog = ({
  value,
  extraSensitiveKeys = []
}: {
  value: unknown;
  extraSensitiveKeys?: string[];
}): unknown => {
  const normalizedExtraKeys = new Set(extraSensitiveKeys.map(item => normalizeKey(item)).filter(item => item.length > 0));

  return sanitizeInternal({
    value,
    depth: 0,
    seen: new WeakSet<object>(),
    extraSensitiveKeys: normalizedExtraKeys
  });
};
