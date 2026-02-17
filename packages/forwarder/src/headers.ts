import {OpenApiHeaderListSchema, type OpenApiHeaderList} from '@broker-interceptor/schemas';

import {err, ok, type ForwarderResult} from './errors';

const HTTP_HEADER_NAME_REGEX = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const CONNECTION_TOKEN_SPLIT_REGEX = /\s*,\s*/u;

export const HOP_BY_HOP_HEADER_NAMES = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

export const normalizeHeaderName = (name: string): ForwarderResult<string> => {
  const normalizedName = name.trim().toLowerCase();
  if (!HTTP_HEADER_NAME_REGEX.test(normalizedName)) {
    return err('invalid_header_name', `Invalid header name: ${name}`);
  }

  return ok(normalizedName);
};

export const validateHeaderValue = (value: string): ForwarderResult<string> => {
  if (/[\r\n]/u.test(value)) {
    return err('invalid_header_value', 'Header values must not contain CR or LF');
  }

  return ok(value.trim());
};

const parseConnectionHeaderTokens = (connectionHeaderValue: string): ForwarderResult<Set<string>> => {
  const tokenSet = new Set<string>();
  const tokens = connectionHeaderValue.split(CONNECTION_TOKEN_SPLIT_REGEX);

  for (const rawToken of tokens) {
    const token = rawToken.trim().toLowerCase();
    if (token.length === 0) {
      continue;
    }

    if (!HTTP_HEADER_NAME_REGEX.test(token)) {
      return err(
        'invalid_connection_header',
        `Connection header contains an invalid token: ${rawToken}`
      );
    }

    tokenSet.add(token);
  }

  return ok(tokenSet);
};

export const stripHopByHopHeaders = (rawHeaders: unknown): ForwarderResult<OpenApiHeaderList> => {
  const parsedHeaders = OpenApiHeaderListSchema.safeParse(rawHeaders);
  if (!parsedHeaders.success) {
    return err('invalid_input', parsedHeaders.error.message);
  }

  const normalizedHeaders: OpenApiHeaderList = [];
  const connectionNominatedHeaders = new Set<string>();

  for (const header of parsedHeaders.data) {
    const normalizedName = normalizeHeaderName(header.name);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    const normalizedValue = validateHeaderValue(header.value);
    if (!normalizedValue.ok) {
      return normalizedValue;
    }

    if (normalizedName.value === 'connection') {
      const parsedConnectionTokens = parseConnectionHeaderTokens(normalizedValue.value);
      if (!parsedConnectionTokens.ok) {
        return parsedConnectionTokens;
      }

      for (const token of parsedConnectionTokens.value) {
        connectionNominatedHeaders.add(token);
      }
    }

    normalizedHeaders.push({
      name: normalizedName.value,
      value: normalizedValue.value
    });
  }

  const headersToStrip = new Set<string>([
    ...HOP_BY_HOP_HEADER_NAMES,
    ...connectionNominatedHeaders
  ]);

  return ok(normalizedHeaders.filter(header => !headersToStrip.has(header.name)));
};
