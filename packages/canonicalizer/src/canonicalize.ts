import crypto from 'node:crypto';

import type {
  BodyDigestMode,
  CanonicalRequestDescriptorContract,
  CanonicalizationContext,
  CanonicalizeExecuteRequestInput,
  HttpMethodContract,
  OpenApiExecuteRequestContract,
  TemplatePathGroupContract
} from './contracts';
import {
  CanonicalRequestDescriptorSchema,
  CanonicalizeExecuteRequestInputSchema
} from './contracts';
import {err, ok, type CanonicalizerResult} from './errors';
import {
  compileCanonicalizerTemplate,
  normalizeTemplateHost,
  selectMatchingPathGroup,
  type CompiledPathGroup,
  type CompiledTemplate
} from './template';

const UNRESERVED_CHARS_REGEX = /^[A-Za-z0-9\-._~]$/;
const HTTP_HEADER_NAME_REGEX = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const QUERY_PAIR_DELIMITER = '&';

type QueryPair = {
  key: string;
  value: string;
  hasEquals: boolean;
  index: number;
};

type NormalizedQuery = {
  canonicalQuery: string;
  queryKeys: string[];
  queryFingerprintBase64: string | null;
};

export type CanonicalizeExecuteRequestOutput = {
  descriptor: CanonicalRequestDescriptorContract;
  matched_path_group_id: string;
  matched_path_group: Pick<
    TemplatePathGroupContract,
    'group_id' | 'risk_tier' | 'approval_mode' | 'body_policy'
  >;
  canonical_url: string;
};

const compareStrings = (left: string, right: string) => {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
};

const sha256Base64 = (value: string | Buffer) => crypto.createHash('sha256').update(value).digest('base64');

const normalizePercentEncodedComponent = (value: string): CanonicalizerResult<string> => {
  let normalized = '';

  for (let index = 0; index < value.length; index += 1) {
    const char = value.charAt(index);
    if (char !== '%') {
      normalized += char;
      continue;
    }

    if (index + 2 >= value.length) {
      return err('request_percent_encoding_invalid', `Invalid percent-encoding in "${value}"`);
    }

    const hex = value.slice(index + 1, index + 3);
    if (!/^[0-9A-Fa-f]{2}$/.test(hex)) {
      return err('request_percent_encoding_invalid', `Invalid percent-encoding in "${value}"`);
    }

    const decoded = String.fromCharCode(Number.parseInt(hex, 16));
    if (UNRESERVED_CHARS_REGEX.test(decoded)) {
      normalized += decoded;
    } else {
      normalized += `%${hex.toUpperCase()}`;
    }
    index += 2;
  }

  return ok(normalized);
};

const removeDotSegments = (path: string) => {
  let input = path;
  let output = '';

  while (input.length > 0) {
    if (input.startsWith('../')) {
      input = input.slice(3);
      continue;
    }
    if (input.startsWith('./')) {
      input = input.slice(2);
      continue;
    }
    if (input.startsWith('/./')) {
      input = `/${input.slice(3)}`;
      continue;
    }
    if (input === '/.') {
      input = '/';
      continue;
    }
    if (input.startsWith('/../')) {
      input = `/${input.slice(4)}`;
      output = output.replace(/\/?[^/]*$/, '');
      continue;
    }
    if (input === '/..') {
      input = '/';
      output = output.replace(/\/?[^/]*$/, '');
      continue;
    }
    if (input === '.' || input === '..') {
      input = '';
      continue;
    }

    const nextSlash =
      input.startsWith('/') ? input.indexOf('/', 1) : input.indexOf('/');
    if (nextSlash === -1) {
      output += input;
      input = '';
      continue;
    }

    output += input.slice(0, nextSlash);
    input = input.slice(nextSlash);
  }

  if (output.length === 0) {
    return '/';
  }

  return output;
};

const normalizePath = (path: string): CanonicalizerResult<string> => {
  const normalizedPercent = normalizePercentEncodedComponent(path);
  if (!normalizedPercent.ok) {
    return normalizedPercent;
  }

  const normalizedPath = removeDotSegments(normalizedPercent.value);
  if (!normalizedPath.startsWith('/')) {
    return ok(`/${normalizedPath}`);
  }

  return ok(normalizedPath);
};

const normalizeQuery = ({
  rawQuery,
  pathGroup
}: {
  rawQuery: string;
  pathGroup: CompiledPathGroup;
}): CanonicalizerResult<NormalizedQuery> => {
  if (rawQuery.length === 0) {
    return ok({
      canonicalQuery: '',
      queryKeys: [],
      queryFingerprintBase64: null
    });
  }

  const pairs: QueryPair[] = [];
  const seenCounts = new Map<string, number>();
  const segments = rawQuery.split(QUERY_PAIR_DELIMITER);

  for (const [index, segment] of segments.entries()) {
    if (segment.length === 0) {
      continue;
    }

    const equalsIndex = segment.indexOf('=');
    const hasEquals = equalsIndex >= 0;
    const rawKey = hasEquals ? segment.slice(0, equalsIndex) : segment;
    const rawValue = hasEquals ? segment.slice(equalsIndex + 1) : '';

    const key = normalizePercentEncodedComponent(rawKey);
    if (!key.ok) {
      return key;
    }
    const value = normalizePercentEncodedComponent(rawValue);
    if (!value.ok) {
      return value;
    }

    if (key.value.length === 0) {
      return err('request_query_key_not_allowlisted', 'Empty query key is not allowed');
    }

    if (!pathGroup.queryAllowlist.has(key.value)) {
      return err('request_query_key_not_allowlisted', `Query key is not allowlisted: ${key.value}`);
    }

    const nextCount = (seenCounts.get(key.value) ?? 0) + 1;
    seenCounts.set(key.value, nextCount);
    if (nextCount > 1) {
      const duplicateAllowed =
        pathGroup.duplicateQueryPolicy.mode === 'all' ||
        (pathGroup.duplicateQueryPolicy.mode === 'allowlist' &&
          pathGroup.duplicateQueryPolicy.keys.has(key.value));
      if (!duplicateAllowed) {
        return err(
          'request_query_duplicate_key_forbidden',
          `Duplicate query key is forbidden unless explicitly allowed: ${key.value}`
        );
      }
    }

    pairs.push({
      key: key.value,
      value: value.value,
      hasEquals,
      index
    });
  }

  const sortedPairs = [...pairs].sort((left, right) => {
    const keyCompare = compareStrings(left.key, right.key);
    if (keyCompare !== 0) {
      return keyCompare;
    }
    return left.index - right.index;
  });

  const canonicalQuery = sortedPairs
    .map(pair => (pair.hasEquals || pair.value.length > 0 ? `${pair.key}=${pair.value}` : pair.key))
    .join('&');
  const queryKeys = [...new Set(sortedPairs.map(pair => pair.key))].sort(compareStrings);

  return ok({
    canonicalQuery,
    queryKeys,
    queryFingerprintBase64: canonicalQuery.length > 0 ? sha256Base64(canonicalQuery) : null
  });
};

const normalizeHeaders = ({
  headers,
  pathGroup
}: {
  headers: OpenApiExecuteRequestContract['request']['headers'];
  pathGroup: CompiledPathGroup;
}): CanonicalizerResult<CanonicalRequestDescriptorContract['normalized_headers']> => {
  const normalizedHeaders: Array<{name: string; value: string; index: number}> = [];

  for (const [index, header] of headers.entries()) {
    const normalizedName = header.name.trim().toLowerCase();
    if (!HTTP_HEADER_NAME_REGEX.test(normalizedName)) {
      return err('request_header_name_invalid', `Invalid header name: ${header.name}`);
    }

    if (!pathGroup.headerAllowlist.has(normalizedName)) {
      continue;
    }

    if (/[\r\n]/.test(header.value)) {
      return err('request_header_value_invalid', `Invalid header value for ${header.name}`);
    }

    normalizedHeaders.push({
      name: normalizedName,
      value: header.value.trim(),
      index
    });
  }

  return ok(
    normalizedHeaders
      .sort((left, right) => {
        const nameCompare = compareStrings(left.name, right.name);
        if (nameCompare !== 0) {
          return nameCompare;
        }

        const valueCompare = compareStrings(left.value, right.value);
        if (valueCompare !== 0) {
          return valueCompare;
        }

        return left.index - right.index;
      })
      .map(item => ({name: item.name, value: item.value}))
  );
};

const parseBodyBase64 = (bodyBase64: string): CanonicalizerResult<Buffer> => {
  const normalized = bodyBase64.trim();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 !== 0) {
    return err('request_body_base64_invalid', 'body_base64 is not valid base64');
  }

  const decoded = Buffer.from(normalized, 'base64');
  if (decoded.toString('base64') !== normalized) {
    return err('request_body_base64_invalid', 'body_base64 is not valid base64');
  }

  return ok(decoded);
};

const decodeBodyBase64IfPresent = (bodyBase64: string | undefined): CanonicalizerResult<Buffer | null> => {
  if (!bodyBase64) {
    return ok(null);
  }

  const decoded = parseBodyBase64(bodyBase64);
  if (!decoded.ok) {
    return decoded;
  }

  return ok(decoded.value);
};

const normalizeContentTypeValue = (value: string): string => {
  const [mediaType] = value.split(';', 1);
  return mediaType?.trim().toLowerCase() ?? '';
};

const enforceBodyPolicy = ({
  request,
  pathGroup,
  bodyBuffer
}: {
  request: OpenApiExecuteRequestContract;
  pathGroup: CompiledPathGroup;
  bodyBuffer: Buffer | null;
}): CanonicalizerResult<void> => {
  const maxBytes = pathGroup.group.body_policy.max_bytes;
  const bodyBytes = bodyBuffer?.byteLength ?? 0;
  if (bodyBytes > maxBytes) {
    return err('request_body_too_large', `Request body exceeds max_bytes=${maxBytes} for group ${pathGroup.group.group_id}`);
  }

  if (bodyBytes === 0) {
    return ok(undefined);
  }

  const allowedContentTypes = new Set(
    pathGroup.group.body_policy.content_types.map(contentType => contentType.trim().toLowerCase())
  );
  if (allowedContentTypes.size === 0) {
    return err(
      'request_content_type_not_allowed',
      `Request body is not allowed for group ${pathGroup.group.group_id}`
    );
  }

  const contentTypeHeader = request.request.headers.find(
    header => header.name.trim().toLowerCase() === 'content-type'
  );
  if (!contentTypeHeader || contentTypeHeader.value.trim().length === 0) {
    return err('request_content_type_missing', 'Request body requires a content-type header');
  }

  const mediaType = normalizeContentTypeValue(contentTypeHeader.value);
  if (!mediaType || !allowedContentTypes.has(mediaType)) {
    return err('request_content_type_not_allowed', `Content-Type is not allowed: ${mediaType || '<empty>'}`);
  }

  return ok(undefined);
};

const computeBodyDigest = ({
  mode,
  riskTier,
  bodyBuffer
}: {
  mode: BodyDigestMode;
  riskTier: CompiledPathGroup['group']['risk_tier'];
  bodyBuffer: Buffer | null;
}): string | null => {
  if (!bodyBuffer) {
    return null;
  }

  if (mode === 'never') {
    return null;
  }

  if (mode === 'high_risk_only' && riskTier !== 'high') {
    return null;
  }

  return sha256Base64(bodyBuffer);
};

const normalizeRequestHost = (hostname: string): CanonicalizerResult<string> => {
  const normalizedHost = normalizeTemplateHost(hostname);
  if (!normalizedHost) {
    return err('request_url_invalid', `Invalid request host: ${hostname}`);
  }

  return ok(normalizedHost);
};

const canonicalizeRequestUrl = ({
  rawUrl,
  compiledTemplate,
  method
}: {
  rawUrl: string;
  compiledTemplate: CompiledTemplate;
  method: HttpMethodContract;
}): CanonicalizerResult<{
  scheme: string;
  host: string;
  port: number;
  normalizedPath: string;
  matchedPathGroup: CompiledPathGroup;
  rawQuery: string;
}> => {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return err('request_url_invalid', `Invalid request URL: ${rawUrl}`);
  }

  if (parsedUrl.username.length > 0 || parsedUrl.password.length > 0) {
    return err('request_url_userinfo_forbidden', 'Request URL userinfo is forbidden');
  }

  if (parsedUrl.hash.length > 0) {
    return err('request_url_fragment_forbidden', 'Request URL fragment is forbidden');
  }

  const scheme = parsedUrl.protocol.slice(0, -1).toLowerCase();
  if (!compiledTemplate.allowedSchemes.has(scheme)) {
    return err('request_scheme_not_allowed', `Request scheme is not allowed: ${scheme}`);
  }

  const host = normalizeRequestHost(parsedUrl.hostname);
  if (!host.ok) {
    return host;
  }
  if (!compiledTemplate.allowedHosts.has(host.value)) {
    return err('request_host_not_allowed', `Request host is not allowed: ${host.value}`);
  }

  const effectivePort = parsedUrl.port.length > 0 ? Number.parseInt(parsedUrl.port, 10) : 443;
  if (!compiledTemplate.allowedPorts.has(effectivePort)) {
    return err('request_port_not_allowed', `Request port is not allowed: ${effectivePort}`);
  }

  const normalizedPath = normalizePath(parsedUrl.pathname);
  if (!normalizedPath.ok) {
    return normalizedPath;
  }

  const matchedPathGroup = selectMatchingPathGroup({
    compiledTemplate,
    method,
    normalizedPath: normalizedPath.value
  });
  if (!matchedPathGroup) {
    return err('no_matching_group', 'No matching template path group for method and path');
  }

  return ok({
    scheme,
    host: host.value,
    port: effectivePort,
    normalizedPath: normalizedPath.value,
    matchedPathGroup,
    rawQuery: parsedUrl.search.startsWith('?') ? parsedUrl.search.slice(1) : parsedUrl.search
  });
};

const normalizeInput = (
  input: unknown
): CanonicalizerResult<{
  context: CanonicalizationContext;
  parsedInput: CanonicalizeExecuteRequestInput;
  mode: BodyDigestMode;
}> => {
  const parsed = CanonicalizeExecuteRequestInputSchema.safeParse(input);
  if (!parsed.success) {
    return err('invalid_input', parsed.error.message);
  }

  if (parsed.data.context.integration_id !== parsed.data.execute_request.integration_id) {
    return err(
      'request_integration_mismatch',
      'context.integration_id must match execute_request.integration_id'
    );
  }

  const mode: BodyDigestMode = parsed.data.body_digest_mode ?? 'high_risk_only';
  return ok({
    context: parsed.data.context,
    parsedInput: parsed.data,
    mode
  });
};

export const canonicalizeExecuteRequest = (input: unknown): CanonicalizerResult<CanonicalizeExecuteRequestOutput> => {
  const normalizedInput = normalizeInput(input);
  if (!normalizedInput.ok) {
    return normalizedInput;
  }

  const compiledTemplate = compileCanonicalizerTemplate(normalizedInput.value.parsedInput.template);
  if (!compiledTemplate.ok) {
    return compiledTemplate;
  }

  const request = normalizedInput.value.parsedInput.execute_request;
  const canonicalizedUrl = canonicalizeRequestUrl({
    rawUrl: request.request.url,
    compiledTemplate: compiledTemplate.value,
    method: request.request.method
  });
  if (!canonicalizedUrl.ok) {
    return canonicalizedUrl;
  }

  const normalizedQuery = normalizeQuery({
    rawQuery: canonicalizedUrl.value.rawQuery,
    pathGroup: canonicalizedUrl.value.matchedPathGroup
  });
  if (!normalizedQuery.ok) {
    return normalizedQuery;
  }

  const decodedBody = decodeBodyBase64IfPresent(request.request.body_base64);
  if (!decodedBody.ok) {
    return decodedBody;
  }

  const bodyPolicyCheck = enforceBodyPolicy({
    request,
    pathGroup: canonicalizedUrl.value.matchedPathGroup,
    bodyBuffer: decodedBody.value
  });
  if (!bodyPolicyCheck.ok) {
    return bodyPolicyCheck;
  }

  const normalizedHeaders = normalizeHeaders({
    headers: request.request.headers,
    pathGroup: canonicalizedUrl.value.matchedPathGroup
  });
  if (!normalizedHeaders.ok) {
    return normalizedHeaders;
  }

  const bodySha256 = computeBodyDigest({
    mode: normalizedInput.value.mode,
    riskTier: canonicalizedUrl.value.matchedPathGroup.group.risk_tier,
    bodyBuffer: decodedBody.value
  });

  const isDefaultPort = canonicalizedUrl.value.scheme === 'https' && canonicalizedUrl.value.port === 443;
  const canonicalUrl =
    `${canonicalizedUrl.value.scheme}://${canonicalizedUrl.value.host}` +
    `${isDefaultPort ? '' : `:${canonicalizedUrl.value.port}`}` +
    `${canonicalizedUrl.value.normalizedPath}` +
    `${normalizedQuery.value.canonicalQuery.length > 0 ? `?${normalizedQuery.value.canonicalQuery}` : ''}`;

  const descriptorCandidate: CanonicalRequestDescriptorContract = {
    tenant_id: normalizedInput.value.context.tenant_id,
    workload_id: normalizedInput.value.context.workload_id,
    integration_id: normalizedInput.value.context.integration_id,
    template_id: compiledTemplate.value.template.template_id,
    template_version: compiledTemplate.value.template.version,
    method: request.request.method,
    canonical_url: canonicalUrl,
    matched_path_group_id: canonicalizedUrl.value.matchedPathGroup.group.group_id,
    normalized_headers: normalizedHeaders.value,
    query_keys: normalizedQuery.value.queryKeys,
    query_fingerprint_base64: normalizedQuery.value.queryFingerprintBase64,
    body_sha256_base64: bodySha256
  };

  const descriptor = CanonicalRequestDescriptorSchema.safeParse(descriptorCandidate);
  /* c8 ignore next 3 -- defensive guard: descriptorCandidate is derived from schema-validated inputs. */
  if (!descriptor.success) {
    return err('internal_descriptor_invalid', descriptor.error.message);
  }

  return ok({
    descriptor: descriptor.data,
    matched_path_group_id: canonicalizedUrl.value.matchedPathGroup.group.group_id,
    matched_path_group: {
      group_id: canonicalizedUrl.value.matchedPathGroup.group.group_id,
      risk_tier: canonicalizedUrl.value.matchedPathGroup.group.risk_tier,
      approval_mode: canonicalizedUrl.value.matchedPathGroup.group.approval_mode,
      body_policy: canonicalizedUrl.value.matchedPathGroup.group.body_policy
    },
    canonical_url: canonicalUrl
  });
};
