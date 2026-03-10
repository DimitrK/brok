import {createHash, createHmac} from 'node:crypto';

import {type OpenApiExecuteRequest, type OpenApiHeaderList, type OpenApiTemplate, type SecretMaterial, type UpstreamAuthStrategy} from '@broker-interceptor/schemas';

import {defineRuntimeAuthStrategy} from '../strategyModule';
import {resolvePathGroup} from '../utils';

type AwsSigV4SecretMaterial = Extract<SecretMaterial, {type: 'aws_sigv4'}>;
type AwsSigV4Strategy = Extract<UpstreamAuthStrategy, {type: 'aws_sigv4'}>;

const EMPTY_BODY_SHA256 = createHash('sha256').update('').digest('hex');

const encodeRfc3986 = (value: string) =>
  encodeURIComponent(value).replace(/[!'()*]/gu, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);

const normalizeHeaderValueForSigning = (value: string) => value.trim().replace(/\s+/gu, ' ');

const toSigningDate = (now: Date) => {
  const isoTimestamp = now.toISOString().replace(/\.\d{3}Z$/u, 'Z');
  return {
    amzDate: isoTimestamp.replace(/[-:]/gu, '').replace(/Z$/u, 'Z'),
    shortDate: isoTimestamp.slice(0, 10).replace(/-/gu, '')
  };
};

const buildCanonicalQueryString = (url: URL) => {
  const pairs = [...url.searchParams.entries()].map(
    ([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)] as const
  );
  pairs.sort(([leftKey, leftValue], [rightKey, rightValue]) => {
    if (leftKey === rightKey) {
      return leftValue.localeCompare(rightValue);
    }
    return leftKey.localeCompare(rightKey);
  });
  return pairs.map(([key, value]) => `${key}=${value}`).join('&');
};

const buildCanonicalUri = (url: URL) => {
  const pathname = url.pathname.length > 0 ? url.pathname : '/';
  return pathname
    .split('/')
    .map(segment => encodeRfc3986(decodeURIComponent(segment)))
    .join('/');
};

const sha256Hex = (value: Buffer | string) => createHash('sha256').update(value).digest('hex');

const hmac = (key: Buffer | string, value: string) => createHmac('sha256', key).update(value).digest();

const deriveSigningKey = ({
  secretAccessKey,
  shortDate,
  region,
  service
}: {
  secretAccessKey: string;
  shortDate: string;
  region: string;
  service: string;
}) => {
  const kDate = hmac(`AWS4${secretAccessKey}`, shortDate);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
};

const deriveS3RegionFromHostname = (hostname: string): string | null => {
  const normalized = hostname.trim().toLowerCase();
  const directPatterns = [
    /^s3[.-]([a-z0-9-]+)\.amazonaws\.com$/u,
    /^[^.]+\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$/u,
    /^s3\.dualstack\.([a-z0-9-]+)\.amazonaws\.com$/u,
    /^[^.]+\.s3\.dualstack\.([a-z0-9-]+)\.amazonaws\.com$/u
  ];

  for (const pattern of directPatterns) {
    const match = normalized.match(pattern);
    if (match?.[1]) {
      return match[1];
    }
  }

  if (normalized === 's3.amazonaws.com' || normalized.endsWith('.s3.amazonaws.com')) {
    return 'us-east-1';
  }

  return null;
};

const decodeRequestBody = (request: OpenApiExecuteRequest['request']) =>
  request.body_base64 ? Buffer.from(request.body_base64, 'base64') : Buffer.alloc(0);

const appendCanonicalHeaderValue = ({
  headers,
  name,
  value
}: {
  headers: Map<string, string[]>;
  name: string;
  value: string;
}) => {
  const normalizedValue = normalizeHeaderValueForSigning(value);
  const existingValues = headers.get(name);
  if (existingValues) {
    existingValues.push(normalizedValue);
    return;
  }

  headers.set(name, [normalizedValue]);
};

const buildCanonicalHeaders = (headers: Map<string, string[]>) => {
  const sortedNames = [...headers.keys()].sort((left, right) => left.localeCompare(right));
  return {
    canonicalHeaders: sortedNames
      .map(name => {
        const normalizedValues = [...(headers.get(name) ?? [])].sort((left, right) => left.localeCompare(right));
        return `${name}:${normalizedValues.join(',')}\n`;
      })
      .join(''),
    signedHeaders: sortedNames.join(';')
  };
};

const resolveForwardedHeaderAllowlist = ({
  template,
  matchedPathGroupId
}: {
  template: OpenApiTemplate;
  matchedPathGroupId: string;
}) => {
  const pathGroup = resolvePathGroup({template, matchedPathGroupId});
  if (!pathGroup) {
    return null;
  }

  return new Set(pathGroup.header_forward_allowlist.map(headerName => headerName.trim().toLowerCase()));
};

export const awsSigV4RuntimeAuthStrategy = defineRuntimeAuthStrategy({
  type: 'aws_sigv4',
  supportsSecret: (secretMaterial: SecretMaterial): secretMaterial is AwsSigV4SecretMaterial =>
    secretMaterial.type === 'aws_sigv4',
  buildHeaders: ({
    strategy,
    secretMaterial,
    request,
    template,
    matchedPathGroupId,
    now = new Date()
  }: {
    strategy: AwsSigV4Strategy;
    secretMaterial: AwsSigV4SecretMaterial;
    request: OpenApiExecuteRequest['request'];
    template: OpenApiTemplate;
    matchedPathGroupId: string;
    now?: Date;
  }): OpenApiHeaderList => {
    const url = new URL(request.url);
    const region = secretMaterial.region ?? strategy.region ?? deriveS3RegionFromHostname(url.hostname);
    if (!region) {
      throw new Error(`Unable to derive AWS region for S3 request host ${url.hostname}`);
    }

    const requestBody = decodeRequestBody(request);
    const payloadHash = requestBody.byteLength > 0 ? sha256Hex(requestBody) : EMPTY_BODY_SHA256;
    const {amzDate, shortDate} = toSigningDate(now);

    const canonicalHeaders = new Map<string, string[]>();
    appendCanonicalHeaderValue({headers: canonicalHeaders, name: 'host', value: url.host});
    appendCanonicalHeaderValue({headers: canonicalHeaders, name: 'x-amz-content-sha256', value: payloadHash});
    appendCanonicalHeaderValue({headers: canonicalHeaders, name: 'x-amz-date', value: amzDate});
    const forwardedHeaderAllowlist = resolveForwardedHeaderAllowlist({
      template,
      matchedPathGroupId
    });

    for (const header of request.headers) {
      const headerName = header.name.trim().toLowerCase();
      if (headerName === 'authorization' || headerName === 'host' || headerName.startsWith('x-amz-')) {
        continue;
      }
      if (forwardedHeaderAllowlist && !forwardedHeaderAllowlist.has(headerName)) {
        continue;
      }

      appendCanonicalHeaderValue({
        headers: canonicalHeaders,
        name: headerName,
        value: header.value
      });
    }

    if (secretMaterial.session_token) {
      appendCanonicalHeaderValue({
        headers: canonicalHeaders,
        name: 'x-amz-security-token',
        value: secretMaterial.session_token
      });
    }

    const renderedCanonicalHeaders = buildCanonicalHeaders(canonicalHeaders);
    const credentialScope = `${shortDate}/${region}/${strategy.service}/aws4_request`;
    const canonicalRequest = [
      request.method,
      buildCanonicalUri(url),
      buildCanonicalQueryString(url),
      renderedCanonicalHeaders.canonicalHeaders,
      renderedCanonicalHeaders.signedHeaders,
      payloadHash
    ].join('\n');

    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, sha256Hex(canonicalRequest)].join('\n');

    const signingKey = deriveSigningKey({
      secretAccessKey: secretMaterial.secret_access_key,
      shortDate,
      region,
      service: strategy.service
    });

    const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');
    const authorizationHeader = [
      'AWS4-HMAC-SHA256',
      `Credential=${secretMaterial.access_key_id}/${credentialScope},`,
      `SignedHeaders=${renderedCanonicalHeaders.signedHeaders},`,
      `Signature=${signature}`
    ].join(' ');

    const injectedHeaders: OpenApiHeaderList = [
      {name: 'Authorization', value: authorizationHeader},
      {name: 'x-amz-content-sha256', value: payloadHash},
      {name: 'x-amz-date', value: amzDate}
    ];

    if (secretMaterial.session_token) {
      injectedHeaders.push({
        name: 'x-amz-security-token',
        value: secretMaterial.session_token
      });
    }

    return injectedHeaders;
  }
});
