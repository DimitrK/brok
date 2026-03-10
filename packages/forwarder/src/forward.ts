import {randomUUID} from 'node:crypto';
import type {
  ReadableStream as NodeReadableStream,
  ReadableStreamDefaultReader
} from 'node:stream/web';

import {
  OpenApiExecuteResponseExecutedSchema,
  OpenApiHeaderListSchema,
  type OpenApiHeaderList,
  type Template
} from '@broker-interceptor/schemas';

import {
  DEFAULT_FORWARDER_LIMITS,
  DEFAULT_FORWARDER_TIMEOUTS,
  ForwardExecuteRequestInputSchema,
  type FetchLike,
  type ForwardExecuteRequestInput,
  type ForwardExecuteRequestOutput
} from './contracts';
import {err, ok, type ForwarderResult} from './errors';
import {validateRequestFraming} from './framing';
import {
  HOP_BY_HOP_HEADER_NAMES,
  normalizeHeaderName,
  stripHopByHopHeaders,
  validateHeaderValue
} from './headers';
import {dispatchWithNodeTransport, type BufferedUpstreamResponse} from './nodeTransport';

const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/u;

const CLIENT_HEADER_DENYLIST = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'host',
  'content-length',
  'dpop',
  'x-broker-session-token',
  'x-broker-token',
  'x-broker-authorization',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto'
]);

const INJECTED_HEADER_DENYLIST = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
  'dpop',
  'x-broker-session-token',
  'x-broker-token',
  'x-broker-authorization'
]);

const RESPONSE_HEADER_DENYLIST = new Set([
  ...HOP_BY_HOP_HEADER_NAMES,
  'set-cookie'
]);

const STREAMING_MEDIA_TYPES = new Set([
  'text/event-stream',
  'application/x-ndjson',
  'application/stream+json'
]);

const isRedirectStatus = (statusCode: number) => statusCode >= 300 && statusCode <= 399;

const normalizeMediaType = (value: string): string => {
  const [mediaType] = value.split(';', 1);
  return mediaType?.trim().toLowerCase() ?? '';
};

const isStreamingMediaType = (value: string): boolean => {
  const splitMediaTypes = value.split(',');
  return splitMediaTypes.some(mediaType => STREAMING_MEDIA_TYPES.has(normalizeMediaType(mediaType)));
};

const parseRequestBody = ({
  request,
  maxRequestBodyBytes
}: {
  request: ForwardExecuteRequestInput['execute_request']['request'];
  maxRequestBodyBytes: number;
}): ForwarderResult<Buffer | null> => {
  if (!request.body_base64) {
    return ok(null);
  }

  const normalizedBase64 = request.body_base64.trim();
  if (!BASE64_REGEX.test(normalizedBase64) || normalizedBase64.length % 4 !== 0) {
    return err('request_body_base64_invalid', 'request.body_base64 is not valid base64');
  }

  const decodedBody = Buffer.from(normalizedBase64, 'base64');
  if (decodedBody.toString('base64') !== normalizedBase64) {
    return err('request_body_base64_invalid', 'request.body_base64 is not valid base64');
  }

  if (decodedBody.byteLength > maxRequestBodyBytes) {
    return err(
      'request_body_too_large',
      `Request body exceeds configured max_request_body_bytes=${maxRequestBodyBytes}`
    );
  }

  return ok(decodedBody);
};

const normalizeHostForComparison = (host: string) => {
  const lowered = host.trim().toLowerCase();
  return lowered.endsWith('.') ? lowered.slice(0, -1) : lowered;
};

const resolvePathGroup = ({
  template,
  matchedPathGroupId
}: {
  template: Template;
  matchedPathGroupId: string;
}) => template.path_groups.find(pathGroup => pathGroup.group_id === matchedPathGroupId) ?? null;

const enforceTemplateRoutingConstraints = ({
  template,
  pathGroup,
  request
}: {
  template: Template;
  pathGroup: Template['path_groups'][number];
  request: ForwardExecuteRequestInput['execute_request']['request'];
}): ForwarderResult<void> => {
  if (!pathGroup.methods.includes(request.method)) {
    return err(
      'request_method_not_allowed',
      `Request method ${request.method} is not allowed for path group ${pathGroup.group_id}`
    );
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(request.url);
  } catch {
    return err('request_url_invalid', `Invalid request URL: ${request.url}`);
  }

  const scheme = parsedUrl.protocol.replace(/:$/u, '').toLowerCase();
  const allowedSchemes = new Set(template.allowed_schemes.map(item => item.toLowerCase()));
  if (!allowedSchemes.has(scheme)) {
    return err('request_scheme_not_allowed', `Request scheme is not allowed: ${scheme}`);
  }

  const host = normalizeHostForComparison(parsedUrl.hostname);
  const allowedHosts = new Set(template.allowed_hosts.map(normalizeHostForComparison));
  if (!allowedHosts.has(host)) {
    return err('request_host_not_allowed', `Request host is not allowed: ${host}`);
  }

  const port = parsedUrl.port.length > 0 ? Number.parseInt(parsedUrl.port, 10) : 443;
  const allowedPorts = new Set(template.allowed_ports.map(Number));
  if (!allowedPorts.has(port)) {
    return err('request_port_not_allowed', `Request port is not allowed: ${port}`);
  }

  return ok(undefined);
};

const parseHeaderAllowlist = (headerAllowlist: string[]): ForwarderResult<Set<string>> => {
  const normalizedAllowlist = new Set<string>();

  for (const headerName of headerAllowlist) {
    const normalizedName = normalizeHeaderName(headerName);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    normalizedAllowlist.add(normalizedName.value);
  }

  return ok(normalizedAllowlist);
};

const normalizeInjectedHeaders = (headers: OpenApiHeaderList): ForwarderResult<OpenApiHeaderList> => {
  const normalizedHeaders: OpenApiHeaderList = [];

  for (const header of headers) {
    const normalizedName = normalizeHeaderName(header.name);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    const normalizedValue = validateHeaderValue(header.value);
    if (!normalizedValue.ok) {
      return normalizedValue;
    }

    if (INJECTED_HEADER_DENYLIST.has(normalizedName.value)) {
      return err(
        'forbidden_upstream_header',
        `Injected header is forbidden for upstream forwarding: ${normalizedName.value}`
      );
    }

    normalizedHeaders.push({
      name: normalizedName.value,
      value: normalizedValue.value
    });
  }

  return ok(normalizedHeaders);
};

const finalizeUpstreamHeaders = ({
  headers,
  body,
  framing
}: {
  headers: OpenApiHeaderList;
  body: Buffer | null;
  framing: {content_length: number | null; has_transfer_encoding: boolean};
}): ForwarderResult<OpenApiHeaderList> => {
  if (framing.has_transfer_encoding) {
    return err(
      'request_transfer_encoding_not_supported',
      'Transfer-Encoding is not supported in buffered forwarding mode'
    );
  }

  if (framing.content_length === null && body) {
    return err(
      'request_content_length_required',
      'Buffered request bodies must include an explicit Content-Length header'
    );
  }

  if (framing.content_length === null) {
    return ok(headers);
  }

  return ok([
    ...headers,
    {
      name: 'content-length',
      value: String(framing.content_length)
    }
  ]);
};

const buildUpstreamHeaders = ({
  requestHeaders,
  pathGroupHeaderAllowlist,
  injectedHeaders
}: {
  requestHeaders: OpenApiHeaderList;
  pathGroupHeaderAllowlist: Set<string>;
  injectedHeaders: OpenApiHeaderList;
}): ForwarderResult<OpenApiHeaderList> => {
  const strippedRequestHeaders = stripHopByHopHeaders(requestHeaders);
  if (!strippedRequestHeaders.ok) {
    return strippedRequestHeaders;
  }

  const normalizedInjectedHeaders = normalizeInjectedHeaders(injectedHeaders);
  if (!normalizedInjectedHeaders.ok) {
    return normalizedInjectedHeaders;
  }

  const injectedHeaderNames = new Set(
    normalizedInjectedHeaders.value.map(header => header.name)
  );

  const upstreamHeaders: OpenApiHeaderList = [];

  for (const header of strippedRequestHeaders.value) {
    if (!pathGroupHeaderAllowlist.has(header.name)) {
      continue;
    }

    if (CLIENT_HEADER_DENYLIST.has(header.name)) {
      continue;
    }

    if (injectedHeaderNames.has(header.name)) {
      continue;
    }

    upstreamHeaders.push(header);
  }

  for (const header of normalizedInjectedHeaders.value) {
    upstreamHeaders.push(header);
  }

  return ok(upstreamHeaders);
};

const hasStreamingRequestExpectation = (requestHeaders: OpenApiHeaderList) =>
  requestHeaders.some(
    header => header.name === 'accept' && isStreamingMediaType(header.value)
  );

const getFirstHeaderValue = (headers: OpenApiHeaderList, headerName: string): string | null => {
  for (const header of headers) {
    if (header.name === headerName) {
      return header.value;
    }
  }

  return null;
};

const collectResponseHeaders = ({
  headers,
  allowlist
}: {
  headers: OpenApiHeaderList;
  allowlist: Set<string>;
}): ForwarderResult<OpenApiHeaderList> => {
  const selectedHeaders: OpenApiHeaderList = [];

  for (const header of headers) {
    const normalizedName = normalizeHeaderName(header.name);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    if (RESPONSE_HEADER_DENYLIST.has(normalizedName.value)) {
      continue;
    }

    if (!allowlist.has(normalizedName.value)) {
      continue;
    }

    selectedHeaders.push({
      name: normalizedName.value,
      value: header.value
    });
  }

  const parsedHeaders = OpenApiHeaderListSchema.safeParse(selectedHeaders);
  if (!parsedHeaders.success) {
    return err('invalid_upstream_response', parsedHeaders.error.message);
  }

  return ok(parsedHeaders.data);
};

const normalizeFetchResponseHeaders = (response: Response): ForwarderResult<OpenApiHeaderList> => {
  const normalizedHeaders: OpenApiHeaderList = [];

  for (const [name, value] of response.headers.entries()) {
    const normalizedName = normalizeHeaderName(name);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    const normalizedValue = validateHeaderValue(value);
    if (!normalizedValue.ok) {
      return normalizedValue;
    }

    normalizedHeaders.push({
      name: normalizedName.value,
      value: normalizedValue.value
    });
  }

  return ok(normalizedHeaders);
};

const readResponseBodyWithLimit = async ({
  response,
  responseHeaders,
  maxResponseBytes
}: {
  response: Response;
  responseHeaders: OpenApiHeaderList;
  maxResponseBytes: number;
}): Promise<ForwarderResult<Buffer>> => {
  const contentLengthHeader = getFirstHeaderValue(responseHeaders, 'content-length');
  if (contentLengthHeader && /^\d+$/u.test(contentLengthHeader.trim())) {
    const contentLength = Number.parseInt(contentLengthHeader, 10);
    if (Number.isSafeInteger(contentLength) && contentLength > maxResponseBytes) {
      return err(
        'upstream_response_too_large',
        `Upstream response exceeds max_response_bytes=${maxResponseBytes}`
      );
    }
  }

  if (!response.body) {
    return ok(Buffer.alloc(0));
  }

  const reader: ReadableStreamDefaultReader<Uint8Array> = (
    response.body as NodeReadableStream<Uint8Array>
  ).getReader();
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const readResult = await reader.read();
      if (readResult.done) {
        break;
      }

      const chunk = readResult.value;
      if (!chunk || chunk.byteLength === 0) {
        continue;
      }

      totalBytes += chunk.byteLength;
      if (totalBytes > maxResponseBytes) {
        await reader.cancel();
        return err(
          'upstream_response_too_large',
          `Upstream response exceeds max_response_bytes=${maxResponseBytes}`
        );
      }

      chunks.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    }

    return ok(Buffer.concat(chunks, totalBytes));
  } catch {
    return err('upstream_network_error', 'Failed while reading upstream response body');
  }
};

const toFetchHeaders = (headers: OpenApiHeaderList): Array<[string, string]> =>
  headers.map(header => [header.name, header.value]);

const mapFetchError = (unknownError: unknown) => {
  if (unknownError instanceof Error) {
    if (unknownError.name === 'AbortError' || unknownError.name === 'TimeoutError') {
      return err('upstream_timeout', 'Upstream request timed out');
    }

    return err('upstream_network_error', unknownError.message);
  }

  return err('upstream_network_error', 'Upstream request failed');
};

const buildCorrelationId = (input: ForwardExecuteRequestInput) =>
  input.correlation_id ?? input.execute_request.client_context?.request_id ?? randomUUID();

const resolveResponseAllowlist = ({
  inputAllowlist,
  pathGroupAllowlist
}: {
  inputAllowlist: string[] | undefined;
  pathGroupAllowlist: string[];
}): ForwarderResult<Set<string>> => parseHeaderAllowlist(inputAllowlist ?? pathGroupAllowlist);

const dispatchWithFetch = async ({
  url,
  method,
  headers,
  body,
  timeout_ms,
  max_response_bytes,
  fetchImpl
}: {
  url: string;
  method: ForwardExecuteRequestInput['execute_request']['request']['method'];
  headers: OpenApiHeaderList;
  body: Buffer | null;
  timeout_ms: number;
  max_response_bytes: number;
  fetchImpl: FetchLike;
}): Promise<ForwarderResult<BufferedUpstreamResponse>> => {
  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetchImpl(url, {
      method,
      headers: toFetchHeaders(headers),
      body: body ?? undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeout_ms)
    });
  } catch (unknownError) {
    return mapFetchError(unknownError);
  }

  const responseHeaders = normalizeFetchResponseHeaders(upstreamResponse);
  if (!responseHeaders.ok) {
    return responseHeaders;
  }

  if (isRedirectStatus(upstreamResponse.status)) {
    return err(
      'redirect_denied',
      `Upstream returned redirect status ${upstreamResponse.status}; redirects are denied`
    );
  }

  const contentType = getFirstHeaderValue(responseHeaders.value, 'content-type');
  if (contentType && isStreamingMediaType(contentType)) {
    return err(
      'upstream_streaming_not_supported',
      'Streaming upstream responses are not supported in MVP buffering mode'
    );
  }

  const bufferedResponseBody = await readResponseBodyWithLimit({
    response: upstreamResponse,
    responseHeaders: responseHeaders.value,
    maxResponseBytes: max_response_bytes
  });
  if (!bufferedResponseBody.ok) {
    return bufferedResponseBody;
  }

  return ok({
    status_code: upstreamResponse.status,
    headers: responseHeaders.value,
    body: bufferedResponseBody.value
  });
};

export const forwardExecuteRequest = async ({
  input,
  fetchImpl
}: {
  input: unknown;
  fetchImpl?: FetchLike;
}): Promise<ForwarderResult<ForwardExecuteRequestOutput>> => {
  const parsedInput = ForwardExecuteRequestInputSchema.safeParse(input);
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message);
  }

  const correlationId = buildCorrelationId(parsedInput.data);

  const timeouts = {
    ...DEFAULT_FORWARDER_TIMEOUTS,
    ...(parsedInput.data.timeouts ?? {})
  };
  const limits = {
    ...DEFAULT_FORWARDER_LIMITS,
    ...(parsedInput.data.limits ?? {})
  };

  if (parsedInput.data.template.redirect_policy.mode !== 'deny') {
    return err(
      'redirect_policy_not_supported',
      'Only redirect_policy.mode=deny is supported by the forwarder'
    );
  }

  const pathGroup = resolvePathGroup({
    template: parsedInput.data.template,
    matchedPathGroupId: parsedInput.data.matched_path_group_id
  });
  if (!pathGroup) {
    return err(
      'template_group_not_found',
      `Template path group was not found: ${parsedInput.data.matched_path_group_id}`
    );
  }

  const templateConstraintCheck = enforceTemplateRoutingConstraints({
    template: parsedInput.data.template,
    pathGroup,
    request: parsedInput.data.execute_request.request
  });
  if (!templateConstraintCheck.ok) {
    return templateConstraintCheck;
  }

  const parsedBody = parseRequestBody({
    request: parsedInput.data.execute_request.request,
    maxRequestBodyBytes: Math.min(pathGroup.body_policy.max_bytes, limits.max_request_body_bytes)
  });
  if (!parsedBody.ok) {
    return parsedBody;
  }

  const requestHeaders = OpenApiHeaderListSchema.parse(parsedInput.data.execute_request.request.headers);
  const framingCheck = validateRequestFraming({
    headers: requestHeaders,
    body_byte_length: parsedBody.value?.byteLength ?? 0
  });
  if (!framingCheck.ok) {
    return framingCheck;
  }

  const strippedRequestHeaders = stripHopByHopHeaders(requestHeaders);
  if (!strippedRequestHeaders.ok) {
    return strippedRequestHeaders;
  }

  if (hasStreamingRequestExpectation(strippedRequestHeaders.value)) {
    return err(
      'request_streaming_not_supported',
      'Streaming request expectations are not supported; remove streaming Accept media types'
    );
  }

  const parsedPathGroupHeaderAllowlist = parseHeaderAllowlist(pathGroup.header_forward_allowlist);
  if (!parsedPathGroupHeaderAllowlist.ok) {
    return parsedPathGroupHeaderAllowlist;
  }

  const upstreamHeaders = buildUpstreamHeaders({
    requestHeaders,
    pathGroupHeaderAllowlist: parsedPathGroupHeaderAllowlist.value,
    injectedHeaders: OpenApiHeaderListSchema.parse(parsedInput.data.injected_headers ?? [])
  });
  if (!upstreamHeaders.ok) {
    return upstreamHeaders;
  }

  const finalizedUpstreamHeaders = finalizeUpstreamHeaders({
    headers: upstreamHeaders.value,
    body: parsedBody.value,
    framing: framingCheck.value
  });
  if (!finalizedUpstreamHeaders.ok) {
    return finalizedUpstreamHeaders;
  }

  const responseHeaderAllowlist = resolveResponseAllowlist({
    inputAllowlist: parsedInput.data.response_header_allowlist,
    pathGroupAllowlist: pathGroup.header_forward_allowlist
  });
  if (!responseHeaderAllowlist.ok) {
    return responseHeaderAllowlist;
  }

  const dispatchResult = fetchImpl
    ? await dispatchWithFetch({
        url: parsedInput.data.execute_request.request.url,
        method: parsedInput.data.execute_request.request.method,
        headers: finalizedUpstreamHeaders.value,
        body: parsedBody.value,
        timeout_ms: timeouts.total_timeout_ms,
        max_response_bytes: limits.max_response_bytes,
        fetchImpl
      })
    : await dispatchWithNodeTransport({
        url: parsedInput.data.execute_request.request.url,
        method: parsedInput.data.execute_request.request.method,
        headers: finalizedUpstreamHeaders.value,
        body: parsedBody.value,
        timeout_ms: timeouts.total_timeout_ms,
        max_response_bytes: limits.max_response_bytes
      });
  if (!dispatchResult.ok) {
    return dispatchResult;
  }

  const responseHeaders = collectResponseHeaders({
    headers: dispatchResult.value.headers,
    allowlist: responseHeaderAllowlist.value
  });
  if (!responseHeaders.ok) {
    return responseHeaders;
  }

  const executedResponse = OpenApiExecuteResponseExecutedSchema.safeParse({
    status: 'executed',
    correlation_id: correlationId,
    upstream: {
      status_code: dispatchResult.value.status_code,
      headers: responseHeaders.value,
      body_base64: dispatchResult.value.body.toString('base64')
    }
  });
  if (!executedResponse.success) {
    return err('invalid_upstream_response', executedResponse.error.message);
  }

  return ok(executedResponse.data);
};
