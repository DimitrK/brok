import {request as httpRequest, type IncomingMessage} from 'node:http';
import {request as httpsRequest} from 'node:https';

import type {OpenApiHeaderList} from '@broker-interceptor/schemas';

import {err, ok, type ForwarderResult} from './errors';
import {normalizeHeaderName, validateHeaderValue} from './headers';

const STREAMING_MEDIA_TYPES = new Set([
  'text/event-stream',
  'application/x-ndjson',
  'application/stream+json'
]);

export type BufferedUpstreamResponse = {
  status_code: number;
  headers: OpenApiHeaderList;
  body: Buffer;
};

export type NodeTransportRequestOptions = {
  protocol: 'http:' | 'https:';
  hostname: string;
  port?: string;
  path: string;
  method: string;
  headers: string[];
};

export type NodeTransportRequest = {
  on(event: 'error', listener: (error: unknown) => void): NodeTransportRequest;
  write(chunk: Buffer): boolean;
  end(): void;
  destroy(error?: Error): void;
};

export type NodeTransportRequestFactory = (
  options: NodeTransportRequestOptions,
  onResponse: (response: IncomingMessage) => void
) => NodeTransportRequest;

type NodeTransportFactories = {
  'http:': NodeTransportRequestFactory;
  'https:': NodeTransportRequestFactory;
};

const defaultRequestFactories: NodeTransportFactories = {
  'http:': (options, onResponse) => httpRequest(options, onResponse),
  'https:': (options, onResponse) => httpsRequest(options, onResponse)
};

const isRedirectStatus = (statusCode: number) => statusCode >= 300 && statusCode <= 399;

const normalizeMediaType = (value: string): string => {
  const [mediaType] = value.split(';', 1);
  return mediaType?.trim().toLowerCase() ?? '';
};

const isStreamingMediaType = (value: string): boolean =>
  value
    .split(',')
    .some(mediaType => STREAMING_MEDIA_TYPES.has(normalizeMediaType(mediaType)));

const defaultPortForProtocol = (protocol: string) => {
  if (protocol === 'https:') {
    return '443';
  }

  if (protocol === 'http:') {
    return '80';
  }

  return '';
};

const buildHostHeaderValue = (url: URL) => {
  const defaultPort = defaultPortForProtocol(url.protocol);
  if (!url.port || url.port === defaultPort) {
    return url.hostname;
  }

  return `${url.hostname}:${url.port}`;
};

const ensureHostHeader = (headers: OpenApiHeaderList, url: URL): OpenApiHeaderList => {
  if (headers.some(header => header.name === 'host')) {
    return headers;
  }

  return [
    ...headers,
    {
      name: 'host',
      value: buildHostHeaderValue(url)
    }
  ];
};

const toRawHeaderPairs = (headers: OpenApiHeaderList): string[] =>
  headers.flatMap(header => [header.name, header.value]);

const normalizeResponseHeaders = (rawHeaders: readonly string[]): ForwarderResult<OpenApiHeaderList> => {
  if (rawHeaders.length % 2 !== 0) {
    return err('invalid_upstream_response', 'Upstream response headers are malformed');
  }

  const normalizedHeaders: OpenApiHeaderList = [];
  const headerIterator = rawHeaders[Symbol.iterator]();

  while (true) {
    const rawName = headerIterator.next();
    if (rawName.done) {
      break;
    }

    const rawValue = headerIterator.next();
    if (rawValue.done) {
      return err('invalid_upstream_response', 'Upstream response headers are malformed');
    }

    const normalizedName = normalizeHeaderName(rawName.value);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    const normalizedValue = validateHeaderValue(rawValue.value);
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

const getFirstHeaderValue = (headers: OpenApiHeaderList, headerName: string): string | null => {
  for (const header of headers) {
    if (header.name === headerName) {
      return header.value;
    }
  }

  return null;
};

const createTimeoutError = () => {
  const timeoutError = new Error('Upstream request timed out');
  timeoutError.name = 'TimeoutError';
  return timeoutError;
};

const mapTransportError = (unknownError: unknown): ForwarderResult<never> => {
  if (unknownError instanceof Error) {
    if (unknownError.name === 'AbortError' || unknownError.name === 'TimeoutError') {
      return err('upstream_timeout', 'Upstream request timed out');
    }

    return err('upstream_network_error', unknownError.message);
  }

  return err('upstream_network_error', 'Upstream request failed');
};

export const dispatchWithNodeTransport = ({
  url,
  method,
  headers,
  body,
  timeout_ms,
  max_response_bytes,
  requestFactories = defaultRequestFactories
}: {
  url: string;
  method: string;
  headers: OpenApiHeaderList;
  body: Buffer | null;
  timeout_ms: number;
  max_response_bytes: number;
  requestFactories?: NodeTransportFactories;
}): Promise<ForwarderResult<BufferedUpstreamResponse>> => {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return Promise.resolve(err('request_url_invalid', `Invalid request URL: ${url}`));
  }

  const requestFactory = requestFactories[parsedUrl.protocol as keyof NodeTransportFactories];
  if (!requestFactory) {
    return Promise.resolve(err('upstream_network_error', `Unsupported upstream protocol: ${parsedUrl.protocol}`));
  }

  return new Promise(resolve => {
    let settled = false;
    let activeResponse: IncomingMessage | null = null;
    let deadlineTimer: ReturnType<typeof setTimeout> | null = null;

    const settle = (result: ForwarderResult<BufferedUpstreamResponse>) => {
      if (settled) {
        return;
      }

      settled = true;
      if (deadlineTimer) {
        clearTimeout(deadlineTimer);
        deadlineTimer = null;
      }
      resolve(result);
    };

    const request = requestFactory(
      {
        protocol: parsedUrl.protocol as 'http:' | 'https:',
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || undefined,
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method,
        headers: toRawHeaderPairs(ensureHostHeader(headers, parsedUrl))
      },
      response => {
        activeResponse = response;
        const statusCode = response.statusCode;
        if (!statusCode) {
          response.resume();
          settle(err('invalid_upstream_response', 'Upstream response is missing a valid status code'));
          return;
        }

        const responseHeaders = normalizeResponseHeaders(response.rawHeaders);
        if (!responseHeaders.ok) {
          response.resume();
          settle(responseHeaders);
          return;
        }

        if (isRedirectStatus(statusCode)) {
          response.resume();
          settle(err('redirect_denied', `Upstream returned redirect status ${statusCode}; redirects are denied`));
          return;
        }

        const contentType = getFirstHeaderValue(responseHeaders.value, 'content-type');
        if (contentType && isStreamingMediaType(contentType)) {
          response.resume();
          settle(
            err(
              'upstream_streaming_not_supported',
              'Streaming upstream responses are not supported in MVP buffering mode'
            )
          );
          return;
        }

        const contentLength = getFirstHeaderValue(responseHeaders.value, 'content-length');
        if (contentLength && /^\d+$/u.test(contentLength.trim())) {
          const parsedContentLength = Number.parseInt(contentLength, 10);
          if (Number.isSafeInteger(parsedContentLength) && parsedContentLength > max_response_bytes) {
            response.resume();
            settle(
              err(
                'upstream_response_too_large',
                `Upstream response exceeds max_response_bytes=${max_response_bytes}`
              )
            );
            return;
          }
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;

        response.on('data', (chunk: Buffer | string) => {
          const normalizedChunk = Buffer.from(chunk);
          totalBytes += normalizedChunk.byteLength;

          if (totalBytes > max_response_bytes) {
            response.destroy();
            settle(
              err(
                'upstream_response_too_large',
                `Upstream response exceeds max_response_bytes=${max_response_bytes}`
              )
            );
            return;
          }

          chunks.push(normalizedChunk);
        });

        response.on('end', () => {
          settle(
            ok({
              status_code: statusCode,
              headers: responseHeaders.value,
              body: Buffer.concat(chunks, totalBytes)
            })
          );
        });

        response.on('error', responseError => {
          settle(mapTransportError(responseError));
        });
      }
    );

    deadlineTimer = setTimeout(() => {
      const timeoutError = createTimeoutError();
      activeResponse?.destroy(timeoutError);
      request.destroy(timeoutError);
      settle(err('upstream_timeout', 'Upstream request timed out'));
    }, timeout_ms);

    request.on('error', requestError => {
      settle(mapTransportError(requestError));
    });

    if (body) {
      request.write(body);
    }

    request.end();
  });
};
