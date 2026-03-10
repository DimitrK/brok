import {EventEmitter} from 'node:events';
import type {IncomingMessage} from 'node:http';
import {PassThrough} from 'node:stream';

import {afterEach, describe, expect, it, vi} from 'vitest';

import {
  dispatchWithNodeTransport,
  type NodeTransportRequest,
  type NodeTransportRequestFactory,
  type NodeTransportRequestOptions
} from '../nodeTransport';

class MockClientRequest extends EventEmitter implements NodeTransportRequest {
  public override on(event: 'error', listener: (error: unknown) => void): this {
    return super.on(event, listener);
  }

  public write(chunk: Buffer): boolean {
    void chunk;
    return true;
  }

  public end(): void {}

  public destroy(error?: Error): void {
    if (error) {
      queueMicrotask(() => {
        this.emit('error', error);
      });
    }
  }
}

const createIncomingMessage = ({
  statusCode,
  rawHeaders,
  body
}: {
  statusCode: number;
  rawHeaders: string[];
  body: string;
}): IncomingMessage => {
  const response = new PassThrough() as PassThrough & IncomingMessage;
  response.statusCode = statusCode;
  response.rawHeaders = rawHeaders;

  queueMicrotask(() => {
    response.end(body);
  });

  return response;
};

describe('dispatchWithNodeTransport', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('passes duplicate request headers as raw header pairs to the node transport', async () => {
    let capturedOptions: NodeTransportRequestOptions | null = null;

    const httpsFactory: NodeTransportRequestFactory = (options, onResponse) => {
      capturedOptions = options;
      const request = new MockClientRequest();

      queueMicrotask(() => {
        onResponse(
          createIncomingMessage({
            statusCode: 200,
            rawHeaders: ['Content-Type', 'application/json'],
            body: '{"ok":true}'
          })
        );
      });

      return request;
    };

    const result = await dispatchWithNodeTransport({
      url: 'https://api.example.com/v1/messages?x=1&x=2',
      method: 'GET',
      headers: [
        {name: 'authorization', value: 'Bearer provider-secret'},
        {name: 'x-auth-fragment', value: 'fragment-a'},
        {name: 'x-auth-fragment', value: 'fragment-b'}
      ],
      body: null,
      timeout_ms: 1_000,
      max_response_bytes: 1_024,
      requestFactories: {
        'http:': () => {
          throw new Error('unexpected http transport');
        },
        'https:': httpsFactory
      }
    });

    expect(capturedOptions).toEqual({
      protocol: 'https:',
      hostname: 'api.example.com',
      port: undefined,
      path: '/v1/messages?x=1&x=2',
      method: 'GET',
      headers: [
        'authorization',
        'Bearer provider-secret',
        'x-auth-fragment',
        'fragment-a',
        'x-auth-fragment',
        'fragment-b',
        'host',
        'api.example.com'
      ]
    });
    expect(result.ok).toBe(true);
  });

  it('includes the explicit port in the derived host header when non-default', async () => {
    let capturedOptions: NodeTransportRequestOptions | null = null;

    const httpsFactory: NodeTransportRequestFactory = (options, onResponse) => {
      capturedOptions = options;
      const request = new MockClientRequest();

      queueMicrotask(() => {
        onResponse(
          createIncomingMessage({
            statusCode: 200,
            rawHeaders: ['Content-Type', 'application/json'],
            body: '{"ok":true}'
          })
        );
      });

      return request;
    };

    const result = await dispatchWithNodeTransport({
      url: 'https://api.example.com:8443/v1/messages',
      method: 'GET',
      headers: [{name: 'accept', value: 'application/json'}],
      body: null,
      timeout_ms: 1_000,
      max_response_bytes: 1_024,
      requestFactories: {
        'http:': () => {
          throw new Error('unexpected http transport');
        },
        'https:': httpsFactory
      }
    });

    expect(capturedOptions).not.toBeNull();
    if (!capturedOptions) {
      return;
    }

    const options = capturedOptions as NodeTransportRequestOptions;

    expect(options.headers).toEqual([
      'accept',
      'application/json',
      'host',
      'api.example.com:8443'
    ]);
    expect(result.ok).toBe(true);
  });

  it('maps node transport timeouts to a stable reason code', async () => {
    vi.useFakeTimers();

    const httpsFactory: NodeTransportRequestFactory = () => {
      return new MockClientRequest();
    };

    const resultPromise = dispatchWithNodeTransport({
      url: 'https://api.example.com/v1/messages',
      method: 'GET',
      headers: [{name: 'accept', value: 'application/json'}],
      body: null,
      timeout_ms: 1_000,
      max_response_bytes: 1_024,
      requestFactories: {
        'http:': () => {
          throw new Error('unexpected http transport');
        },
        'https:': httpsFactory
      }
    });

    await vi.advanceTimersByTimeAsync(1_000);
    const result = await resultPromise;

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('upstream_timeout');
  });
});
