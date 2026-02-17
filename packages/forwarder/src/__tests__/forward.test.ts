import {TemplateSchema, type OpenApiExecuteRequest} from '@broker-interceptor/schemas';
import {describe, expect, it, vi} from 'vitest';

import {forwardExecuteRequest, stripHopByHopHeaders, validateRequestFraming} from '../index';

const createTemplate = () =>
  TemplateSchema.parse({
    template_id: 'tpl_forwarder_v1',
    version: 1,
    provider: 'test_provider',
    allowed_schemes: ['https'],
    allowed_ports: [443],
    allowed_hosts: ['api.example.com'],
    redirect_policy: {
      mode: 'deny'
    },
    path_groups: [
      {
        group_id: 'group_a',
        risk_tier: 'medium',
        approval_mode: 'none',
        methods: ['GET', 'POST'],
        path_patterns: ['^/v1/messages$'],
        query_allowlist: [],
        header_forward_allowlist: ['accept', 'x-client-id', 'authorization'],
        body_policy: {
          max_bytes: 1024 * 1024,
          content_types: ['application/json']
        }
      }
    ],
    network_safety: {
      deny_private_ip_ranges: true,
      deny_link_local: true,
      deny_loopback: true,
      deny_metadata_ranges: true,
      dns_resolution_required: true
    }
  });

const createExecuteRequest = (): OpenApiExecuteRequest => {
  const body = Buffer.from(JSON.stringify({message: 'hello'})).toString('base64');

  return {
    integration_id: 'integration_1',
    request: {
      method: 'POST',
      url: 'https://api.example.com/v1/messages',
      headers: [
        {name: 'Accept', value: 'application/json'},
        {name: 'X-Client-Id', value: 'workload_1'},
        {name: 'Authorization', value: 'Bearer broker-session-token'},
        {name: 'Content-Length', value: String(Buffer.from(body, 'base64').byteLength)}
      ],
      body_base64: body
    },
    client_context: {
      request_id: 'req_123'
    }
  };
};

describe('stripHopByHopHeaders', () => {
  it('removes hop-by-hop headers and Connection-nominated headers', () => {
    const stripped = stripHopByHopHeaders([
      {name: 'Connection', value: 'Keep-Alive, X-Remove-Me'},
      {name: 'Keep-Alive', value: 'timeout=5'},
      {name: 'X-Remove-Me', value: '1'},
      {name: 'X-Keep-Me', value: 'ok'}
    ]);

    expect(stripped.ok).toBe(true);
    if (!stripped.ok) {
      return;
    }

    expect(stripped.value).toEqual([{name: 'x-keep-me', value: 'ok'}]);
  });

  it('fails closed for invalid Connection tokens', () => {
    const stripped = stripHopByHopHeaders([{name: 'Connection', value: 'x-valid, bad token'}]);

    expect(stripped.ok).toBe(false);
    if (stripped.ok) {
      return;
    }

    expect(stripped.error.code).toBe('invalid_connection_header');
  });
});

describe('validateRequestFraming', () => {
  it('rejects conflicting Content-Length and Transfer-Encoding', () => {
    const framing = validateRequestFraming({
      headers: [
        {name: 'Content-Length', value: '12'},
        {name: 'Transfer-Encoding', value: 'chunked'}
      ],
      body_byte_length: 12
    });

    expect(framing.ok).toBe(false);
    if (framing.ok) {
      return;
    }

    expect(framing.error.code).toBe('ambiguous_framing_conflicting_content_length_transfer_encoding');
  });

  it('rejects invalid Content-Length values', () => {
    const framing = validateRequestFraming({
      headers: [{name: 'Content-Length', value: 'abc'}],
      body_byte_length: 0
    });

    expect(framing.ok).toBe(false);
    if (framing.ok) {
      return;
    }

    expect(framing.error.code).toBe('ambiguous_framing_invalid_content_length');
  });

  it('rejects transfer-encoding chains that do not end with chunked', () => {
    const framing = validateRequestFraming({
      headers: [{name: 'Transfer-Encoding', value: 'gzip'}],
      body_byte_length: 0
    });

    expect(framing.ok).toBe(false);
    if (framing.ok) {
      return;
    }

    expect(framing.error.code).toBe('ambiguous_framing_transfer_encoding_invalid');
  });
});

describe('forwardExecuteRequest', () => {
  it('forwards with injected auth, strips unsafe headers, and allowlists response headers', async () => {
    const fetchSpy = vi.fn((_input: unknown, init?: RequestInit) => {
      const upstreamHeaders = init?.headers as Headers;
      expect(upstreamHeaders.get('authorization')).toBe('Bearer provider-secret');
      expect(upstreamHeaders.get('x-client-id')).toBe('workload_1');
      expect(upstreamHeaders.get('connection')).toBeNull();

      return Promise.resolve(new Response(JSON.stringify({ok: true}), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'x-upstream-id': 'upstream_123',
          'x-unallowlisted': 'hidden'
        }
      }));
    });

    const result = await forwardExecuteRequest({
      input: {
        execute_request: createExecuteRequest(),
        template: createTemplate(),
        matched_path_group_id: 'group_a',
        injected_headers: [{name: 'Authorization', value: 'Bearer provider-secret'}],
        response_header_allowlist: ['content-type', 'x-upstream-id'],
        correlation_id: 'corr_abc'
      },
      fetchImpl: fetchSpy
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(result.value.status).toBe('executed');
    expect(result.value.correlation_id).toBe('corr_abc');
    expect(result.value.upstream.status_code).toBe(200);
    expect(result.value.upstream.headers).toEqual([
      {name: 'content-type', value: 'application/json'},
      {name: 'x-upstream-id', value: 'upstream_123'}
    ]);
    expect(Buffer.from(result.value.upstream.body_base64, 'base64').toString('utf8')).toContain('"ok":true');
  });

  it('denies redirects from upstream', async () => {
    const result = await forwardExecuteRequest({
      input: {
        execute_request: createExecuteRequest(),
        template: createTemplate(),
        matched_path_group_id: 'group_a',
        injected_headers: [{name: 'Authorization', value: 'Bearer provider-secret'}]
      },
      fetchImpl: vi.fn(() =>
        Promise.resolve(new Response('', {status: 302, headers: {location: 'https://evil.example'}}))
      )
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('redirect_denied');
  });

  it('rejects streaming request expectations', async () => {
    const request = createExecuteRequest();
    request.request.headers = [{name: 'Accept', value: 'text/event-stream'}];
    request.request.method = 'GET';
    delete request.request.body_base64;

    const result = await forwardExecuteRequest({
      input: {
        execute_request: request,
        template: createTemplate(),
        matched_path_group_id: 'group_a'
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('request_streaming_not_supported');
  });

  it('rejects streaming upstream responses', async () => {
    const result = await forwardExecuteRequest({
      input: {
        execute_request: createExecuteRequest(),
        template: createTemplate(),
        matched_path_group_id: 'group_a',
        injected_headers: [{name: 'Authorization', value: 'Bearer provider-secret'}]
      },
      fetchImpl: vi.fn(() =>
        Promise.resolve(
          new Response('data: hello\n\n', {status: 200, headers: {'content-type': 'text/event-stream'}})
        )
      )
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('upstream_streaming_not_supported');
  });

  it('fails closed when matched path group does not exist', async () => {
    const result = await forwardExecuteRequest({
      input: {
        execute_request: createExecuteRequest(),
        template: createTemplate(),
        matched_path_group_id: 'missing_group'
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('template_group_not_found');
  });

  it('rejects Content-Length mismatch', async () => {
    const request = createExecuteRequest();
    request.request.headers = request.request.headers.map(header =>
      header.name.toLowerCase() === 'content-length' ? {name: header.name, value: '999'} : header
    );

    const result = await forwardExecuteRequest({
      input: {
        execute_request: request,
        template: createTemplate(),
        matched_path_group_id: 'group_a'
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('ambiguous_framing_content_length_mismatch');
  });

  it('enforces max_response_bytes limits', async () => {
    const oversizedBody = 'x'.repeat(128);

    const result = await forwardExecuteRequest({
      input: {
        execute_request: createExecuteRequest(),
        template: createTemplate(),
        matched_path_group_id: 'group_a',
        injected_headers: [{name: 'Authorization', value: 'Bearer provider-secret'}],
        limits: {
          max_response_bytes: 32,
          max_request_body_bytes: 1024 * 1024
        }
      },
      fetchImpl: vi.fn(() =>
        Promise.resolve(
          new Response(oversizedBody, {
            status: 200,
            headers: {'content-type': 'application/json', 'content-length': String(oversizedBody.length)}
          })
        )
      )
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('upstream_response_too_large');
  });

  it('rejects invalid request body base64', async () => {
    const request = createExecuteRequest();
    request.request.body_base64 = 'not-base64!!!';

    const result = await forwardExecuteRequest({
      input: {
        execute_request: request,
        template: createTemplate(),
        matched_path_group_id: 'group_a'
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('request_body_base64_invalid');
  });

  it('rejects forbidden injected upstream headers', async () => {
    const result = await forwardExecuteRequest({
      input: {
        execute_request: createExecuteRequest(),
        template: createTemplate(),
        matched_path_group_id: 'group_a',
        injected_headers: [{name: 'Host', value: 'evil.example'}]
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('forbidden_upstream_header');
  });

  it('maps upstream network failures to stable reason codes', async () => {
    const result = await forwardExecuteRequest({
      input: {
        execute_request: createExecuteRequest(),
        template: createTemplate(),
        matched_path_group_id: 'group_a'
      },
      fetchImpl: vi.fn(() => Promise.reject(new Error('dial failed')))
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('upstream_network_error');
  });

  it('fails closed when method is outside matched template group methods', async () => {
    const request = createExecuteRequest();
    request.request.method = 'DELETE';
    delete request.request.body_base64;
    request.request.headers = [{name: 'Accept', value: 'application/json'}];

    const result = await forwardExecuteRequest({
      input: {
        execute_request: request,
        template: createTemplate(),
        matched_path_group_id: 'group_a'
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('request_method_not_allowed');
  });

  it('fails closed when host is outside template allowlist', async () => {
    const request = createExecuteRequest();
    request.request.url = 'https://evil.example/v1/messages';

    const result = await forwardExecuteRequest({
      input: {
        execute_request: request,
        template: createTemplate(),
        matched_path_group_id: 'group_a'
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('request_host_not_allowed');
  });

  it('fails closed when scheme is outside template allowlist', async () => {
    const request = createExecuteRequest();
    request.request.url = 'http://api.example.com/v1/messages';

    const result = await forwardExecuteRequest({
      input: {
        execute_request: request,
        template: createTemplate(),
        matched_path_group_id: 'group_a'
      },
      fetchImpl: vi.fn()
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('request_scheme_not_allowed');
  });
});
