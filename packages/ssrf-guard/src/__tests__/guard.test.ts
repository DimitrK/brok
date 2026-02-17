import {TemplateSchema, type OpenApiExecuteRequest, type Template} from '@broker-interceptor/schemas';
import {describe, expect, it, vi} from 'vitest';

import {enforceRedirectDenyPolicy, guardExecuteRequestDestination} from '../index';

const buildTemplate = (): Template =>
  TemplateSchema.parse({
    template_id: 'tpl_ssrf_guard_v1',
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
        risk_tier: 'low',
        approval_mode: 'none',
        methods: ['GET', 'POST'],
        path_patterns: ['^/v1/messages$'],
        query_allowlist: [],
        header_forward_allowlist: ['accept', 'content-type'],
        body_policy: {
          max_bytes: 1024,
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

const buildExecuteRequest = (url: string): OpenApiExecuteRequest => ({
  integration_id: 'integration_1',
  request: {
    method: 'POST',
    url,
    headers: [{name: 'Accept', value: 'application/json'}]
  }
});

describe('guardExecuteRequestDestination', () => {
  it('resolves DNS at request time and accepts public destinations', async () => {
    const dnsResolver = vi.fn(() => ['93.184.216.34']);

    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {dns_resolver: dnsResolver}
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.destination.host).toBe('api.example.com');
    expect(result.value.resolved_ips).toEqual(['93.184.216.34']);
    expect(dnsResolver).toHaveBeenCalledTimes(1);
    expect(dnsResolver).toHaveBeenCalledWith({hostname: 'api.example.com'});
  });

  it('rejects DNS rebinding-like mixed resolution when any resolved IP is denylisted', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['93.184.216.34', '10.1.2.3']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('resolved_ip_denied_private_range');
  });

  it('rejects private ranges', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['10.1.2.3']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('resolved_ip_denied_private_range');
  });

  it('rejects loopback ranges', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['::1']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('resolved_ip_denied_loopback');
  });

  it('rejects link-local ranges', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['169.254.12.45']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('resolved_ip_denied_link_local');
  });

  it('rejects metadata ranges', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['169.254.169.254']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('resolved_ip_denied_metadata_range');
  });

  it('rejects malformed DNS answers', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['not-an-ip']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('resolved_ip_invalid');
  });

  it('fails closed when DNS returns no addresses', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => []
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('dns_resolution_empty');
  });

  it('fails closed on DNS resolution failures', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => {
          throw new Error('dns failure');
        }
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('dns_resolution_failed');
  });

  it('rejects userinfo URL patterns (open proxy abuse pattern)', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://user:pass@api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_url_userinfo_forbidden');
  });

  it('rejects URL fragments', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages#frag'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_url_fragment_forbidden');
  });

  it('rejects malformed host normalization edge cases', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://./v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_url_invalid');
  });

  it('fails closed when template host entries are invalid after normalization', async () => {
    const template = buildTemplate();
    template.allowed_hosts = ['   '];

    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('template_host_invalid');
  });

  it('rejects hosts outside template allowlist', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://evil.example/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_host_not_allowed');
  });

  it('rejects schemes outside template allowlist', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('http://api.example.com/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_scheme_not_allowed');
  });

  it('rejects ports outside template allowlist', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com:8443/v1/messages'),
        template: buildTemplate()
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_port_not_allowed');
  });

  it('rejects IP literal URLs unless explicitly allowlisted by template', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://93.184.216.34/v1/messages'),
        template: buildTemplate()
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_ip_literal_forbidden');
  });

  it('accepts public IP literal URLs when explicitly allowlisted', async () => {
    const template = buildTemplate();
    template.allowed_hosts = ['93.184.216.34'];

    const dnsResolver = vi.fn(() => ['10.0.0.1']);

    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://93.184.216.34/v1/messages'),
        template
      },
      options: {
        dns_resolver: dnsResolver
      }
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.resolved_ips).toEqual(['93.184.216.34']);
    expect(dnsResolver).not.toHaveBeenCalled();
  });

  it('rejects allowlisted IP literals when they resolve to denied range directly', async () => {
    const template = buildTemplate();
    template.allowed_hosts = ['127.0.0.1'];

    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://127.0.0.1/v1/messages'),
        template
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('resolved_ip_denied_loopback');
  });

  it('fails closed when template disables dns_resolution_required', async () => {
    const template = buildTemplate();
    template.network_safety.dns_resolution_required = false;

    const result = await guardExecuteRequestDestination({
      input: {
        execute_request: buildExecuteRequest('https://api.example.com/v1/messages'),
        template
      },
      options: {
        dns_resolver: () => ['93.184.216.34']
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('dns_resolution_required');
  });

  it('validates execute guard inputs at boundary', async () => {
    const result = await guardExecuteRequestDestination({
      input: {
        request: {}
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('invalid_input');
  });
});

describe('enforceRedirectDenyPolicy', () => {
  it('denies upstream redirects for MVP policy', () => {
    const result = enforceRedirectDenyPolicy({
      input: {
        template: buildTemplate(),
        upstream_status_code: 302,
        upstream_headers: [{name: 'location', value: 'https://redirect.example'}]
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('redirect_denied');
  });

  it('accepts non-redirect statuses', () => {
    const result = enforceRedirectDenyPolicy({
      input: {
        template: buildTemplate(),
        upstream_status_code: 200
      }
    });

    expect(result.ok).toBe(true);
  });

  it('validates redirect guard inputs at boundary', () => {
    const result = enforceRedirectDenyPolicy({
      input: {
        upstream_status_code: 302
      }
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('invalid_input');
  });
});
