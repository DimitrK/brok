import crypto from 'node:crypto';

import {describe, expect, it} from 'vitest';

import {canonicalizeExecuteRequest} from '../index';
import type {CanonicalizeExecuteRequestInput} from '../index';
import {buildTemplate} from './fixtures/canonicalization-vectors';

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

const buildBaseInput = (): CanonicalizeExecuteRequestInput => ({
  context: {
    tenant_id: 't_123',
    workload_id: 'w_456',
    integration_id: 'i_789'
  },
  template: buildTemplate(),
  execute_request: {
    integration_id: 'i_789',
    request: {
      method: 'GET',
      url: 'https://GMAIL.GOOGLEAPIS.COM:443/gmail/v1/users/me/messages/./../messages/%7e?q=hello&format=full',
      headers: [
        {name: 'Authorization', value: 'Bearer secret'},
        {name: 'Accept', value: 'application/json'},
        {name: 'X-Custom', value: '  b  '},
        {name: 'x-custom', value: 'a'},
        {name: 'User-Agent', value: 'canonicalizer-test'}
      ]
    }
  }
});

describe('canonicalizeExecuteRequest', () => {
  it('builds a canonical descriptor for a valid request', () => {
    const result = canonicalizeExecuteRequest(buildBaseInput());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.canonical_url).toBe(
      'https://gmail.googleapis.com/gmail/v1/users/me/messages/~?format=full&q=hello'
    );
    expect(result.value.matched_path_group_id).toBe('gmail_read');
    expect(result.value.descriptor.query_keys).toEqual(['format', 'q']);
    expect(result.value.descriptor.body_sha256_base64).toBeNull();
    expect(result.value.descriptor.normalized_headers).toEqual([
      {name: 'accept', value: 'application/json'},
      {name: 'user-agent', value: 'canonicalizer-test'},
      {name: 'x-custom', value: 'a'},
      {name: 'x-custom', value: 'b'}
    ]);
  });

  it('computes body digest for high-risk groups by default', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'POST';
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send?q=ok';
    input.execute_request.request.headers = [
      {name: 'Content-Type', value: 'application/json'},
      {name: 'Accept', value: 'application/json'}
    ];
    input.execute_request.request.body_base64 = Buffer.from('{"ok":true}', 'utf8').toString('base64');

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.matched_path_group_id).toBe('gmail_send');
    expect(result.value.descriptor.body_sha256_base64).toBe(
      crypto.createHash('sha256').update('{"ok":true}').digest('base64')
    );
  });

  it('does not compute body digest when mode is never', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'POST';
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send?q=ok';
    input.execute_request.request.headers = [
      {name: 'Content-Type', value: 'application/json'},
      {name: 'Accept', value: 'application/json'}
    ];
    input.execute_request.request.body_base64 = Buffer.from('{"ok":true}', 'utf8').toString('base64');
    input.body_digest_mode = 'never';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.descriptor.body_sha256_base64).toBeNull();
  });

  it('computes body digest for low-risk groups when mode is always', () => {
    const input = buildBaseInput();
    input.template.path_groups[0].body_policy = {
      max_bytes: 1_024,
      content_types: ['application/json']
    };
    input.execute_request.request.headers = [
      {name: 'Content-Type', value: 'application/json'},
      {name: 'Accept', value: 'application/json'}
    ];
    input.execute_request.request.body_base64 = Buffer.from('{"ping":true}', 'utf8').toString('base64');
    input.body_digest_mode = 'always';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.descriptor.body_sha256_base64).toBe(
      crypto.createHash('sha256').update('{"ping":true}').digest('base64')
    );
  });

  it('does not compute body digest for low-risk groups in high_risk_only mode', () => {
    const input = buildBaseInput();
    input.template.path_groups[0].body_policy = {
      max_bytes: 1_024,
      content_types: ['application/json']
    };
    input.execute_request.request.headers = [{name: 'Content-Type', value: 'application/json'}];
    input.execute_request.request.body_base64 = Buffer.from('{"ping":true}', 'utf8').toString('base64');
    input.body_digest_mode = 'high_risk_only';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.descriptor.body_sha256_base64).toBeNull();
  });

  it('rejects requests with userinfo', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://user:pass@gmail.googleapis.com/gmail/v1/users/me/messages';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_url_userinfo_forbidden');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects requests with fragment', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages#fragment';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_url_fragment_forbidden');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects scheme outside template allowlist', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'http://gmail.googleapis.com/gmail/v1/users/me/messages';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_scheme_not_allowed');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects host outside template allowlist', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://api.openai.com/gmail/v1/users/me/messages';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_host_not_allowed');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects ports outside template allowlist', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://gmail.googleapis.com:444/gmail/v1/users/me/messages';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_port_not_allowed');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects requests with disallowed query keys', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?bad=1';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_query_key_not_allowlisted');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects duplicate query keys when not explicitly allowed', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=a&q=b';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_query_duplicate_key_forbidden');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('allows duplicate query keys when allow_duplicate_query_keys is true', () => {
    const input = buildBaseInput();
    const template = clone(input.template);
    template.path_groups[0].constraints = {
      allow_duplicate_query_keys: true
    };
    input.template = template;
    input.execute_request.request.url =
      'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=a&q=b&format=full';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.canonical_url).toBe(
      'https://gmail.googleapis.com/gmail/v1/users/me/messages?format=full&q=a&q=b'
    );
    expect(result.value.descriptor.query_keys).toEqual(['format', 'q']);
  });

  it('rejects duplicate query keys when allow_duplicate_query_keys is false', () => {
    const input = buildBaseInput();
    const template = clone(input.template);
    template.path_groups[0].constraints = {
      allow_duplicate_query_keys: false
    };
    input.template = template;
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=a&q=b';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_query_duplicate_key_forbidden');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('allows duplicate query keys when explicitly configured', () => {
    const input = buildBaseInput();
    const template = clone(input.template);
    template.path_groups[0].constraints = {
      allow_duplicate_query_keys: ['q']
    };
    input.template = template;
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=a&q=b';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.canonical_url).toBe('https://gmail.googleapis.com/gmail/v1/users/me/messages?q=a&q=b');
    expect(result.value.descriptor.query_keys).toEqual(['q']);
  });

  it('normalizes query keys and ignores empty query segments', () => {
    const input = buildBaseInput();
    input.execute_request.request.url =
      'https://gmail.googleapis.com/gmail/v1/users/me/messages?format=full&&q';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.canonical_url).toBe('https://gmail.googleapis.com/gmail/v1/users/me/messages?format=full&q');
    expect(result.value.descriptor.query_fingerprint_base64).toBe(
      crypto.createHash('sha256').update('format=full&q').digest('base64')
    );
  });

  it('rejects empty query key', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?=1';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_query_key_not_allowlisted');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects invalid percent encoding', () => {
    const input = buildBaseInput();
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/%zz';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_percent_encoding_invalid');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects invalid header values', () => {
    const input = buildBaseInput();
    input.execute_request.request.headers = [{name: 'accept', value: 'line1\r\nline2'}];

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_header_value_invalid');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects invalid header names', () => {
    const input = buildBaseInput();
    input.execute_request.request.headers = [{name: 'bad header', value: 'x'}];

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_header_name_invalid');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects invalid body base64 when digest is required', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'POST';
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send?q=ok';
    input.execute_request.request.headers = [{name: 'content-type', value: 'application/json'}];
    input.execute_request.request.body_base64 = '!!!not-base64!!!';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_body_base64_invalid');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects body without content-type when body is present', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'POST';
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send?q=ok';
    input.execute_request.request.headers = [{name: 'accept', value: 'application/json'}];
    input.execute_request.request.body_base64 = Buffer.from('{"ok":true}', 'utf8').toString('base64');

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_content_type_missing');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects body with disallowed content-type', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'POST';
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send?q=ok';
    input.execute_request.request.headers = [{name: 'content-type', value: 'text/plain'}];
    input.execute_request.request.body_base64 = Buffer.from('{"ok":true}', 'utf8').toString('base64');

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_content_type_not_allowed');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects request body when group has no allowed content-types', () => {
    const input = buildBaseInput();
    input.template.path_groups[0].body_policy.max_bytes = 16;
    input.execute_request.request.headers = [{name: 'content-type', value: 'application/json'}];
    input.execute_request.request.body_base64 = Buffer.from('{}', 'utf8').toString('base64');

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_content_type_not_allowed');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('accepts content-type parameters when media type is allowlisted', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'POST';
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send?q=ok';
    input.execute_request.request.headers = [
      {name: 'content-type', value: 'application/json; charset=utf-8'}
    ];
    input.execute_request.request.body_base64 = Buffer.from('{"ok":true}', 'utf8').toString('base64');

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.descriptor.body_sha256_base64).toBe(
      crypto.createHash('sha256').update('{"ok":true}').digest('base64')
    );
  });

  it('rejects body that exceeds max_bytes policy', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'POST';
    input.execute_request.request.url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send?q=ok';
    input.execute_request.request.headers = [{name: 'content-type', value: 'application/json'}];
    input.execute_request.request.body_base64 = Buffer.from('{"long":"value"}', 'utf8').toString('base64');
    input.template.path_groups[1].body_policy.max_bytes = 4;

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('request_body_too_large');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects requests with no matching method/path group', () => {
    const input = buildBaseInput();
    input.execute_request.request.method = 'DELETE';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('no_matching_group');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('rejects when context integration does not match execute request integration', () => {
    const input = buildBaseInput();
    input.context.integration_id = 'i_context_mismatch';

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('request_integration_mismatch');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('returns invalid_input for malformed payloads', () => {
    const result = canonicalizeExecuteRequest({
      context: {tenant_id: 't_123', workload_id: 'w_456', integration_id: 'i_789'},
      template: buildTemplate(),
      execute_request: {
        integration_id: 'i_789',
        request: {
          method: 'GET',
          url: 'not-a-url',
          headers: []
        }
      }
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('invalid_input');
    expect(result.error.message.length).toBeGreaterThan(0);
  });

  it('returns template validation errors when template violates canonicalizer constraints', () => {
    const input = buildBaseInput();
    input.template.allowed_hosts = ['*.googleapis.com'];

    const result = canonicalizeExecuteRequest(input);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('template_host_wildcard_forbidden');
    expect(result.error.message.length).toBeGreaterThan(0);
  });
});
