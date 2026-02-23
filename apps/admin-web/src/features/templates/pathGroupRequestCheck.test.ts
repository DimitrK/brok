import {describe, expect, it} from 'vitest';

import {checkPathGroupCurlRequest, checkTemplateCurlRequest, parseCurlRequest} from './pathGroupRequestCheck';

describe('pathGroupRequestCheck', () => {
  it('parses cURL and infers POST when payload is present', () => {
    const parsed = parseCurlRequest('curl "https://api.openai.com/v1/responses" --data \'{"input":"hello"}\'');

    expect(parsed.method).toBe('POST');
    expect(parsed.host).toBe('api.openai.com');
    expect(parsed.path).toBe('/v1/responses');
  });

  it('matches a request against allowed hosts, method, and path patterns', () => {
    const result = checkPathGroupCurlRequest({
      curl: 'curl -X POST "https://api.openai.com/v1/responses"',
      allowedHosts: ['api.openai.com'],
      methods: ['POST'],
      pathPatterns: ['^/v1/responses(?:/.*)?$']
    });

    expect(result.matched).toBe(true);
    expect(result.pathMatchState).toBe('matched');
  });

  it('returns not matched when host is outside template allowlist', () => {
    const result = checkPathGroupCurlRequest({
      curl: 'curl -X POST "https://api.anthropic.com/v1/messages"',
      allowedHosts: ['api.openai.com'],
      methods: ['POST'],
      pathPatterns: ['^/v1/messages$']
    });

    expect(result.matched).toBe(false);
    expect(result.hostMatched).toBe(false);
    expect(result.reason).toMatch(/not in allowed hosts/i);
  });

  it('detects invalid regex patterns for path checks', () => {
    const result = checkPathGroupCurlRequest({
      curl: 'curl -X GET "https://api.openai.com/v1/models"',
      allowedHosts: ['api.openai.com'],
      methods: ['GET'],
      pathPatterns: ['([']
    });

    expect(result.pathMatchState).toBe('invalid_pattern');
    expect(result.invalidPatterns).toEqual(['([']);
  });

  it('ignores option URLs and uses the actual request URL', () => {
    const parsed = parseCurlRequest(
      'curl --referer "https://dashboard.example.com/path" -X POST "https://api.openai.com/v1/responses"'
    );

    expect(parsed.url).toBe('https://api.openai.com/v1/responses');
    expect(parsed.host).toBe('api.openai.com');
  });

  it('matches template when at least one path group matches', () => {
    const result = checkTemplateCurlRequest({
      curl: 'curl -X POST "https://api.openai.com/v1/responses"',
      allowedHosts: ['api.openai.com'],
      pathGroups: [
        {
          groupId: 'responses_create',
          methods: ['POST'],
          pathPatterns: ['^/v1/responses$']
        },
        {
          groupId: 'messages_create',
          methods: ['POST'],
          pathPatterns: ['^/v1/messages$']
        }
      ]
    });

    expect(result.matched).toBe(true);
    expect(result.matchedPathGroups.map(pathGroup => pathGroup.groupId)).toEqual(['responses_create']);
    expect(result.failedPathGroups.map(pathGroup => pathGroup.groupId)).toEqual(['messages_create']);
  });

  it('returns path group failures when template does not match', () => {
    const result = checkTemplateCurlRequest({
      curl: 'curl -X GET "https://api.openai.com/v1/responses"',
      allowedHosts: ['api.openai.com'],
      pathGroups: [
        {
          groupId: 'responses_create',
          methods: ['POST'],
          pathPatterns: ['^/v1/responses$']
        }
      ]
    });

    expect(result.matched).toBe(false);
    expect(result.failedPathGroups).toHaveLength(1);
    expect(result.failedPathGroups[0]?.check.reason).toMatch(/method/i);
  });
});
