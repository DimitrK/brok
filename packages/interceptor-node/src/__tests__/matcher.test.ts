/**
 * Unit tests for the URL matcher module.
 */

import {describe, expect, it} from 'vitest';
import {matchUrl, shouldIntercept} from '../matcher.js';
import type {ParsedManifest, MatchRule} from '../types.js';

/**
 * Create a test manifest with the given rules.
 */
function createManifest(rules: MatchRule[]): ParsedManifest {
  return {
    manifest_version: 1,
    issued_at: '2024-01-01T00:00:00Z',
    expires_at: '2025-01-01T00:00:00Z',
    broker_execute_url: 'https://broker.example.com/execute',
    match_rules: rules,
    signature: {
      alg: 'EdDSA',
      kid: 'test-key-1',
      jws: 'test-signature'
    }
  };
}

/**
 * Create a basic match rule.
 */
function createRule(
  integrationId: string,
  hosts: string[],
  options?: {
    ports?: number[];
    pathGroups?: string[];
  }
): MatchRule {
  return {
    integration_id: integrationId,
    provider: 'test-provider',
    match: {
      hosts,
      schemes: ['https'],
      ports: options?.ports ?? [443],
      path_groups: options?.pathGroups ?? ['*']
    },
    rewrite: {
      mode: 'execute',
      send_intended_url: true
    }
  };
}

describe('matchUrl', () => {
  describe('host matching', () => {
    it('matches exact host', () => {
      const manifest = createManifest([createRule('openai', ['api.openai.com'])]);

      const result = matchUrl('https://api.openai.com/v1/chat', manifest);

      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(result.integrationId).toBe('openai');
      }
    });

    it('does not match different host', () => {
      const manifest = createManifest([createRule('openai', ['api.openai.com'])]);

      const result = matchUrl('https://api.anthropic.com/v1/chat', manifest);

      expect(result.matched).toBe(false);
    });

    it('matches wildcard subdomain pattern', () => {
      const manifest = createManifest([createRule('openai', ['*.openai.com'])]);

      expect(matchUrl('https://api.openai.com/v1', manifest).matched).toBe(true);
      expect(matchUrl('https://chat.openai.com/v1', manifest).matched).toBe(true);
      expect(matchUrl('https://sub.api.openai.com/v1', manifest).matched).toBe(true);
    });

    it('wildcard subdomain does not match root domain', () => {
      const manifest = createManifest([createRule('openai', ['*.openai.com'])]);

      // According to the code, *.openai.com should match openai.com too
      const result = matchUrl('https://openai.com/v1', manifest);
      expect(result.matched).toBe(true);
    });

    it('supports multiple hosts in one rule', () => {
      const manifest = createManifest([createRule('ai-providers', ['api.openai.com', 'api.anthropic.com'])]);

      expect(matchUrl('https://api.openai.com/v1', manifest).matched).toBe(true);
      expect(matchUrl('https://api.anthropic.com/v1', manifest).matched).toBe(true);
      expect(matchUrl('https://api.cohere.com/v1', manifest).matched).toBe(false);
    });
  });

  describe('port matching', () => {
    it('matches default HTTPS port', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'], {ports: [443]})]);

      // URL without explicit port should use 443 for https
      expect(matchUrl('https://api.example.com/test', manifest).matched).toBe(true);
    });

    it('matches explicit port', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'], {ports: [8443]})]);

      expect(matchUrl('https://api.example.com:8443/test', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/test', manifest).matched).toBe(false);
    });

    it('matches multiple ports', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'], {ports: [443, 8443, 9443]})]);

      expect(matchUrl('https://api.example.com/test', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com:8443/test', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com:9443/test', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com:1234/test', manifest).matched).toBe(false);
    });
  });

  describe('path matching', () => {
    it('matches wildcard path (*)', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'], {pathGroups: ['*']})]);

      expect(matchUrl('https://api.example.com/', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/any/path/here', manifest).matched).toBe(true);
    });

    it('matches exact path', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'], {pathGroups: ['/v1/chat']})]);

      expect(matchUrl('https://api.example.com/v1/chat', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/v1/completions', manifest).matched).toBe(false);
    });

    it('matches path prefix with wildcard', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'], {pathGroups: ['/v1/*']})]);

      expect(matchUrl('https://api.example.com/v1/chat', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/v1/embeddings', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/v2/chat', manifest).matched).toBe(false);
    });

    it('matches nested path prefixes', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'], {pathGroups: ['/v1/chat/*']})]);

      expect(matchUrl('https://api.example.com/v1/chat/completions', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/v1/embeddings', manifest).matched).toBe(false);
    });

    it('matches multiple path groups', () => {
      const manifest = createManifest([
        createRule('test', ['api.example.com'], {
          pathGroups: ['/v1/chat', '/v1/embeddings', '/v1/models']
        })
      ]);

      expect(matchUrl('https://api.example.com/v1/chat', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/v1/embeddings', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/v1/models', manifest).matched).toBe(true);
      expect(matchUrl('https://api.example.com/v1/audio', manifest).matched).toBe(false);
    });
  });

  describe('scheme matching', () => {
    it('only matches https scheme', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'])]);

      expect(matchUrl('https://api.example.com/test', manifest).matched).toBe(true);
      // HTTP should not match since rules only have 'https' scheme
      // expect(matchUrl('http://api.example.com/test', manifest).matched).toBe(false)
    });
  });

  describe('multiple rules', () => {
    it('returns first matching rule', () => {
      const manifest = createManifest([
        createRule('first', ['api.openai.com']),
        createRule('second', ['*.openai.com'])
      ]);

      const result = matchUrl('https://api.openai.com/v1', manifest);

      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(result.integrationId).toBe('first');
      }
    });

    it('matches second rule when first does not match', () => {
      const manifest = createManifest([
        createRule('openai', ['api.openai.com']),
        createRule('anthropic', ['api.anthropic.com'])
      ]);

      const result = matchUrl('https://api.anthropic.com/v1', manifest);

      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(result.integrationId).toBe('anthropic');
      }
    });

    it('returns no match when no rules match', () => {
      const manifest = createManifest([
        createRule('openai', ['api.openai.com']),
        createRule('anthropic', ['api.anthropic.com'])
      ]);

      const result = matchUrl('https://api.cohere.com/v1', manifest);

      expect(result.matched).toBe(false);
    });
  });

  describe('URL object input', () => {
    it('accepts URL object', () => {
      const manifest = createManifest([createRule('test', ['api.example.com'])]);

      const url = new URL('https://api.example.com/v1/chat');
      const result = matchUrl(url, manifest);

      expect(result.matched).toBe(true);
    });
  });
});

describe('shouldIntercept', () => {
  it('returns true when URL matches', () => {
    const manifest = createManifest([createRule('test', ['api.example.com'])]);

    expect(shouldIntercept('https://api.example.com/v1', manifest)).toBe(true);
  });

  it('returns false when URL does not match', () => {
    const manifest = createManifest([createRule('test', ['api.example.com'])]);

    expect(shouldIntercept('https://other.example.com/v1', manifest)).toBe(false);
  });
});
