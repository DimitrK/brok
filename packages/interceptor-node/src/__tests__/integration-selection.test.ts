import {describe, expect, it} from 'vitest';

import {resolveInterceptionTarget, validateIntegrationOverridesAgainstManifest} from '../integration-selection.js';
import type {IntegrationOverride, ParsedManifest} from '../types.js';

function createManifest(): ParsedManifest {
  return {
    manifest_version: 1,
    issued_at: '2026-03-01T00:00:00Z',
    expires_at: '2026-03-02T00:00:00Z',
    broker_execute_url: 'https://broker.example.com/v1/execute',
    match_rules: [
      {
        integration_id: 'int_default',
        provider: 's3-compatible',
        match: {
          hosts: ['bucket.s3.example.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/']
        },
        rewrite: {
          mode: 'execute',
          send_intended_url: true
        }
      },
      {
        integration_id: 'int_backup',
        provider: 's3-compatible',
        match: {
          hosts: ['bucket.s3.example.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/']
        },
        rewrite: {
          mode: 'execute',
          send_intended_url: true
        }
      }
    ],
    signature: {
      alg: 'EdDSA',
      kid: 'kid_1',
      jws: 'stub'
    }
  };
}

describe('validateIntegrationOverridesAgainstManifest', () => {
  it('rejects an override that references an integration absent from the manifest', () => {
    const result = validateIntegrationOverridesAgainstManifest(
      [
        {
          integrationId: 'int_missing',
          match: {
            hosts: ['bucket.s3.example.com'],
            schemes: ['https'],
            ports: [443],
            path_groups: ['/']
          }
        }
      ],
      createManifest()
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('unknown integration_id');
    }
  });
});

describe('resolveInterceptionTarget', () => {
  it('falls back to manifest-first-match when no override is configured', () => {
    const result = resolveInterceptionTarget('https://bucket.s3.example.com/?list-type=2', createManifest(), undefined);

    expect(result.matched).toBe(true);
    if (result.matched) {
      expect(result.integrationId).toBe('int_default');
      expect(result.source).toBe('manifest');
    }
  });

  it('uses an explicit override when multiple manifest rules match the same request', () => {
    const overrides: IntegrationOverride[] = [
      {
        integrationId: 'int_backup',
        match: {
          hosts: ['bucket.s3.example.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/']
        }
      }
    ];

    const result = resolveInterceptionTarget('https://bucket.s3.example.com/?list-type=2&prefix=backups%2F', createManifest(), overrides);

    expect(result.matched).toBe(true);
    if (result.matched) {
      expect(result.integrationId).toBe('int_backup');
      expect(result.source).toBe('override');
    }
  });

  it('fails closed when an override matches the request but the manifest does not allow that integration for the URL', () => {
    const overrides: IntegrationOverride[] = [
      {
        integrationId: 'int_backup',
        match: {
          hosts: ['bucket.s3.example.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/backups/*']
        }
      }
    ];

    const result = resolveInterceptionTarget('https://bucket.s3.example.com/backups/2026-03-01/archive.tar.gz', createManifest(), overrides);

    expect(result.matched).toBe(false);
    if (!result.matched && result.source === 'override') {
      expect(result.source).toBe('override');
      expect(result.error).toContain('no manifest rule matched');
    }
  });

  it('fails closed when multiple overrides match the same request', () => {
    const overrides: IntegrationOverride[] = [
      {
        integrationId: 'int_default',
        match: {
          hosts: ['bucket.s3.example.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/']
        }
      },
      {
        integrationId: 'int_backup',
        match: {
          hosts: ['bucket.s3.example.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/']
        }
      }
    ];

    const result = resolveInterceptionTarget('https://bucket.s3.example.com/?list-type=2', createManifest(), overrides);

    expect(result.matched).toBe(false);
    if (!result.matched && result.source === 'override') {
      expect(result.source).toBe('override');
      expect(result.error).toContain('Multiple integration overrides matched request');
    }
  });
});
