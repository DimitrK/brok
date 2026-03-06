import {afterEach, describe, expect, it, vi} from 'vitest';

vi.mock('../manifest.js', () => ({
  fetchManifest: vi.fn(),
  startManifestRefresh: vi.fn(() => setInterval(() => undefined, 60_000))
}));

vi.mock('../patch-http.js', () => ({
  applyPatches: vi.fn(),
  removePatches: vi.fn(),
  updateState: vi.fn()
}));

vi.mock('../patch-fetch.js', () => ({
  applyFetchPatch: vi.fn(),
  removeFetchPatch: vi.fn(),
  updateFetchState: vi.fn()
}));

vi.mock('../patch-child-process.js', () => ({
  applyChildProcessPatches: vi.fn(),
  removeChildProcessPatches: vi.fn(),
  updateChildProcessState: vi.fn()
}));

vi.mock('../session.js', () => ({
  SessionManager: class SessionManager {},
  canCreateSessionManager: vi.fn(() => false)
}));

import {fetchManifest} from '../manifest.js';
import {getManifest, initializeInterceptor, refreshManifest, shutdownInterceptor} from '../index.js';
import type {ParsedManifest} from '../types.js';

function createManifest(integrationIds: string[]): ParsedManifest {
  return {
    manifest_version: 1,
    issued_at: '2026-03-01T00:00:00Z',
    expires_at: '2026-03-02T00:00:00Z',
    broker_execute_url: 'https://broker.example.com/v1/execute',
    match_rules: integrationIds.map(integrationId => ({
      integration_id: integrationId,
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
    })),
    signature: {
      alg: 'EdDSA',
      kid: 'kid_1',
      jws: 'stub'
    }
  };
}

describe('refreshManifest', () => {
  const mockedFetchManifest = vi.mocked(fetchManifest);

  afterEach(() => {
    shutdownInterceptor();
    vi.clearAllMocks();
  });

  it('fails closed when a manual refresh returns a manifest incompatible with configured integration overrides', async () => {
    const initialManifest = createManifest(['int_backup']);
    const refreshedManifest = createManifest(['int_default']);

    mockedFetchManifest
      .mockResolvedValueOnce({ok: true, manifest: initialManifest, keys: {keys: []}})
      .mockResolvedValueOnce({ok: true, manifest: refreshedManifest, keys: {keys: []}});

    const initResult = await initializeInterceptor({
      brokerUrl: 'https://broker.example.com',
      workloadId: 'w_test',
      sessionToken: 'sess_test',
      integrationOverrides: [
        {
          integrationId: 'int_backup',
          match: {
            hosts: ['bucket.s3.example.com'],
            path_groups: ['/']
          }
        }
      ]
    });

    expect(initResult.ok).toBe(true);
    expect(getManifest()?.match_rules[0]?.integration_id).toBe('int_backup');

    const refreshResult = await refreshManifest();

    expect(refreshResult.ok).toBe(false);
    if (!refreshResult.ok) {
      expect(refreshResult.error).toContain('unknown integration_id');
    }
    expect(getManifest()?.match_rules[0]?.integration_id).toBe('int_backup');
  });
});
