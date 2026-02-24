import * as child_process from 'node:child_process';

import {afterEach, describe, expect, it, vi} from 'vitest';

import {applyChildProcessPatches, buildNodeOptionsWithImport, isChildProcessPatched, removeChildProcessPatches} from '../patch-child-process.js';
import type {InterceptorState, ParsedManifest, ResolvedInterceptorConfig} from '../types.js';

function createManifest(overrides?: Partial<ParsedManifest>): ParsedManifest {
  return {
    manifest_version: 1,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    broker_execute_url: 'https://broker.example.com/v1/execute',
    match_rules: [],
    signature: {
      alg: 'EdDSA',
      kid: 'k1',
      jws: 'stub'
    },
    ...overrides
  };
}

function createConfig(overrides?: Partial<ResolvedInterceptorConfig>): ResolvedInterceptorConfig {
  return {
    brokerUrl: 'https://broker.example.com',
    workloadId: 'w_test',
    sessionToken: 'tok_test',
    sessionTtlSeconds: 3600,
    manifestRefreshIntervalMs: 300000,
    failOnManifestError: true,
    manifestFailurePolicy: 'use_last_valid',
    ...overrides
  };
}

function createState(loggerOverrides?: Partial<InterceptorState['logger']>): InterceptorState {
  const manifest = createManifest();
  return {
    config: createConfig(),
    manifest,
    manifestRuntime: {
      currentManifest: manifest,
      currentManifestExpiresAt: new Date(manifest.expires_at),
      lastRefreshAttemptAt: null,
      manifestState: 'valid'
    },
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
      ...loggerOverrides
    },
    refreshTimer: null,
    initialized: true,
    sessionManager: null
  };
}

afterEach(() => {
  removeChildProcessPatches();
});

describe('buildNodeOptionsWithImport', () => {
  const importSpecifier = 'file:///tmp/preload.js';

  it('adds --import flag when NODE_OPTIONS is empty', () => {
    const result = buildNodeOptionsWithImport('', importSpecifier);
    expect(result).toBe(`--import=${importSpecifier}`);
  });

  it('appends --import flag to existing options', () => {
    const result = buildNodeOptionsWithImport('--trace-warnings', importSpecifier);
    expect(result).toContain('--trace-warnings');
    expect(result).toContain(`--import=${importSpecifier}`);
  });

  it('does not duplicate existing import flag', () => {
    const existing = `--trace-warnings --import=${importSpecifier}`;
    const result = buildNodeOptionsWithImport(existing, importSpecifier);
    expect(result).toBe(existing);
  });

  it('does not duplicate existing split --import token form', () => {
    const existing = `--trace-warnings --import ${importSpecifier}`;
    const result = buildNodeOptionsWithImport(existing, importSpecifier);
    expect(result).toBe(existing);
  });

  it('does not treat partial substring as an existing import specifier', () => {
    const existing = `--trace-warnings --conditions=${importSpecifier}`;
    const result = buildNodeOptionsWithImport(existing, importSpecifier);
    expect(result).toContain(`--conditions=${importSpecifier}`);
    expect(result).toContain(`--import=${importSpecifier}`);
  });
});

describe('child_process patch lifecycle', () => {
  it('applies and removes patches without readonly assignment warnings', () => {
    const warn = vi.fn();
    const state = createState({warn});
    const initialSpawn = child_process.spawn;

    applyChildProcessPatches(state);
    expect(isChildProcessPatched()).toBe(true);
    expect(child_process.spawn).not.toBe(initialSpawn);
    expect(warn).not.toHaveBeenCalledWith(expect.stringContaining('Cannot patch child_process.spawn'));

    removeChildProcessPatches();
    expect(isChildProcessPatched()).toBe(false);
    expect(child_process.spawn).toBe(initialSpawn);
  });
});
