/**
 * Unit tests for the main module exports.
 */

import {describe, expect, it} from 'vitest';
import {
  initializeInterceptor,
  shutdownInterceptor,
  getManifest,
  isInitialized,
  ApprovalRequiredError,
  RequestDeniedError,
  matchUrl,
  shouldIntercept
} from '../index.js';

describe('exports', () => {
  it('exports initializeInterceptor function', () => {
    expect(typeof initializeInterceptor).toBe('function');
  });

  it('exports shutdownInterceptor function', () => {
    expect(typeof shutdownInterceptor).toBe('function');
  });

  it('exports getManifest function', () => {
    expect(typeof getManifest).toBe('function');
  });

  it('exports isInitialized function', () => {
    expect(typeof isInitialized).toBe('function');
  });

  it('exports ApprovalRequiredError class', () => {
    expect(ApprovalRequiredError).toBeDefined();
    expect(ApprovalRequiredError.prototype instanceof Error).toBe(true);
  });

  it('exports RequestDeniedError class', () => {
    expect(RequestDeniedError).toBeDefined();
    expect(RequestDeniedError.prototype instanceof Error).toBe(true);
  });

  it('exports matchUrl function', () => {
    expect(typeof matchUrl).toBe('function');
  });

  it('exports shouldIntercept function', () => {
    expect(typeof shouldIntercept).toBe('function');
  });
});

describe('isInitialized', () => {
  it('returns false when not initialized', () => {
    // Ensure we're in a clean state
    shutdownInterceptor();

    expect(isInitialized()).toBe(false);
  });
});

describe('getManifest', () => {
  it('returns null when not initialized', () => {
    // Ensure we're in a clean state
    shutdownInterceptor();

    expect(getManifest()).toBeNull();
  });
});

describe('initializeInterceptor', () => {
  it('rejects invalid config', async () => {
    const result = await initializeInterceptor({
      brokerUrl: 'not-a-url',
      workloadId: 'w_test',
      sessionToken: 'test'
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Invalid config');
    }
  });

  it('rejects empty sessionToken', async () => {
    const result = await initializeInterceptor({
      brokerUrl: 'https://broker.example.com',
      workloadId: 'w_test',
      sessionToken: ''
    });

    expect(result.ok).toBe(false);
  });
});

describe('shutdownInterceptor', () => {
  it('does not throw when not initialized', () => {
    expect(() => shutdownInterceptor()).not.toThrow();
  });
});
