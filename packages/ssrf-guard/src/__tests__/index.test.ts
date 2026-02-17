import {describe, expect, it} from 'vitest';

import {
  SsrfGuardStorageBridge,
  createSsrfGuardStorageBridge_INCOMPLETE,
  enforceRedirectDenyPolicy,
  guardExecuteRequestDestination,
  packageName,
  ssrfGuardErrorCodes
} from '../index';

describe('index', () => {
  it('exports package metadata and main APIs', () => {
    expect(packageName).toBe('ssrf-guard');
    expect(typeof guardExecuteRequestDestination).toBe('function');
    expect(typeof enforceRedirectDenyPolicy).toBe('function');
    expect(typeof SsrfGuardStorageBridge).toBe('function');
    expect(typeof createSsrfGuardStorageBridge_INCOMPLETE).toBe('function');
    expect(ssrfGuardErrorCodes.length).toBeGreaterThan(0);
  });
});
