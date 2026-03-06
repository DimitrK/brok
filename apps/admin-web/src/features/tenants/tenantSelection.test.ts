import {describe, expect, it} from 'vitest';

import {resolveAutoSelectedTenantId} from './tenantSelection';

describe('resolveAutoSelectedTenantId', () => {
  it('returns undefined when unauthenticated', () => {
    expect(
      resolveAutoSelectedTenantId({
        isAuthenticated: false,
        tenantIds: ['t_only'],
        selectedTenantId: undefined
      })
    ).toBeUndefined();
  });

  it('returns single tenant id when authenticated and nothing is selected', () => {
    expect(
      resolveAutoSelectedTenantId({
        isAuthenticated: true,
        tenantIds: ['t_only'],
        selectedTenantId: undefined
      })
    ).toBe('t_only');
  });

  it('returns undefined when selected tenant already matches the only tenant', () => {
    expect(
      resolveAutoSelectedTenantId({
        isAuthenticated: true,
        tenantIds: ['t_only'],
        selectedTenantId: 't_only'
      })
    ).toBeUndefined();
  });

  it('returns the only tenant id when selection is stale', () => {
    expect(
      resolveAutoSelectedTenantId({
        isAuthenticated: true,
        tenantIds: ['t_only'],
        selectedTenantId: 't_stale'
      })
    ).toBe('t_only');
  });

  it('returns undefined when multiple tenants are available', () => {
    expect(
      resolveAutoSelectedTenantId({
        isAuthenticated: true,
        tenantIds: ['t_a', 't_b'],
        selectedTenantId: undefined
      })
    ).toBeUndefined();
  });
});
