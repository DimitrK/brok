import {describe, expect, it} from 'vitest';

import * as auth from '../index';

describe('index exports', () => {
  it('re-exports auth package surface', () => {
    expect(typeof auth.verifyDpopProofJwt).toBe('function');
    expect(typeof auth.verifyDpopClaimsOnly).toBe('function');
    expect(typeof auth.verifyOidcAccessToken).toBe('function');
    expect(typeof auth.extractAdminClaims).toBe('function');
    expect(typeof auth.validateIssuerAudience).toBe('function');
    expect(typeof auth.issueSession).toBe('function');
    expect(typeof auth.createMtlsMiddleware).toBe('function');
    expect(typeof auth.buildVaultRoleSpec).toBe('function');
    expect(typeof auth.parseAndValidateCsr).toBe('function');
  });
});
