import {describe, expect, it, vi} from 'vitest';

import {
  buildVaultRoleSpec,
  computeRoleUpdate,
  isUnsafeVaultPolicy,
  signCsrWithVault,
  validateVaultPolicy
} from '../vaultPki';

describe('vaultPki', () => {
  it('buildVaultRoleSpec sets safe defaults and optional TTL fields', () => {
    const role = buildVaultRoleSpec({
      allowedUriSans: 'spiffe://tenant/workload-a',
      ttl: '10m',
      maxTtl: '1h'
    });

    expect(role).toEqual({
      allowed_uri_sans: 'spiffe://tenant/workload-a',
      allow_any_name: false,
      allow_ip_sans: false,
      ttl: '10m',
      max_ttl: '1h'
    });
  });

  it('computeRoleUpdate requires updates when current role is missing', () => {
    const desiredRole = buildVaultRoleSpec({allowedUriSans: 'spiffe://tenant/workload-a'});
    const result = computeRoleUpdate({currentRole: null, desiredRole});

    expect(result).toEqual({needsUpdate: true, desiredRole});
  });

  it('computeRoleUpdate compares role content with stable ordering', () => {
    const desiredRole = {
      allowed_uri_sans: 'spiffe://tenant/workload-a',
      allow_any_name: false,
      allow_ip_sans: false,
      ttl: '10m',
      max_ttl: '1h'
    };
    const currentRole = {
      allow_ip_sans: false,
      allow_any_name: false,
      max_ttl: '1h',
      ttl: '10m',
      allowed_uri_sans: 'spiffe://tenant/workload-a'
    };
    const result = computeRoleUpdate({currentRole, desiredRole});

    expect(result).toEqual({needsUpdate: false, desiredRole});
  });

  it('flags unsafe Vault policy endpoints and issuer override paths', () => {
    expect(
      isUnsafeVaultPolicy({
        policyText: 'path "pki/sign-verbatim/role" { capabilities = ["update"] }'
      })
    ).toBe(true);
    expect(
      isUnsafeVaultPolicy({
        policyText: 'path "/pki/issuer/issuer-a/sign/workload-role" { capabilities = ["update"] }'
      })
    ).toBe(true);
    expect(
      isUnsafeVaultPolicy({
        policyText: 'path "pki/sign/workload-role" { capabilities = ["update"] }'
      })
    ).toBe(false);
  });

  it('validateVaultPolicy returns explicit unsafe reason code', () => {
    expect(
      validateVaultPolicy({
        policyText: 'path "pki/sign-self-issued/workload-role" { capabilities = ["update"] }'
      })
    ).toEqual({ok: false, error: 'vault_policy_unsafe'});

    expect(
      validateVaultPolicy({
        policyText: 'path "pki/sign/workload-role" { capabilities = ["update"] }'
      })
    ).toEqual({ok: true});
  });

  it('signCsrWithVault passes role and csr inputs through to client', async () => {
    const signCsr = vi.fn().mockResolvedValue({
      certificatePem: 'cert',
      caChainPem: ['ca-1']
    });

    const result = await signCsrWithVault({
      client: {
        signCsr,
        readRole: () => Promise.resolve(null),
        writeRole: () => Promise.resolve()
      },
      roleName: 'workload-role',
      csrPem: '---csr---'
    });

    expect(signCsr).toHaveBeenCalledWith({roleName: 'workload-role', csrPem: '---csr---'});
    expect(result).toEqual({
      certificatePem: 'cert',
      caChainPem: ['ca-1']
    });
  });
});
