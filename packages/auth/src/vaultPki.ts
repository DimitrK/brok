import type {VaultPkiClient, VaultRoleSpec} from './types';

const stableStringify = (value: unknown): string => {
  if (!value || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a.localeCompare(b)
  );
  return `{${entries.map(([key, val]) => `${JSON.stringify(key)}:${stableStringify(val)}`).join(',')}}`;
};

export const buildVaultRoleSpec = ({
  allowedUriSans,
  ttl,
  maxTtl
}: {
  allowedUriSans: string;
  ttl?: string;
  maxTtl?: string;
}): VaultRoleSpec => ({
  allowed_uri_sans: allowedUriSans,
  allow_any_name: false,
  allow_ip_sans: false,
  ttl,
  max_ttl: maxTtl
});

export const computeRoleUpdate = ({
  currentRole,
  desiredRole
}: {
  currentRole: VaultRoleSpec | null;
  desiredRole: VaultRoleSpec;
}) => {
  if (!currentRole) {
    return {needsUpdate: true, desiredRole};
  }

  const currentString = stableStringify(currentRole);
  const desiredString = stableStringify(desiredRole);
  return {needsUpdate: currentString !== desiredString, desiredRole};
};

export const isUnsafeVaultPolicy = ({policyText}: {policyText: string}) => {
  const lowered = policyText.toLowerCase();
  const unsafeEndpoints = ['sign-verbatim', 'sign-intermediate', 'sign-self-issued'];
  const hasUnsafe = unsafeEndpoints.some(endpoint => lowered.includes(endpoint));
  const hasIssuerOverride = /(?:^|\/)pki\/issuer\/.+\/sign\//.test(lowered);
  return hasUnsafe || hasIssuerOverride;
};

export const validateVaultPolicy = ({policyText}: {policyText: string}) =>
  isUnsafeVaultPolicy({policyText}) ? {ok: false, error: 'vault_policy_unsafe'} : {ok: true};

export const signCsrWithVault = ({
  client,
  roleName,
  csrPem
}: {
  client: VaultPkiClient;
  roleName: string;
  csrPem: string;
}) => client.signCsr({roleName, csrPem});
