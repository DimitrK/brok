import {describe, expect, it} from 'vitest';

import {
  acquireCryptoRotationLock_INCOMPLETE,
  createCryptoStorageService_INCOMPLETE,
  createManifestSigningKeyRecord_INCOMPLETE,
  createSecretEnvelopeVersion_INCOMPLETE,
  getActiveManifestSigningKeyRecord_INCOMPLETE,
  getCryptoVerificationDefaultsByTenant_INCOMPLETE,
  getActiveSecretEnvelope_INCOMPLETE,
  getSecretEnvelopeVersion_INCOMPLETE,
  listManifestVerificationKeysWithEtag_INCOMPLETE,
  persistManifestKeysetMetadata_INCOMPLETE,
  releaseCryptoRotationLock_INCOMPLETE,
  retireManifestSigningKey_INCOMPLETE,
  revokeManifestSigningKey_INCOMPLETE,
  rotateManifestSigningKeysWithStore_INCOMPLETE,
  setActiveManifestSigningKey_INCOMPLETE,
  setActiveSecretEnvelopeVersion_INCOMPLETE,
  upsertCryptoVerificationDefaults_INCOMPLETE
} from '../index';

describe('storage integration placeholders', () => {
  it('fails closed for every db-dependent _INCOMPLETE method', () => {
    const placeholderResults = [
      createSecretEnvelopeVersion_INCOMPLETE({
        secret_ref: 'secret_1',
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        secret_type: 'api_key',
        envelope: {
          version: 1,
          content_encryption_alg: 'A256GCM',
          key_encryption_alg: 'A256GCMKW',
          key_id: 'kek_v1',
          wrapped_data_key_b64: Buffer.from('wrapped').toString('base64'),
          iv_b64: Buffer.alloc(12, 1).toString('base64'),
          ciphertext_b64: Buffer.from('ciphertext').toString('base64'),
          auth_tag_b64: Buffer.alloc(16, 2).toString('base64')
        },
        created_at: '2026-02-08T00:00:00Z'
      }),
      getActiveSecretEnvelope_INCOMPLETE({secret_ref: 'secret_1'}),
      getSecretEnvelopeVersion_INCOMPLETE({secret_ref: 'secret_1', version: 1}),
      setActiveSecretEnvelopeVersion_INCOMPLETE({secret_ref: 'secret_1', version: 1}),
      createManifestSigningKeyRecord_INCOMPLETE({
        kid: 'manifest_v1',
        alg: 'EdDSA',
        public_jwk: {
          kid: 'manifest_v1',
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'abc123',
          alg: 'EdDSA',
          use: 'sig'
        },
        private_key_ref: 'kms://signing/manifest_v1',
        created_at: '2026-02-08T00:00:00Z'
      }),
      getActiveManifestSigningKeyRecord_INCOMPLETE(),
      setActiveManifestSigningKey_INCOMPLETE({
        kid: 'manifest_v1',
        activated_at: '2026-02-08T00:00:00Z'
      }),
      retireManifestSigningKey_INCOMPLETE({
        kid: 'manifest_v1',
        retired_at: '2026-02-08T00:00:00Z'
      }),
      revokeManifestSigningKey_INCOMPLETE({
        kid: 'manifest_v1',
        revoked_at: '2026-02-08T00:00:00Z'
      }),
      listManifestVerificationKeysWithEtag_INCOMPLETE(),
      persistManifestKeysetMetadata_INCOMPLETE({
        etag: 'W/"etag_1"',
        generated_at: '2026-02-08T00:00:00Z',
        max_age_seconds: 120
      }),
      acquireCryptoRotationLock_INCOMPLETE({lock_name: 'crypto_rotation', ttl_ms: 30000}),
      releaseCryptoRotationLock_INCOMPLETE({lock_name: 'crypto_rotation', token: 'token_1'}),
      getCryptoVerificationDefaultsByTenant_INCOMPLETE({
        tenant_id: 'tenant_1'
      }),
      upsertCryptoVerificationDefaults_INCOMPLETE({
        tenant_id: 'tenant_1',
        require_temporal_validity: true,
        max_clock_skew_seconds: 0
      }),
      rotateManifestSigningKeysWithStore_INCOMPLETE({
        current_manifest_keys: {
          keys: []
        },
        signing_alg: 'EdDSA',
        retain_previous_key_count: 0
      })
    ];

    for (const result of placeholderResults) {
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe('dependency_not_configured');
        expect(result.error.message.includes('_INCOMPLETE')).toBe(true);
      }
    }
  });

  it('uses app-injected repositories and forwards transaction context', async () => {
    const transactionClient = {tx_id: 'tx_1'};
    const service = createCryptoStorageService_INCOMPLETE({
      createSecretEnvelopeVersion: (_input, context) => {
        expect(context?.transaction_client).toBe(transactionClient);
        return {
          ok: true,
          value: {
            secret_ref: 'secret_1',
            tenant_id: 'tenant_1',
            integration_id: 'integration_1',
            secret_type: 'api_key',
            version: 1,
            envelope: {
              version: 1,
              content_encryption_alg: 'A256GCM',
              key_encryption_alg: 'A256GCMKW',
              key_id: 'kek_v1',
              wrapped_data_key_b64: Buffer.from('wrapped').toString('base64'),
              iv_b64: Buffer.alloc(12, 1).toString('base64'),
              ciphertext_b64: Buffer.from('ciphertext').toString('base64'),
              auth_tag_b64: Buffer.alloc(16, 2).toString('base64')
            },
            created_at: '2026-02-08T00:00:00Z'
          }
        } as const;
      },
      getActiveManifestSigningKeyRecord: context => {
        expect(context?.transaction_client).toBe(transactionClient);
        return {
          ok: true,
          value: {
            kid: 'manifest_v1',
            alg: 'EdDSA',
            public_jwk: {
              kid: 'manifest_v1',
              kty: 'OKP',
              crv: 'Ed25519',
              x: 'abc123',
              alg: 'EdDSA',
              use: 'sig'
            },
            private_key_ref: 'kms://signing/manifest_v1',
            status: 'active',
            created_at: '2026-02-08T00:00:00Z',
            activated_at: '2026-02-08T00:00:00Z'
          }
        } as const;
      },
      getCryptoVerificationDefaultsByTenant: (_input, context) => {
        expect(context?.transaction_client).toBe(transactionClient);
        return {
          ok: true,
          value: {
            tenant_id: 'tenant_1',
            require_temporal_validity: true,
            max_clock_skew_seconds: 0
          }
        } as const;
      }
    });

    const created = await service.createSecretEnvelopeVersion_INCOMPLETE(
      {
        secret_ref: 'secret_1',
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        secret_type: 'api_key',
        envelope: {
          version: 1,
          content_encryption_alg: 'A256GCM',
          key_encryption_alg: 'A256GCMKW',
          key_id: 'kek_v1',
          wrapped_data_key_b64: Buffer.from('wrapped').toString('base64'),
          iv_b64: Buffer.alloc(12, 1).toString('base64'),
          ciphertext_b64: Buffer.from('ciphertext').toString('base64'),
          auth_tag_b64: Buffer.alloc(16, 2).toString('base64')
        },
        created_at: '2026-02-08T00:00:00Z'
      },
      {transaction_client: transactionClient}
    );
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    expect(created.value.version).toBe(1);

    const activeKey = await service.getActiveManifestSigningKeyRecord_INCOMPLETE({
      transaction_client: transactionClient
    });
    expect(activeKey.ok).toBe(true);
    if (!activeKey.ok || activeKey.value === null) {
      return;
    }

    expect(activeKey.value.kid).toBe('manifest_v1');

    const defaults = await service.getCryptoVerificationDefaultsByTenant_INCOMPLETE(
      {
        tenant_id: 'tenant_1'
      },
      {transaction_client: transactionClient}
    );
    expect(defaults.ok).toBe(true);
    if (!defaults.ok) {
      return;
    }

    expect(defaults.value.max_clock_skew_seconds).toBe(0);
  });

  it('preserves not-found envelope lookups as successful null results', async () => {
    const service = createCryptoStorageService_INCOMPLETE({
      getActiveSecretEnvelope: () => ({
        ok: true,
        value: null
      }),
      getSecretEnvelopeVersion: () => ({
        ok: true,
        value: null
      }),
      getActiveManifestSigningKeyRecord: () => ({
        ok: true,
        value: null
      }),
      listManifestVerificationKeysWithEtag: () => ({
        ok: true,
        value: null
      })
    });

    const active = await service.getActiveSecretEnvelope_INCOMPLETE({
      secret_ref: 'secret_1'
    });
    expect(active.ok).toBe(true);
    if (!active.ok) {
      return;
    }

    expect(active.value).toBeNull();

    const version = await service.getSecretEnvelopeVersion_INCOMPLETE({
      secret_ref: 'secret_1',
      version: 99
    });
    expect(version.ok).toBe(true);
    if (!version.ok) {
      return;
    }

    expect(version.value).toBeNull();

    const activeKey = await service.getActiveManifestSigningKeyRecord_INCOMPLETE();
    expect(activeKey.ok).toBe(true);
    if (!activeKey.ok) {
      return;
    }

    expect(activeKey.value).toBeNull();

    const keyset = await service.listManifestVerificationKeysWithEtag_INCOMPLETE();
    expect(keyset.ok).toBe(true);
    if (!keyset.ok) {
      return;
    }

    expect(keyset.value).toBeNull();
  });

  it('fails closed when an injected repository returns an invalid result shape', async () => {
    const service = createCryptoStorageService_INCOMPLETE({
      getActiveSecretEnvelope: () =>
        ({
          ok: true,
          value: {
            secret_ref: 'secret_1'
          }
        }) as never,
      getCryptoVerificationDefaultsByTenant: () =>
        ({
          ok: false,
          error: {
            code: 'not_a_real_crypto_code',
            message: 'bad'
          }
        }) as never,
      listManifestVerificationKeysWithEtag: () => {
        throw new Error('boom');
      }
    });

    const active = await service.getActiveSecretEnvelope_INCOMPLETE({
      secret_ref: 'secret_1'
    });
    expect(active.ok).toBe(false);
    if (!active.ok) {
      expect(active.error.code).toBe('invalid_repository_response');
    }

    const defaults = await service.getCryptoVerificationDefaultsByTenant_INCOMPLETE({
      tenant_id: 'tenant_1'
    });
    expect(defaults.ok).toBe(false);
    if (!defaults.ok) {
      expect(defaults.error.code).toBe('invalid_repository_response');
    }

    const listed = await service.listManifestVerificationKeysWithEtag_INCOMPLETE();
    expect(listed.ok).toBe(false);
    if (!listed.ok) {
      expect(listed.error.code).toBe('invalid_repository_response');
    }
  });

  it('fails closed from factory when repositories are not provided', async () => {
    const service = createCryptoStorageService_INCOMPLETE({});
    const listed = await service.listManifestVerificationKeysWithEtag_INCOMPLETE();

    expect(listed.ok).toBe(false);
    if (listed.ok) {
      return;
    }

    expect(listed.error.code).toBe('dependency_not_configured');
    expect(listed.error.message.includes('_INCOMPLETE')).toBe(true);

    const defaults = await service.getCryptoVerificationDefaultsByTenant_INCOMPLETE({
      tenant_id: 'tenant_1'
    });
    expect(defaults.ok).toBe(false);
    if (!defaults.ok) {
      expect(defaults.error.code).toBe('dependency_not_configured');
      expect(defaults.error.message.includes('_INCOMPLETE')).toBe(true);
    }
  });
});
