import {describe, expect, it} from 'vitest';

import {
  createAesGcmKeyManagementService,
  decryptSecretMaterial,
  decryptWithEnvelope,
  encryptSecretMaterial,
  encryptWithEnvelope
} from '../index';

const createKmsOrThrow = () => {
  const kms = createAesGcmKeyManagementService({
    active_key_id: 'kek_v1',
    keys: {
      kek_v1: Buffer.alloc(32, 1).toString('base64'),
      kek_v2: Buffer.alloc(32, 2).toString('base64')
    }
  });

  if (!kms.ok) {
    throw new Error(kms.error.message);
  }

  return kms.value;
};

describe('envelope encryption', () => {
  it('encrypts and decrypts secret material with AAD context', async () => {
    const aad = Buffer.from('tenant:t_123|integration:i_123');
    const kms = createKmsOrThrow();

    const encrypted = await encryptSecretMaterial({
      secret_material: {
        type: 'api_key',
        value: 'sk-live-123'
      },
      key_management_service: kms,
      requested_key_id: 'kek_v2',
      aad
    });

    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    expect(encrypted.value.envelope.key_id).toBe('kek_v2');
    expect(encrypted.value.envelope.content_encryption_alg).toBe('A256GCM');
    expect(encrypted.value.envelope.key_encryption_alg).toBe('A256GCMKW');

    const decrypted = await decryptSecretMaterial({
      encrypted_secret_material: encrypted.value,
      key_management_service: kms,
      expected_aad: aad
    });

    expect(decrypted.ok).toBe(true);
    if (!decrypted.ok) {
      return;
    }

    expect(decrypted.value).toEqual({
      type: 'api_key',
      value: 'sk-live-123'
    });
  });

  it('fails closed on aad mismatch', async () => {
    const kms = createKmsOrThrow();
    const encrypted = await encryptSecretMaterial({
      secret_material: {
        type: 'oauth_refresh_token',
        value: 'refresh-token'
      },
      key_management_service: kms,
      aad: Buffer.from('tenant:t_123')
    });

    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const decrypted = await decryptSecretMaterial({
      encrypted_secret_material: encrypted.value,
      key_management_service: kms,
      expected_aad: Buffer.from('tenant:t_999')
    });

    expect(decrypted.ok).toBe(false);
    if (decrypted.ok) {
      return;
    }

    expect(decrypted.error.code).toBe('aad_mismatch');
  });

  it('fails closed when ciphertext is tampered', async () => {
    const kms = createKmsOrThrow();
    const encrypted = await encryptWithEnvelope({
      plaintext: Buffer.from('sensitive-value'),
      key_management_service: kms
    });

    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const tampered = {
      ...encrypted.value,
      ciphertext_b64: `${encrypted.value.ciphertext_b64.slice(0, -2)}AA`
    };

    const decrypted = await decryptWithEnvelope({
      envelope: tampered,
      key_management_service: kms
    });

    expect(decrypted.ok).toBe(false);
    if (decrypted.ok) {
      return;
    }

    expect(decrypted.error.code).toBe('decrypt_auth_failed');
  });

  it('rejects invalid key material during KMS bootstrap', () => {
    const kms = createAesGcmKeyManagementService({
      active_key_id: 'kek_v1',
      keys: {
        kek_v1: Buffer.alloc(16, 1).toString('base64')
      }
    });

    expect(kms.ok).toBe(false);
    if (kms.ok) {
      return;
    }

    expect(kms.error.code).toBe('invalid_key_length');
  });
});
