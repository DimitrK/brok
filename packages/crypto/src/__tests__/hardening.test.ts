import {describe, expect, it} from 'vitest';

import {
  buildManifestKeySet,
  computeManifestKeysEtag,
  createAesGcmKeyManagementService,
  decodeBase64,
  decryptWithEnvelope,
  encryptWithEnvelope,
  generateKeyId,
  generateManifestSigningKeyPair,
  signManifest,
  UnsignedManifestSchema,
  verifyManifestSignature
} from '../index';

const createUnsignedManifest = () =>
  UnsignedManifestSchema.parse({
    manifest_version: 1,
    issued_at: '2026-02-07T10:00:00Z',
    expires_at: '2026-02-07T10:10:00Z',
    broker_execute_url: 'https://broker.example/v1/execute',
    match_rules: [
      {
        integration_id: 'i_openai_01',
        provider: 'openai',
        match: {
          hosts: ['api.openai.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['openai_responses']
        },
        rewrite: {
          mode: 'execute',
          send_intended_url: true
        }
      }
    ]
  });

describe('hardening checks', () => {
  it('rejects oversized local KMS keyrings', () => {
    const keys: Record<string, string> = {};
    for (let index = 0; index <= 128; index += 1) {
      keys[`kek_${index}`] = Buffer.alloc(32, index % 255).toString('base64');
    }

    const kms = createAesGcmKeyManagementService({
      active_key_id: 'kek_0',
      keys
    });

    expect(kms.ok).toBe(false);
    if (kms.ok) {
      return;
    }

    expect(kms.error.code).toBe('invalid_input');
  });

  it('rejects malformed base64 values', () => {
    expect(decodeBase64('%%%')).toBeNull();
    expect(decodeBase64('abcde')).toBeNull();
  });

  it('returns invalid key id for unsupported prefix characters', () => {
    const generated = generateKeyId({prefix: 'bad prefix '});
    expect(generated.ok).toBe(false);
    if (generated.ok) {
      return;
    }

    expect(generated.error.code).toBe('invalid_key_id');
  });

  it('rejects invalid key material and invalid requested key ids', async () => {
    const invalidKms = createAesGcmKeyManagementService({
      active_key_id: 'kek_v1',
      keys: {
        kek_v1: 'not-valid-base64'
      }
    });
    expect(invalidKms.ok).toBe(false);
    if (invalidKms.ok) {
      return;
    }

    expect(invalidKms.error.code).toBe('invalid_base64');

    const validKms = createAesGcmKeyManagementService({
      active_key_id: 'kek_v1',
      keys: {
        kek_v1: Buffer.alloc(32, 1).toString('base64')
      }
    });
    expect(validKms.ok).toBe(true);
    if (!validKms.ok) {
      return;
    }

    const encrypted = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: validKms.value,
      requested_key_id: 'bad key id'
    });

    expect(encrypted.ok).toBe(false);
    if (encrypted.ok) {
      return;
    }

    expect(encrypted.error.code).toBe('invalid_key_id');
  });

  it('fails KMS bootstrap when active key id is missing from keyring', () => {
    const kms = createAesGcmKeyManagementService({
      active_key_id: 'kek_missing',
      keys: {
        kek_v1: Buffer.alloc(32, 1).toString('base64')
      }
    });

    expect(kms.ok).toBe(false);
    if (kms.ok) {
      return;
    }

    expect(kms.error.code).toBe('kms_key_not_found');
  });

  it('rejects malformed manifest verification keys at key-set build boundary', () => {
    const keySet = buildManifestKeySet({
      keys: [
        {
          kid: 'manifest_v1',
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          use: 'sig'
        } as never
      ]
    });

    expect(keySet.ok).toBe(false);
    if (keySet.ok) {
      return;
    }

    expect(keySet.error.code).toBe('invalid_input');
  });

  it('rejects manifest key-sets with duplicate key ids', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const keySet = buildManifestKeySet({
      keys: [keyPair.value.public_key, keyPair.value.public_key]
    });

    expect(keySet.ok).toBe(false);
    if (keySet.ok) {
      return;
    }

    expect(keySet.error.code).toBe('manifest_key_mismatch');
  });

  it('rejects manifests signed with unsupported signature algorithms', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const signed = await signManifest({
      manifest: createUnsignedManifest(),
      signing_key: keyPair.value.private_key
    });
    expect(signed.ok).toBe(true);
    if (!signed.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: {
        ...signed.value,
        signature: {
          ...signed.value.signature,
          alg: 'HS256'
        }
      },
      manifest_keys: {
        keys: [keyPair.value.public_key]
      },
      now: new Date('2026-02-07T10:05:00Z')
    });

    expect(verified.ok).toBe(false);
    if (verified.ok) {
      return;
    }

    expect(verified.error.code).toBe('invalid_algorithm');
  });

  it('rejects out-of-policy manifest clock skew windows', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const signed = await signManifest({
      manifest: createUnsignedManifest(),
      signing_key: keyPair.value.private_key
    });
    expect(signed.ok).toBe(true);
    if (!signed.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: signed.value,
      manifest_keys: {
        keys: [keyPair.value.public_key]
      },
      now: new Date('2026-02-07T10:05:00Z'),
      max_clock_skew_seconds: 301
    });

    expect(verified.ok).toBe(false);
    if (verified.ok) {
      return;
    }

    expect(verified.error.code).toBe('invalid_input');
  });

  it('rejects oversized manifest JWS inputs before verification', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const signed = await signManifest({
      manifest: createUnsignedManifest(),
      signing_key: keyPair.value.private_key
    });
    expect(signed.ok).toBe(true);
    if (!signed.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: {
        ...signed.value,
        signature: {
          ...signed.value.signature,
          jws: 'a'.repeat(524_289)
        }
      },
      manifest_keys: {
        keys: [keyPair.value.public_key]
      },
      now: new Date('2026-02-07T10:05:00Z')
    });

    expect(verified.ok).toBe(false);
    if (verified.ok) {
      return;
    }

    expect(verified.error.code).toBe('invalid_input');
  });

  it('rejects oversized manifest payloads before signing', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const oversizedManifest = UnsignedManifestSchema.parse({
      manifest_version: 1,
      issued_at: '2026-02-07T10:00:00Z',
      expires_at: '2026-02-07T10:10:00Z',
      broker_execute_url: 'https://broker.example/v1/execute',
      match_rules: [
        {
          integration_id: 'i_openai_01',
          provider: 'openai',
          match: {
            hosts: ['api.openai.com'],
            schemes: ['https'],
            ports: [443],
            path_groups: ['x'.repeat(300_000)]
          },
          rewrite: {
            mode: 'execute',
            send_intended_url: true
          }
        }
      ]
    });

    const signed = await signManifest({
      manifest: oversizedManifest,
      signing_key: keyPair.value.private_key
    });

    expect(signed.ok).toBe(false);
    if (signed.ok) {
      return;
    }

    expect(signed.error.code).toBe('manifest_invalid');
  });

  it('rejects envelope inputs that exceed payload size limits', async () => {
    const kms = createAesGcmKeyManagementService({
      active_key_id: 'kek_v1',
      keys: {
        kek_v1: Buffer.alloc(32, 1).toString('base64')
      }
    });
    expect(kms.ok).toBe(true);
    if (!kms.ok) {
      return;
    }

    const oversizeAadEncrypt = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: kms.value,
      aad: Buffer.alloc(16_385, 1)
    });
    expect(oversizeAadEncrypt.ok).toBe(false);
    if (!oversizeAadEncrypt.ok) {
      expect(oversizeAadEncrypt.error.code).toBe('invalid_input');
    }

    const encrypted = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: kms.value
    });
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const oversizedCiphertextEnvelope = {
      ...encrypted.value,
      ciphertext_b64: Buffer.alloc(1_048_577, 7).toString('base64')
    };
    const oversizeCiphertextDecrypt = await decryptWithEnvelope({
      envelope: oversizedCiphertextEnvelope,
      key_management_service: kms.value
    });
    expect(oversizeCiphertextDecrypt.ok).toBe(false);
    if (!oversizeCiphertextDecrypt.ok) {
      expect(oversizeCiphertextDecrypt.error.code).toBe('invalid_envelope_payload');
    }

    const oversizeExpectedAad = await decryptWithEnvelope({
      envelope: encrypted.value,
      key_management_service: kms.value,
      expected_aad: Buffer.alloc(16_385, 1)
    });
    expect(oversizeExpectedAad.ok).toBe(false);
    if (!oversizeExpectedAad.ok) {
      expect(oversizeExpectedAad.error.code).toBe('invalid_input');
    }
  });

  it('computes deterministic key-set etags', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const etagOne = computeManifestKeysEtag({
      manifest_keys: {
        keys: [keyPair.value.public_key]
      }
    });
    const etagTwo = computeManifestKeysEtag({
      manifest_keys: {
        keys: [keyPair.value.public_key]
      }
    });

    expect(etagOne.ok).toBe(true);
    expect(etagTwo.ok).toBe(true);
    if (!etagOne.ok || !etagTwo.ok) {
      return;
    }

    expect(etagOne.value).toBe(etagTwo.value);
  });
});
