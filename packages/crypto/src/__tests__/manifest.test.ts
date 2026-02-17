import {describe, expect, it} from 'vitest';

import {
  buildManifestKeySet,
  generateManifestSigningKeyPair,
  rotateManifestSigningKeys,
  signManifest,
  UnsignedManifestSchema,
  verifyManifestSignature
} from '../index';

const createUnsignedManifest = ({
  issuedAt,
  expiresAt
}: {
  issuedAt: string;
  expiresAt: string;
}) => {
  return UnsignedManifestSchema.parse({
    manifest_version: 1,
    issued_at: issuedAt,
    expires_at: expiresAt,
    broker_execute_url: 'https://broker.example/v1/execute',
    dpop_required: true,
    dpop_ath_required: true,
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
};

describe('manifest signing', () => {
  it('signs and verifies manifests using EdDSA', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const manifest = createUnsignedManifest({
      issuedAt: '2026-02-07T10:00:00Z',
      expiresAt: '2026-02-07T10:10:00Z'
    });

    const signedManifest = await signManifest({
      manifest,
      signing_key: keyPair.value.private_key
    });
    expect(signedManifest.ok).toBe(true);
    if (!signedManifest.ok) {
      return;
    }

    const keySet = buildManifestKeySet({
      keys: [keyPair.value.public_key]
    });
    expect(keySet.ok).toBe(true);
    if (!keySet.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: signedManifest.value,
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T10:05:00Z')
    });

    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      return;
    }

    expect(verified.value.signing_key.kid).toBe('manifest_v1');
    expect(verified.value.unsigned_manifest.broker_execute_url).toBe(
      'https://broker.example/v1/execute'
    );
  });

  it('supports key rotation by keeping previous verification keys', async () => {
    const oldKeyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_old'
    });
    const newKeyPair = await generateManifestSigningKeyPair({
      alg: 'ES256',
      kid: 'manifest_new'
    });

    expect(oldKeyPair.ok).toBe(true);
    expect(newKeyPair.ok).toBe(true);
    if (!oldKeyPair.ok || !newKeyPair.ok) {
      return;
    }

    const signedManifest = await signManifest({
      manifest: createUnsignedManifest({
        issuedAt: '2026-02-07T10:00:00Z',
        expiresAt: '2026-02-07T10:10:00Z'
      }),
      signing_key: oldKeyPair.value.private_key
    });
    expect(signedManifest.ok).toBe(true);
    if (!signedManifest.ok) {
      return;
    }

    const rotatedKeySet = buildManifestKeySet({
      keys: [newKeyPair.value.public_key, oldKeyPair.value.public_key]
    });
    expect(rotatedKeySet.ok).toBe(true);
    if (!rotatedKeySet.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: signedManifest.value,
      manifest_keys: rotatedKeySet.value,
      now: new Date('2026-02-07T10:02:00Z')
    });

    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      return;
    }

    expect(verified.value.signing_key.kid).toBe('manifest_old');
  });

  it('fails when kid is unknown', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const signedManifest = await signManifest({
      manifest: createUnsignedManifest({
        issuedAt: '2026-02-07T10:00:00Z',
        expiresAt: '2026-02-07T10:10:00Z'
      }),
      signing_key: keyPair.value.private_key
    });
    expect(signedManifest.ok).toBe(true);
    if (!signedManifest.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: signedManifest.value,
      manifest_keys: {keys: []},
      now: new Date('2026-02-07T10:05:00Z')
    });

    expect(verified.ok).toBe(false);
    if (verified.ok) {
      return;
    }

    expect(verified.error.code).toBe('manifest_key_not_found');
  });

  it('fails when signed payload is tampered', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const signedManifest = await signManifest({
      manifest: createUnsignedManifest({
        issuedAt: '2026-02-07T10:00:00Z',
        expiresAt: '2026-02-07T10:10:00Z'
      }),
      signing_key: keyPair.value.private_key
    });
    expect(signedManifest.ok).toBe(true);
    if (!signedManifest.ok) {
      return;
    }

    const tamperedManifest = {
      ...signedManifest.value,
      broker_execute_url: 'https://attacker.example/execute'
    };

    const keySet = buildManifestKeySet({
      keys: [keyPair.value.public_key]
    });
    expect(keySet.ok).toBe(true);
    if (!keySet.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: tamperedManifest,
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T10:05:00Z')
    });

    expect(verified.ok).toBe(false);
    if (verified.ok) {
      return;
    }

    expect(verified.error.code).toBe('manifest_payload_mismatch');
  });

  it('fails closed for expired manifests by default', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const signedManifest = await signManifest({
      manifest: createUnsignedManifest({
        issuedAt: '2026-02-07T10:00:00Z',
        expiresAt: '2026-02-07T10:01:00Z'
      }),
      signing_key: keyPair.value.private_key
    });
    expect(signedManifest.ok).toBe(true);
    if (!signedManifest.ok) {
      return;
    }

    const keySet = buildManifestKeySet({
      keys: [keyPair.value.public_key]
    });
    expect(keySet.ok).toBe(true);
    if (!keySet.ok) {
      return;
    }

    const verified = await verifyManifestSignature({
      manifest: signedManifest.value,
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T10:05:00Z')
    });

    expect(verified.ok).toBe(false);
    if (verified.ok) {
      return;
    }

    expect(verified.error.code).toBe('manifest_expired');
  });

  it('rotates manifest signing keys with bounded overlap and stable ordering', async () => {
    const previousPrimary = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_prev_primary'
    });
    const previousSecondary = await generateManifestSigningKeyPair({
      alg: 'ES256',
      kid: 'manifest_prev_secondary'
    });

    expect(previousPrimary.ok).toBe(true);
    expect(previousSecondary.ok).toBe(true);
    if (!previousPrimary.ok || !previousSecondary.ok) {
      return;
    }

    const currentKeySet = buildManifestKeySet({
      keys: [previousPrimary.value.public_key, previousSecondary.value.public_key]
    });
    expect(currentKeySet.ok).toBe(true);
    if (!currentKeySet.ok) {
      return;
    }

    const rotated = await rotateManifestSigningKeys({
      current_manifest_keys: currentKeySet.value,
      signing_alg: 'EdDSA',
      new_kid: 'manifest_new_active',
      retain_previous_key_count: 1
    });

    expect(rotated.ok).toBe(true);
    if (!rotated.ok) {
      return;
    }

    expect(rotated.value.active_signing_private_key.kid).toBe('manifest_new_active');
    expect(rotated.value.rotated_manifest_keys.keys).toHaveLength(2);
    expect(rotated.value.rotated_manifest_keys.keys[0]?.kid).toBe('manifest_new_active');
    expect(rotated.value.rotated_manifest_keys.keys[1]?.kid).toBe('manifest_prev_primary');
    expect(rotated.value.etag.startsWith('W/"')).toBe(true);
  });

  it('fails key rotation when the requested kid already exists', async () => {
    const previous = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_existing'
    });
    expect(previous.ok).toBe(true);
    if (!previous.ok) {
      return;
    }

    const currentKeySet = buildManifestKeySet({
      keys: [previous.value.public_key]
    });
    expect(currentKeySet.ok).toBe(true);
    if (!currentKeySet.ok) {
      return;
    }

    const rotated = await rotateManifestSigningKeys({
      current_manifest_keys: currentKeySet.value,
      signing_alg: 'EdDSA',
      new_kid: 'manifest_existing',
      retain_previous_key_count: 1
    });

    expect(rotated.ok).toBe(false);
    if (rotated.ok) {
      return;
    }

    expect(rotated.error.code).toBe('manifest_key_mismatch');
  });

  it('fails closed on invalid key rotation input', async () => {
    const rotated = await rotateManifestSigningKeys({
      current_manifest_keys: {keys: []},
      signing_alg: 'EdDSA',
      retain_previous_key_count: -1
    } as never);

    expect(rotated.ok).toBe(false);
    if (rotated.ok) {
      return;
    }

    expect(rotated.error.code).toBe('manifest_key_rotation_invalid');
  });

  it('fails closed when current keyset contains duplicate kids', async () => {
    const rotated = await rotateManifestSigningKeys({
      current_manifest_keys: {
        keys: [
          {
            kid: 'dup_kid',
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'abc',
            alg: 'EdDSA',
            use: 'sig'
          },
          {
            kid: 'dup_kid',
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'def',
            alg: 'EdDSA',
            use: 'sig'
          }
        ]
      },
      signing_alg: 'EdDSA',
      retain_previous_key_count: 0
    });

    expect(rotated.ok).toBe(false);
    if (rotated.ok) {
      return;
    }

    expect(rotated.error.code).toBe('manifest_key_mismatch');
  });
});
