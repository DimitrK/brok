import {CompactSign, importJWK} from 'jose';
import {describe, expect, it} from 'vitest';

import {
  buildManifestKeySet,
  computeManifestKeysEtag,
  createAesGcmKeyManagementService,
  decodeBase64,
  decryptSecretMaterial,
  decryptWithEnvelope,
  encryptSecretMaterial,
  encryptWithEnvelope,
  equalByteArrays,
  generateKeyId,
  generateManifestSigningKeyPair,
  ManifestSigningPrivateKeySchema,
  signManifest,
  stripManifestSignature,
  toCanonicalManifestPayload,
  UnsignedManifestSchema,
  verifyManifestSignature,
  type EnvelopeKeyManagementService
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

const createUnsignedManifest = ({
  issuedAt = '2026-02-07T10:00:00Z',
  expiresAt = '2026-02-07T10:10:00Z'
}: {
  issuedAt?: string;
  expiresAt?: string;
} = {}) =>
  UnsignedManifestSchema.parse({
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

describe('base64 and key-id hardening', () => {
  it('rejects empty and malformed base64 and supports padding normalization', () => {
    expect(decodeBase64('   ')).toBeNull();
    expect(decodeBase64('%%%')).toBeNull();

    const decoded = decodeBase64('AA');
    expect(decoded).not.toBeNull();
    expect(decoded?.length).toBe(1);
  });

  it('compares byte arrays with length checks and timing-safe equality', () => {
    expect(equalByteArrays(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
    expect(equalByteArrays(Buffer.from('abc'), Buffer.from('abcd'))).toBe(false);
    expect(equalByteArrays(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
  });

  it('generates valid key identifiers for default prefix', () => {
    const generated = generateKeyId();
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    expect(generated.value.startsWith('kid_')).toBe(true);
  });
});

describe('contract and schema guards', () => {
  it('enforces EdDSA private key shape constraints', () => {
    const parsed = ManifestSigningPrivateKeySchema.safeParse({
      kid: 'manifest_bad_eddsa',
      alg: 'EdDSA',
      private_jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'x',
        y: 'y',
        d: 'd'
      }
    });

    expect(parsed.success).toBe(false);
  });

  it('enforces ES256 private key shape constraints', () => {
    const parsed = ManifestSigningPrivateKeySchema.safeParse({
      kid: 'manifest_bad_es256',
      alg: 'ES256',
      private_jwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'x',
        d: 'd'
      }
    });

    expect(parsed.success).toBe(false);
  });
});

describe('envelope error branches', () => {
  it('fails closed for invalid encryption input and unknown key ids', async () => {
    const kms = createKmsOrThrow();

    const invalidPlaintext = await encryptWithEnvelope({
      plaintext: 'secret' as unknown as Uint8Array,
      key_management_service: kms
    });
    expect(invalidPlaintext.ok).toBe(false);
    if (!invalidPlaintext.ok) {
      expect(invalidPlaintext.error.code).toBe('invalid_input');
    }

    const missingKey = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: kms,
      requested_key_id: 'unknown_kek'
    });
    expect(missingKey.ok).toBe(false);
    if (!missingKey.ok) {
      expect(missingKey.error.code).toBe('kms_key_not_found');
    }
  });

  it('fails closed for malformed wrapDataKey responses', async () => {
    const malformedPayloadKms: EnvelopeKeyManagementService = {
      wrapDataKey: () =>
        ({
          key_id: 'kek_v1',
          key_encryption_alg: 'A256GCMKW',
          wrapped_data_key: 'not-bytes'
        }) as unknown as {
          key_id: string;
          key_encryption_alg: string;
          wrapped_data_key: Uint8Array;
        },
      unwrapDataKey: () => Buffer.alloc(32, 1)
    };

    const malformedPayload = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: malformedPayloadKms
    });
    expect(malformedPayload.ok).toBe(false);
    if (!malformedPayload.ok) {
      expect(malformedPayload.error.code).toBe('invalid_envelope_payload');
    }

    const emptyWrappedKeyKms: EnvelopeKeyManagementService = {
      wrapDataKey: () => ({
        key_id: 'kek_v1',
        key_encryption_alg: 'A256GCMKW',
        wrapped_data_key: new Uint8Array()
      }),
      unwrapDataKey: () => Buffer.alloc(32, 1)
    };

    const emptyWrappedKey = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: emptyWrappedKeyKms
    });
    expect(emptyWrappedKey.ok).toBe(false);
    if (!emptyWrappedKey.ok) {
      expect(emptyWrappedKey.error.code).toBe('invalid_envelope_payload');
    }

    const invalidKeyIdKms: EnvelopeKeyManagementService = {
      wrapDataKey: () => ({
        key_id: 'bad key id',
        key_encryption_alg: 'A256GCMKW',
        wrapped_data_key: Buffer.from('wrapped')
      }),
      unwrapDataKey: () => Buffer.alloc(32, 1)
    };

    const invalidKeyId = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: invalidKeyIdKms
    });
    expect(invalidKeyId.ok).toBe(false);
    if (!invalidKeyId.ok) {
      expect(invalidKeyId.error.code).toBe('invalid_key_id');
    }

    const invalidAlgKms: EnvelopeKeyManagementService = {
      wrapDataKey: () => ({
        key_id: 'kek_v1',
        key_encryption_alg: '',
        wrapped_data_key: Buffer.from('wrapped')
      }),
      unwrapDataKey: () => Buffer.alloc(32, 1)
    };

    const invalidAlg = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: invalidAlgKms
    });
    expect(invalidAlg.ok).toBe(false);
    if (!invalidAlg.ok) {
      expect(invalidAlg.error.code).toBe('invalid_envelope_payload');
    }
  });

  it('validates envelope fields and unwrap behavior on decrypt', async () => {
    const kms = createKmsOrThrow();
    const encrypted = await encryptWithEnvelope({
      plaintext: Buffer.from('secret'),
      key_management_service: kms
    });
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const invalidIv = await decryptWithEnvelope({
      envelope: {...encrypted.value, iv_b64: Buffer.alloc(4).toString('base64')},
      key_management_service: kms
    });
    expect(invalidIv.ok).toBe(false);
    if (!invalidIv.ok) {
      expect(invalidIv.error.code).toBe('invalid_envelope_payload');
    }

    const invalidAuthTag = await decryptWithEnvelope({
      envelope: {...encrypted.value, auth_tag_b64: Buffer.alloc(3).toString('base64')},
      key_management_service: kms
    });
    expect(invalidAuthTag.ok).toBe(false);
    if (!invalidAuthTag.ok) {
      expect(invalidAuthTag.error.code).toBe('invalid_envelope_payload');
    }

    const invalidCiphertext = await decryptWithEnvelope({
      envelope: {...encrypted.value, ciphertext_b64: '%%%'},
      key_management_service: kms
    });
    expect(invalidCiphertext.ok).toBe(false);
    if (!invalidCiphertext.ok) {
      expect(invalidCiphertext.error.code).toBe('invalid_base64');
    }

    const invalidWrappedKey = await decryptWithEnvelope({
      envelope: {...encrypted.value, wrapped_data_key_b64: '%%%'},
      key_management_service: kms
    });
    expect(invalidWrappedKey.ok).toBe(false);
    if (!invalidWrappedKey.ok) {
      expect(invalidWrappedKey.error.code).toBe('invalid_base64');
    }

    const invalidAad = await decryptWithEnvelope({
      envelope: {...encrypted.value, aad_b64: '%%%'},
      key_management_service: kms
    });
    expect(invalidAad.ok).toBe(false);
    if (!invalidAad.ok) {
      expect(invalidAad.error.code).toBe('invalid_base64');
    }

    const missingAad = await decryptWithEnvelope({
      envelope: encrypted.value,
      key_management_service: kms,
      expected_aad: Buffer.from('tenant:t_1')
    });
    expect(missingAad.ok).toBe(false);
    if (!missingAad.ok) {
      expect(missingAad.error.code).toBe('aad_mismatch');
    }

    const nonBytesKey: EnvelopeKeyManagementService = {
      wrapDataKey: kms.wrapDataKey,
      unwrapDataKey: () => 'bad' as unknown as Uint8Array
    };
    const unwrappedNonBytes = await decryptWithEnvelope({
      envelope: encrypted.value,
      key_management_service: nonBytesKey
    });
    expect(unwrappedNonBytes.ok).toBe(false);
    if (!unwrappedNonBytes.ok) {
      expect(unwrappedNonBytes.error.code).toBe('kms_unwrap_failed');
    }

    const shortKey: EnvelopeKeyManagementService = {
      wrapDataKey: kms.wrapDataKey,
      unwrapDataKey: () => Buffer.alloc(16, 1)
    };
    const invalidKeyLength = await decryptWithEnvelope({
      envelope: encrypted.value,
      key_management_service: shortKey
    });
    expect(invalidKeyLength.ok).toBe(false);
    if (!invalidKeyLength.ok) {
      expect(invalidKeyLength.error.code).toBe('invalid_key_length');
    }

    const unwrapThrows: EnvelopeKeyManagementService = {
      wrapDataKey: kms.wrapDataKey,
      unwrapDataKey: () => {
        throw new Error('kms down');
      }
    };
    const unwrapFailure = await decryptWithEnvelope({
      envelope: encrypted.value,
      key_management_service: unwrapThrows
    });
    expect(unwrapFailure.ok).toBe(false);
    if (!unwrapFailure.ok) {
      expect(unwrapFailure.error.code).toBe('kms_unwrap_failed');
    }

    const wrongKeyKms = createAesGcmKeyManagementService({
      active_key_id: 'kek_v1',
      keys: {
        kek_v1: Buffer.alloc(32, 9).toString('base64')
      }
    });
    expect(wrongKeyKms.ok).toBe(true);
    if (!wrongKeyKms.ok) {
      return;
    }

    const wrongKeyDecrypt = await decryptWithEnvelope({
      envelope: encrypted.value,
      key_management_service: wrongKeyKms.value
    });
    expect(wrongKeyDecrypt.ok).toBe(false);
    if (!wrongKeyDecrypt.ok) {
      expect(wrongKeyDecrypt.error.code).toBe('kms_unwrap_failed');
    }
  });

  it('handles secret material parse failures', async () => {
    const kms = createKmsOrThrow();

    const invalidSecret = await encryptSecretMaterial({
      secret_material: {type: 'not-supported', value: 'abc'} as unknown as {
        type: 'api_key';
        value: string;
      },
      key_management_service: kms
    });
    expect(invalidSecret.ok).toBe(false);
    if (!invalidSecret.ok) {
      expect(invalidSecret.error.code).toBe('invalid_input');
    }

    const invalidEncryptedSecret = await decryptSecretMaterial({
      encrypted_secret_material: {
        type: 'api_key',
        envelope: {
          version: 1,
          content_encryption_alg: 'A256GCM',
          key_encryption_alg: 'A256GCMKW',
          key_id: 'kek_v1',
          wrapped_data_key_b64: '',
          iv_b64: '',
          ciphertext_b64: '',
          auth_tag_b64: ''
        }
      },
      key_management_service: kms
    });
    expect(invalidEncryptedSecret.ok).toBe(false);
    if (!invalidEncryptedSecret.ok) {
      expect(invalidEncryptedSecret.error.code).toBe('invalid_input');
    }

    const emptyPlaintextEnvelope = await encryptWithEnvelope({
      plaintext: Buffer.alloc(0),
      key_management_service: kms
    });
    expect(emptyPlaintextEnvelope.ok).toBe(false);
    if (!emptyPlaintextEnvelope.ok) {
      expect(emptyPlaintextEnvelope.error.code).toBe('invalid_envelope_payload');
    }
  });

  it('rejects invalid KMS input payload shape', () => {
    const invalidKms = createAesGcmKeyManagementService({
      active_key_id: 'bad key id',
      keys: {
        'bad key id': Buffer.alloc(32, 1).toString('base64')
      }
    });
    expect(invalidKms.ok).toBe(false);
    if (!invalidKms.ok) {
      expect(invalidKms.error.code).toBe('invalid_input');
    }
  });
});

describe('manifest edge-case coverage', () => {
  it('supports generated kid flow and rejects invalid generation input', async () => {
    const generated = await generateManifestSigningKeyPair({alg: 'EdDSA'});
    expect(generated.ok).toBe(true);
    if (generated.ok) {
      expect(generated.value.private_key.kid.startsWith('manifest_')).toBe(true);
    }

    const invalid = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'invalid kid'
    });
    expect(invalid.ok).toBe(false);
    if (!invalid.ok) {
      expect(invalid.error.code).toBe('invalid_input');
    }
  });

  it('handles key-set, signing, and strip validation failures', async () => {
    const duplicateSet = buildManifestKeySet({
      keys: [
        {
          kid: 'dup',
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'abc',
          alg: 'EdDSA',
          use: 'sig'
        },
        {
          kid: 'dup',
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'def',
          alg: 'EdDSA',
          use: 'sig'
        }
      ]
    });
    expect(duplicateSet.ok).toBe(false);
    if (!duplicateSet.ok) {
      expect(duplicateSet.error.code).toBe('manifest_key_mismatch');
    }

    const invalidSetInput = buildManifestKeySet({
      keys: 'bad' as unknown as []
    });
    expect(invalidSetInput.ok).toBe(false);
    if (!invalidSetInput.ok) {
      expect(invalidSetInput.error.code).toBe('invalid_input');
    }

    const invalidManifest = await signManifest({
      manifest: {} as unknown as ReturnType<typeof createUnsignedManifest>,
      signing_key: {
        kid: 'manifest_v1',
        alg: 'EdDSA',
        private_jwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'x',
          d: 'd'
        }
      }
    });
    expect(invalidManifest.ok).toBe(false);
    if (!invalidManifest.ok) {
      expect(invalidManifest.error.code).toBe('manifest_invalid');
    }

    const invalidSigningKey = await signManifest({
      manifest: createUnsignedManifest(),
      signing_key: {
        kid: 'manifest_v1',
        alg: 'EdDSA',
        private_jwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'x',
          d: 'd',
          y: 'y'
        }
      }
    });
    expect(invalidSigningKey.ok).toBe(false);
    if (!invalidSigningKey.ok) {
      expect(invalidSigningKey.error.code).toBe('manifest_signing_key_invalid');
    }

    const importFailure = await signManifest({
      manifest: createUnsignedManifest(),
      signing_key: {
        kid: 'manifest_v1',
        alg: 'EdDSA',
        private_jwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'not-base64url',
          d: 'not-base64url'
        }
      }
    });
    expect(importFailure.ok).toBe(false);
    if (!importFailure.ok) {
      expect(importFailure.error.code).toBe('manifest_signing_failed');
    }

    const stripped = stripManifestSignature({} as never);
    expect(stripped.ok).toBe(false);
    if (!stripped.ok) {
      expect(stripped.error.code).toBe('manifest_invalid');
    }
  });

  it('covers temporal checks and signature metadata/header validation', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_time_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const keySet = buildManifestKeySet({
      keys: [keyPair.value.public_key]
    });
    expect(keySet.ok).toBe(true);
    if (!keySet.ok) {
      return;
    }

    const signedFuture = await signManifest({
      manifest: createUnsignedManifest({
        issuedAt: '2026-02-07T12:00:00Z',
        expiresAt: '2026-02-07T12:10:00Z'
      }),
      signing_key: keyPair.value.private_key
    });
    expect(signedFuture.ok).toBe(true);
    if (!signedFuture.ok) {
      return;
    }

    const notYetValid = await verifyManifestSignature({
      manifest: signedFuture.value,
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T11:59:00Z')
    });
    expect(notYetValid.ok).toBe(false);
    if (!notYetValid.ok) {
      expect(notYetValid.error.code).toBe('manifest_not_yet_valid');
    }

    const invalidWindow = await verifyManifestSignature({
      manifest: {
        ...signedFuture.value,
        issued_at: '2026-02-07T13:00:00Z',
        expires_at: '2026-02-07T12:00:00Z'
      },
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T12:01:00Z')
    });
    expect(invalidWindow.ok).toBe(false);
    if (!invalidWindow.ok) {
      expect(invalidWindow.error.code).toBe('manifest_time_invalid');
    }

    const temporalDisabled = await verifyManifestSignature({
      manifest: signedFuture.value,
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T12:20:00Z'),
      require_temporal_validity: false
    });
    expect(temporalDisabled.ok).toBe(true);

    const keyMismatch = await verifyManifestSignature({
      manifest: {
        ...signedFuture.value,
        signature: {
          ...signedFuture.value.signature,
          alg: 'ES256'
        }
      },
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T12:01:00Z')
    });
    expect(keyMismatch.ok).toBe(false);
    if (!keyMismatch.ok) {
      expect(keyMismatch.error.code).toBe('manifest_key_mismatch');
    }
  });

  it('covers JWS typ/header mismatch and invalid verification inputs', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_header_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const keySet = buildManifestKeySet({
      keys: [keyPair.value.public_key]
    });
    expect(keySet.ok).toBe(true);
    if (!keySet.ok) {
      return;
    }

    const unsigned = createUnsignedManifest();
    const canonicalPayload = toCanonicalManifestPayload(unsigned);
    const importedKey = await importJWK(
      {
        ...keyPair.value.private_key.private_jwk,
        kid: keyPair.value.private_key.kid,
        alg: keyPair.value.private_key.alg,
        use: 'sig'
      },
      keyPair.value.private_key.alg
    );

    const wrongTypJws = await new CompactSign(Buffer.from(canonicalPayload))
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: keyPair.value.private_key.kid,
        typ: 'application/json'
      })
      .sign(importedKey);

    const wrongTypResult = await verifyManifestSignature({
      manifest: {
        ...unsigned,
        signature: {
          alg: 'EdDSA',
          kid: keyPair.value.private_key.kid,
          jws: wrongTypJws
        }
      },
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T10:05:00Z')
    });
    expect(wrongTypResult.ok).toBe(false);
    if (!wrongTypResult.ok) {
      expect(wrongTypResult.error.code).toBe('manifest_signature_invalid');
    }

    const wrongKidHeaderJws = await new CompactSign(Buffer.from(canonicalPayload))
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: 'different-kid',
        typ: 'application/broker-manifest+jws'
      })
      .sign(importedKey);

    const wrongHeaderResult = await verifyManifestSignature({
      manifest: {
        ...unsigned,
        signature: {
          alg: 'EdDSA',
          kid: keyPair.value.private_key.kid,
          jws: wrongKidHeaderJws
        }
      },
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T10:05:00Z')
    });
    expect(wrongHeaderResult.ok).toBe(false);
    if (!wrongHeaderResult.ok) {
      expect(wrongHeaderResult.error.code).toBe('manifest_signature_invalid');
    }

    const invalidJws = await verifyManifestSignature({
      manifest: {
        ...unsigned,
        signature: {
          alg: 'EdDSA',
          kid: keyPair.value.private_key.kid,
          jws: 'not-a-jws'
        }
      },
      manifest_keys: keySet.value,
      now: new Date('2026-02-07T10:05:00Z')
    });
    expect(invalidJws.ok).toBe(false);
    if (!invalidJws.ok) {
      expect(invalidJws.error.code).toBe('manifest_signature_invalid');
    }

    const invalidInput = await verifyManifestSignature({
      manifest: {
        ...unsigned,
        signature: {
          alg: 'EdDSA',
          kid: keyPair.value.private_key.kid,
          jws: wrongTypJws
        }
      },
      manifest_keys: keySet.value,
      max_clock_skew_seconds: -1
    });
    expect(invalidInput.ok).toBe(false);
    if (!invalidInput.ok) {
      expect(invalidInput.error.code).toBe('invalid_input');
    }
  });

  it('validates manifest key etag input and output determinism', async () => {
    const keyPair = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_etag_v1'
    });
    expect(keyPair.ok).toBe(true);
    if (!keyPair.ok) {
      return;
    }

    const goodEtag = computeManifestKeysEtag({
      manifest_keys: {
        keys: [keyPair.value.public_key]
      }
    });
    expect(goodEtag.ok).toBe(true);
    if (goodEtag.ok) {
      expect(goodEtag.value.startsWith('W/"')).toBe(true);
    }

    const badEtag = computeManifestKeysEtag({
      manifest_keys: {
        keys: 'invalid'
      } as never
    });
    expect(badEtag.ok).toBe(false);
    if (!badEtag.ok) {
      expect(badEtag.error.code).toBe('invalid_input');
    }
  });
});
