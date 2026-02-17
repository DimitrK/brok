import {createCipheriv, createDecipheriv, randomBytes} from 'node:crypto';

import {z} from 'zod';

import {
  EncryptedSecretMaterialSchema,
  EnvelopeCiphertextSchema,
  KeyIdSchema,
  SecretMaterialSchema,
  type EncryptedSecretMaterial,
  type EnvelopeCiphertext,
  type SecretMaterial
} from './contracts.js';
import {decodeBase64, encodeBase64, equalByteArrays} from './base64.js';
import {err, ok, type CryptoErrorCode, type CryptoResult} from './errors.js';

const DATA_KEY_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;

const AES_GCM_KEY_ENCRYPTION_ALG = 'A256GCMKW';
const AES_GCM_CONTENT_ENCRYPTION_ALG = 'A256GCM';

const WRAPPED_DATA_KEY_MIN_BYTES = AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES + 1;
const MAX_WRAPPED_DATA_KEY_BYTES = 16_384;
const MAX_ENVELOPE_AAD_BYTES = 16_384;
const MAX_ENVELOPE_CIPHERTEXT_BYTES = 1_048_576;
const MAX_KMS_KEYRING_SIZE = 128;
const MAX_KMS_KEY_B64_LENGTH = 128;

const AesGcmKeyManagementInputSchema = z
  .object({
    active_key_id: KeyIdSchema,
    keys: z.record(KeyIdSchema, z.string().min(1).max(MAX_KMS_KEY_B64_LENGTH)),
    key_encryption_alg: z.literal(AES_GCM_KEY_ENCRYPTION_ALG).default(AES_GCM_KEY_ENCRYPTION_ALG)
  })
  .strict();

const serializeContextForAad = (value: unknown): string => {
  if (value === null) {
    return 'null';
  }

  if (Array.isArray(value)) {
    return `[${value.map(item => serializeContextForAad(item)).join(',')}]`;
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
      left.localeCompare(right)
    );
    const renderedEntries = entries.map(
      ([key, entryValue]) => `${JSON.stringify(key)}:${serializeContextForAad(entryValue)}`
    );
    return `{${renderedEntries.join(',')}}`;
  }

  return JSON.stringify(value);
};

const normalizeAad = (aad?: Uint8Array): Buffer | undefined => (aad ? Buffer.from(aad) : undefined);

const zeroizeBytes = (bytes: Uint8Array) => {
  if (Buffer.isBuffer(bytes)) {
    bytes.fill(0);
    return;
  }

  Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).fill(0);
};

class KmsServiceError extends Error {
  public readonly code: CryptoErrorCode;

  public constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

const decodeAndValidateAesKey = ({
  encodedKey,
  keyId
}: {
  encodedKey: string;
  keyId: string;
}): CryptoResult<Buffer> => {
  const decoded = decodeBase64(encodedKey);
  if (!decoded) {
    return err('invalid_base64', `Key ${keyId} must be valid base64`);
  }

  if (decoded.length !== DATA_KEY_BYTES) {
    return err('invalid_key_length', `Key ${keyId} must decode to exactly ${DATA_KEY_BYTES} bytes`);
  }

  return ok(decoded);
};

const mapKmsFailure = ({
  fallbackCode,
  failure
}: {
  fallbackCode: CryptoErrorCode;
  failure: unknown;
}) => {
  if (failure instanceof KmsServiceError) {
    return err(failure.code, failure.message);
  }

  return err(fallbackCode, 'Key management operation failed');
};

export type WrapDataKeyInput = {
  plaintext_data_key: Uint8Array;
  requested_key_id?: string;
  aad?: Uint8Array;
};

export type WrapDataKeyOutput = {
  key_id: string;
  key_encryption_alg: string;
  wrapped_data_key: Uint8Array;
};

export type UnwrapDataKeyInput = {
  key_id: string;
  key_encryption_alg: string;
  wrapped_data_key: Uint8Array;
  aad?: Uint8Array;
};

export type EnvelopeKeyManagementService = {
  wrapDataKey: (input: WrapDataKeyInput) => Promise<WrapDataKeyOutput> | WrapDataKeyOutput;
  unwrapDataKey: (input: UnwrapDataKeyInput) => Promise<Uint8Array> | Uint8Array;
};

export type EncryptWithEnvelopeInput = {
  plaintext: Uint8Array;
  key_management_service: EnvelopeKeyManagementService;
  requested_key_id?: string;
  aad?: Uint8Array;
};

export type DecryptWithEnvelopeInput = {
  envelope: EnvelopeCiphertext;
  key_management_service: EnvelopeKeyManagementService;
  expected_aad?: Uint8Array;
};

export type EncryptSecretMaterialInput = {
  secret_material: SecretMaterial;
  key_management_service: EnvelopeKeyManagementService;
  requested_key_id?: string;
  aad?: Uint8Array;
};

export type DecryptSecretMaterialInput = {
  encrypted_secret_material: EncryptedSecretMaterial;
  key_management_service: EnvelopeKeyManagementService;
  expected_aad?: Uint8Array;
};

export type AesGcmKeyManagementInput = z.input<typeof AesGcmKeyManagementInputSchema>;

export const buildEnvelopeAad = (context: Readonly<Record<string, string>>) =>
  Buffer.from(serializeContextForAad(context), 'utf8');

export const createAesGcmKeyManagementService = (
  input: AesGcmKeyManagementInput
): CryptoResult<EnvelopeKeyManagementService> => {
  const parsedInput = AesGcmKeyManagementInputSchema.safeParse(input);
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message);
  }

  const keyringEntries = Object.entries(parsedInput.data.keys);
  if (keyringEntries.length < 1) {
    return err('invalid_input', 'keys must include at least one key');
  }

  if (keyringEntries.length > MAX_KMS_KEYRING_SIZE) {
    return err('invalid_input', `keys must include at most ${MAX_KMS_KEYRING_SIZE} entries`);
  }

  const keyring = new Map<string, Buffer>();
  for (const [keyId, encodedKey] of keyringEntries) {
    const decodedKey = decodeAndValidateAesKey({encodedKey, keyId});
    if (!decodedKey.ok) {
      return decodedKey;
    }
    keyring.set(keyId, decodedKey.value);
  }

  if (!keyring.has(parsedInput.data.active_key_id)) {
    return err('kms_key_not_found', `active_key_id ${parsedInput.data.active_key_id} does not exist in keys`);
  }

  const resolveKey = (requestedKeyId?: string) => {
    if (requestedKeyId !== undefined) {
      const parsedKeyId = KeyIdSchema.safeParse(requestedKeyId);
      if (!parsedKeyId.success) {
        throw new KmsServiceError('invalid_key_id', parsedKeyId.error.message);
      }
    }

    const effectiveKeyId = requestedKeyId ?? parsedInput.data.active_key_id;
    const key = keyring.get(effectiveKeyId);
    if (!key) {
      throw new KmsServiceError('kms_key_not_found', `Key id ${effectiveKeyId} was not found in keyring`);
    }

    return {key_id: effectiveKeyId, key};
  };

  const service: EnvelopeKeyManagementService = {
    wrapDataKey: ({plaintext_data_key, requested_key_id, aad}) => {
      if (!(plaintext_data_key instanceof Uint8Array)) {
        throw new KmsServiceError('invalid_input', 'plaintext_data_key must be Uint8Array');
      }

      if (plaintext_data_key.length !== DATA_KEY_BYTES) {
        throw new KmsServiceError('invalid_key_length', `plaintext_data_key must be exactly ${DATA_KEY_BYTES} bytes`);
      }

      const keySelection = resolveKey(requested_key_id);
      const iv = randomBytes(AES_GCM_IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', keySelection.key, iv);
      const normalizedAad = normalizeAad(aad);
      if (normalizedAad) {
        if (normalizedAad.length > MAX_ENVELOPE_AAD_BYTES) {
          throw new KmsServiceError('invalid_input', `aad must be at most ${MAX_ENVELOPE_AAD_BYTES} bytes`);
        }

        cipher.setAAD(normalizedAad);
      }

      const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext_data_key)), cipher.final()]);
      const authTag = cipher.getAuthTag();

      return {
        key_id: keySelection.key_id,
        key_encryption_alg: parsedInput.data.key_encryption_alg,
        wrapped_data_key: Buffer.concat([iv, authTag, encrypted])
      };
    },
    unwrapDataKey: ({key_id, key_encryption_alg, wrapped_data_key, aad}) => {
      if (key_encryption_alg !== parsedInput.data.key_encryption_alg) {
        throw new KmsServiceError(
          'invalid_algorithm',
          `Unsupported key encryption algorithm: ${key_encryption_alg}`
        );
      }

      if (!(wrapped_data_key instanceof Uint8Array) || wrapped_data_key.length < WRAPPED_DATA_KEY_MIN_BYTES) {
        throw new KmsServiceError('invalid_envelope_payload', 'wrapped_data_key has invalid length');
      }

      if (wrapped_data_key.length > MAX_WRAPPED_DATA_KEY_BYTES) {
        throw new KmsServiceError(
          'invalid_envelope_payload',
          `wrapped_data_key must be at most ${MAX_WRAPPED_DATA_KEY_BYTES} bytes`
        );
      }

      const keySelection = resolveKey(key_id);
      const wrapped = Buffer.from(wrapped_data_key);
      const iv = wrapped.subarray(0, AES_GCM_IV_BYTES);
      const authTag = wrapped.subarray(AES_GCM_IV_BYTES, AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES);
      const encryptedDataKey = wrapped.subarray(AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES);

      try {
        const decipher = createDecipheriv('aes-256-gcm', keySelection.key, iv);
        const normalizedAad = normalizeAad(aad);
        if (normalizedAad) {
          if (normalizedAad.length > MAX_ENVELOPE_AAD_BYTES) {
            throw new KmsServiceError('invalid_input', `aad must be at most ${MAX_ENVELOPE_AAD_BYTES} bytes`);
          }

          decipher.setAAD(normalizedAad);
        }

        decipher.setAuthTag(authTag);
        return Buffer.concat([decipher.update(encryptedDataKey), decipher.final()]);
      } catch {
        throw new KmsServiceError('kms_unwrap_failed', 'Unable to unwrap data key');
      }
    }
  };

  return ok(service);
};

export const encryptWithEnvelope = async ({
  plaintext,
  key_management_service,
  requested_key_id,
  aad
}: EncryptWithEnvelopeInput): Promise<CryptoResult<EnvelopeCiphertext>> => {
  if (!(plaintext instanceof Uint8Array)) {
    return err('invalid_input', 'plaintext must be Uint8Array');
  }

  if (plaintext.length > MAX_ENVELOPE_CIPHERTEXT_BYTES) {
    return err('invalid_input', `plaintext must be at most ${MAX_ENVELOPE_CIPHERTEXT_BYTES} bytes`);
  }

  if (requested_key_id) {
    const parsedKeyId = KeyIdSchema.safeParse(requested_key_id);
    if (!parsedKeyId.success) {
      return err('invalid_key_id', parsedKeyId.error.message);
    }
  }

  const dataKey = randomBytes(DATA_KEY_BYTES);
  const iv = randomBytes(AES_GCM_IV_BYTES);
  const normalizedAad = normalizeAad(aad);
  if (normalizedAad && normalizedAad.length > MAX_ENVELOPE_AAD_BYTES) {
    return err('invalid_input', `aad must be at most ${MAX_ENVELOPE_AAD_BYTES} bytes`);
  }

  try {
    const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
    if (normalizedAad) {
      cipher.setAAD(normalizedAad);
    }

    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const authTag = cipher.getAuthTag();

    let wrappedDataKeyOutput: WrapDataKeyOutput;
    try {
      wrappedDataKeyOutput = await key_management_service.wrapDataKey({
        plaintext_data_key: dataKey,
        requested_key_id,
        aad: normalizedAad
      });
    } catch (kmsFailure) {
      return mapKmsFailure({fallbackCode: 'kms_wrap_failed', failure: kmsFailure});
    }

    if (!(wrappedDataKeyOutput.wrapped_data_key instanceof Uint8Array)) {
      return err('invalid_envelope_payload', 'wrapDataKey must return wrapped_data_key as Uint8Array');
    }

    if (wrappedDataKeyOutput.wrapped_data_key.length < 1) {
      return err('invalid_envelope_payload', 'wrapDataKey returned an empty wrapped_data_key');
    }

    if (wrappedDataKeyOutput.wrapped_data_key.length > MAX_WRAPPED_DATA_KEY_BYTES) {
      return err(
        'invalid_envelope_payload',
        `wrapDataKey returned wrapped_data_key larger than ${MAX_WRAPPED_DATA_KEY_BYTES} bytes`
      );
    }

    const parsedKeyId = KeyIdSchema.safeParse(wrappedDataKeyOutput.key_id);
    if (!parsedKeyId.success) {
      return err('invalid_key_id', parsedKeyId.error.message);
    }

    const parsedEnvelope = EnvelopeCiphertextSchema.safeParse({
      version: 1,
      content_encryption_alg: AES_GCM_CONTENT_ENCRYPTION_ALG,
      key_encryption_alg: wrappedDataKeyOutput.key_encryption_alg,
      key_id: wrappedDataKeyOutput.key_id,
      wrapped_data_key_b64: encodeBase64(wrappedDataKeyOutput.wrapped_data_key),
      iv_b64: encodeBase64(iv),
      ciphertext_b64: encodeBase64(ciphertext),
      auth_tag_b64: encodeBase64(authTag),
      ...(normalizedAad ? {aad_b64: encodeBase64(normalizedAad)} : {})
    });
    if (!parsedEnvelope.success) {
      return err('invalid_envelope_payload', parsedEnvelope.error.message);
    }

    return ok(parsedEnvelope.data);
  } catch {
    return err('invalid_envelope_payload', 'Envelope encryption failed');
  } finally {
    zeroizeBytes(dataKey);
  }
};

export const decryptWithEnvelope = async ({
  envelope,
  key_management_service,
  expected_aad
}: DecryptWithEnvelopeInput): Promise<CryptoResult<Uint8Array>> => {
  const parsedEnvelope = EnvelopeCiphertextSchema.safeParse(envelope);
  if (!parsedEnvelope.success) {
    return err('invalid_envelope_payload', parsedEnvelope.error.message);
  }

  const iv = decodeBase64(parsedEnvelope.data.iv_b64);
  if (!iv || iv.length !== AES_GCM_IV_BYTES) {
    return err('invalid_envelope_payload', `iv_b64 must decode to ${AES_GCM_IV_BYTES} bytes`);
  }

  const authTag = decodeBase64(parsedEnvelope.data.auth_tag_b64);
  if (!authTag || authTag.length !== AES_GCM_TAG_BYTES) {
    return err('invalid_envelope_payload', `auth_tag_b64 must decode to ${AES_GCM_TAG_BYTES} bytes`);
  }

  const ciphertext = decodeBase64(parsedEnvelope.data.ciphertext_b64);
  if (!ciphertext || ciphertext.length === 0) {
    return err('invalid_base64', 'ciphertext_b64 must be valid base64');
  }

  if (ciphertext.length > MAX_ENVELOPE_CIPHERTEXT_BYTES) {
    return err(
      'invalid_envelope_payload',
      `ciphertext_b64 must decode to at most ${MAX_ENVELOPE_CIPHERTEXT_BYTES} bytes`
    );
  }

  const wrappedDataKey = decodeBase64(parsedEnvelope.data.wrapped_data_key_b64);
  if (!wrappedDataKey || wrappedDataKey.length === 0) {
    return err('invalid_base64', 'wrapped_data_key_b64 must be valid base64');
  }

  if (wrappedDataKey.length > MAX_WRAPPED_DATA_KEY_BYTES) {
    return err(
      'invalid_envelope_payload',
      `wrapped_data_key_b64 must decode to at most ${MAX_WRAPPED_DATA_KEY_BYTES} bytes`
    );
  }

  let aadFromEnvelope: Buffer | undefined;
  if (parsedEnvelope.data.aad_b64) {
    const decodedAad = decodeBase64(parsedEnvelope.data.aad_b64);
    if (!decodedAad) {
      return err('invalid_base64', 'aad_b64 must be valid base64');
    }

    if (decodedAad.length > MAX_ENVELOPE_AAD_BYTES) {
      return err('invalid_envelope_payload', `aad_b64 must decode to at most ${MAX_ENVELOPE_AAD_BYTES} bytes`);
    }

    aadFromEnvelope = decodedAad;
  }

  const normalizedExpectedAad = normalizeAad(expected_aad);
  if (normalizedExpectedAad && normalizedExpectedAad.length > MAX_ENVELOPE_AAD_BYTES) {
    return err('invalid_input', `expected_aad must be at most ${MAX_ENVELOPE_AAD_BYTES} bytes`);
  }

  if (normalizedExpectedAad) {
    if (!aadFromEnvelope) {
      return err('aad_mismatch', 'Expected AAD is missing from encrypted payload');
    }

    if (!equalByteArrays(aadFromEnvelope, normalizedExpectedAad)) {
      return err('aad_mismatch', 'AAD does not match the expected context');
    }
  }

  let dataKey: Uint8Array;
  try {
    dataKey = await key_management_service.unwrapDataKey({
      key_id: parsedEnvelope.data.key_id,
      key_encryption_alg: parsedEnvelope.data.key_encryption_alg,
      wrapped_data_key: wrappedDataKey,
      aad: aadFromEnvelope
    });
  } catch (kmsFailure) {
    return mapKmsFailure({fallbackCode: 'kms_unwrap_failed', failure: kmsFailure});
  }

  if (!(dataKey instanceof Uint8Array)) {
    return err('kms_unwrap_failed', 'unwrapDataKey must return Uint8Array');
  }

  if (dataKey.length !== DATA_KEY_BYTES) {
    zeroizeBytes(dataKey);
    return err('invalid_key_length', `Unwrapped data key must be ${DATA_KEY_BYTES} bytes`);
  }

  try {
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(dataKey), iv);
    if (aadFromEnvelope) {
      decipher.setAAD(aadFromEnvelope);
    }
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return ok(plaintext);
  } catch {
    return err('decrypt_auth_failed', 'Envelope decrypt failed authentication');
  } finally {
    zeroizeBytes(dataKey);
  }
};

export const encryptSecretMaterial = async ({
  secret_material,
  key_management_service,
  requested_key_id,
  aad
}: EncryptSecretMaterialInput): Promise<CryptoResult<EncryptedSecretMaterial>> => {
  const parsedSecretMaterial = SecretMaterialSchema.safeParse(secret_material);
  if (!parsedSecretMaterial.success) {
    return err('invalid_input', parsedSecretMaterial.error.message);
  }

  const encrypted = await encryptWithEnvelope({
    plaintext: Buffer.from(parsedSecretMaterial.data.value, 'utf8'),
    key_management_service,
    requested_key_id,
    aad
  });
  if (!encrypted.ok) {
    return encrypted;
  }

  const parsedEncryptedMaterial = EncryptedSecretMaterialSchema.safeParse({
    type: parsedSecretMaterial.data.type,
    envelope: encrypted.value
  });
  if (!parsedEncryptedMaterial.success) {
    return err('invalid_envelope_payload', parsedEncryptedMaterial.error.message);
  }

  return ok(parsedEncryptedMaterial.data);
};

export const decryptSecretMaterial = async ({
  encrypted_secret_material,
  key_management_service,
  expected_aad
}: DecryptSecretMaterialInput): Promise<CryptoResult<SecretMaterial>> => {
  const parsedEncryptedMaterial = EncryptedSecretMaterialSchema.safeParse(encrypted_secret_material);
  if (!parsedEncryptedMaterial.success) {
    return err('invalid_input', parsedEncryptedMaterial.error.message);
  }

  const decrypted = await decryptWithEnvelope({
    envelope: parsedEncryptedMaterial.data.envelope,
    key_management_service,
    expected_aad
  });
  if (!decrypted.ok) {
    return decrypted;
  }

  const parsedSecretMaterial = SecretMaterialSchema.safeParse({
    type: parsedEncryptedMaterial.data.type,
    value: Buffer.from(decrypted.value).toString('utf8')
  });
  if (!parsedSecretMaterial.success) {
    return err('invalid_input', parsedSecretMaterial.error.message);
  }

  return ok(parsedSecretMaterial.data);
};
