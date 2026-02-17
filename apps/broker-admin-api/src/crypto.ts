import {createHash, randomBytes, randomUUID} from 'node:crypto';

import {
  buildEnvelopeAad,
  computeManifestKeysEtag,
  createAesGcmKeyManagementService,
  decryptSecretMaterial,
  encryptSecretMaterial,
  encryptWithEnvelope,
  type EnvelopeCiphertext,
  type ManifestSigningPrivateKey
} from '@broker-interceptor/crypto';
import {
  OpenApiManifestKeysSchema,
  SecretMaterialSchema,
  type OpenApiManifestKeys,
  type SecretMaterial
} from '@broker-interceptor/schemas';
import {internal} from './errors';

export const generateId = (prefix: string) => `${prefix}${randomUUID().replaceAll('-', '').slice(0, 20)}`;

export const hashToken = (token: string) => createHash('sha256').update(token, 'utf8').digest('hex');

export const createOpaqueToken = (bytes = 32) =>
  randomBytes(bytes).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');

export type EncryptedSecretEnvelope = EnvelopeCiphertext;

const createLocalEnvelopeKms = ({key, keyId}: {key: Buffer; keyId: string}) => {
  const kms = createAesGcmKeyManagementService({
    active_key_id: keyId,
    keys: {
      [keyId]: key.toString('base64')
    }
  });

  if (!kms.ok) {
    throw internal('secret_encrypt_failed', kms.error.message);
  }

  return kms.value;
};

export const encryptSecretMaterialWithCryptoPackage = async ({
  secretMaterial,
  key,
  keyId,
  aadContext
}: {
  secretMaterial: SecretMaterial;
  key: Buffer;
  keyId: string;
  aadContext: Readonly<Record<string, string>>;
}) => {
  const parsedSecretMaterial = SecretMaterialSchema.safeParse(secretMaterial);
  if (!parsedSecretMaterial.success) {
    throw internal('secret_encrypt_failed', 'Secret material payload is invalid');
  }

  const kms = createLocalEnvelopeKms({key, keyId});
  const encrypted = await encryptSecretMaterial({
    secret_material: parsedSecretMaterial.data,
    key_management_service: kms,
    requested_key_id: keyId,
    aad: buildEnvelopeAad(aadContext)
  });
  if (!encrypted.ok) {
    throw internal('secret_encrypt_failed', 'Secret material could not be encrypted');
  }

  return encrypted.value.envelope;
};

export const decryptSecretMaterialWithCryptoPackage = async ({
  envelope,
  secretType,
  key,
  keyId,
  aadContext
}: {
  envelope: EncryptedSecretEnvelope;
  secretType: SecretMaterial['type'];
  key: Buffer;
  keyId: string;
  aadContext: Readonly<Record<string, string>>;
}) => {
  const kms = createLocalEnvelopeKms({key, keyId});
  const decrypted = await decryptSecretMaterial({
    encrypted_secret_material: {
      type: secretType,
      envelope
    },
    key_management_service: kms,
    expected_aad: buildEnvelopeAad(aadContext)
  });
  if (!decrypted.ok) {
    throw internal('secret_decrypt_failed', 'Stored secret could not be decrypted with configured key');
  }

  return decrypted.value.value;
};

export const computeManifestKeysWeakEtagWithCryptoPackage = ({manifestKeys}: {manifestKeys: OpenApiManifestKeys}) => {
  const parsedManifestKeys = OpenApiManifestKeysSchema.safeParse(manifestKeys);
  if (!parsedManifestKeys.success) {
    throw internal('manifest_keys_invalid', 'Manifest keys payload is invalid');
  }

  const computed = computeManifestKeysEtag({
    manifest_keys: parsedManifestKeys.data
  });
  if (!computed.ok) {
    throw internal('manifest_keys_etag_failed', 'Unable to compute manifest keys etag');
  }

  return computed.value;
};

export const computeWeakEtag = (value: unknown) => {
  const digest = createHash('sha256').update(JSON.stringify(value), 'utf8').digest('base64url');
  return `W/"${digest}"`;
};

const toBase64Url = (value: string) => Buffer.from(value, 'utf8').toString('base64url');

export const buildManifestSigningPrivateKeyRef = async ({
  signingKey,
  key,
  keyId,
  version = 1
}: {
  signingKey: ManifestSigningPrivateKey;
  key: Buffer;
  keyId: string;
  version?: number;
}) => {
  const kms = createLocalEnvelopeKms({key, keyId});
  const envelopeResult = await encryptWithEnvelope({
    plaintext: Buffer.from(JSON.stringify(signingKey), 'utf8'),
    key_management_service: kms,
    requested_key_id: keyId,
    aad: buildEnvelopeAad({
      purpose: 'manifest_signing_key',
      kid: signingKey.kid,
      alg: signingKey.alg,
      version: `v${version}`
    })
  });

  if (!envelopeResult.ok) {
    throw internal('secret_encrypt_failed', 'Manifest signing key could not be encrypted');
  }

  const encodedEnvelope = toBase64Url(JSON.stringify(envelopeResult.value));
  return `local+enc://manifest/${signingKey.kid}/v${version}#${encodedEnvelope}`;
};
