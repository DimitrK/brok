import {createHash} from 'node:crypto';

import {
  CompactSign,
  compactVerify,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK
} from 'jose';
import {z} from 'zod';

import {
  KeyIdSchema,
  ManifestSigningAlgorithmSchema,
  ManifestSigningPrivateKeySchema,
  ManifestSigningPublicKeySchema,
  OpenApiManifestKeysSchema,
  OpenApiManifestSchema,
  UnsignedManifestSchema,
  type ManifestContract,
  type ManifestKeysContract,
  type ManifestSigningAlgorithm,
  type ManifestSigningPrivateKey,
  type ManifestSigningPublicKey,
  type UnsignedManifest
} from './contracts.js';
import {err, ok, type CryptoResult} from './errors.js';
import {generateKeyId} from './key-id.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const SIGNING_HEADER_TYPE = 'application/broker-manifest+jws';
const MAX_MANIFEST_CLOCK_SKEW_SECONDS = 300;
const MAX_MANIFEST_KEY_SET_SIZE = 128;
const MAX_MANIFEST_PAYLOAD_BYTES = 262_144;
const MAX_MANIFEST_JWS_LENGTH = 524_288;

const GenerateManifestSigningKeyPairInputSchema = z
  .object({
    alg: ManifestSigningAlgorithmSchema,
    kid: KeyIdSchema.optional()
  })
  .strict();

const BuildManifestKeySetInputSchema = z
  .object({
    keys: z.array(z.unknown()).max(MAX_MANIFEST_KEY_SET_SIZE)
  })
  .strict();

const VerifyManifestSignatureInputSchema = z
  .object({
    manifest: OpenApiManifestSchema,
    manifest_keys: OpenApiManifestKeysSchema,
    require_temporal_validity: z.boolean().default(true),
    max_clock_skew_seconds: z.number().int().gte(0).lte(MAX_MANIFEST_CLOCK_SKEW_SECONDS).default(0),
    now: z.date().optional()
  })
  .strict();

const RotateManifestSigningKeysInputSchema = z
  .object({
    current_manifest_keys: OpenApiManifestKeysSchema,
    signing_alg: ManifestSigningAlgorithmSchema,
    new_kid: KeyIdSchema.optional(),
    retain_previous_key_count: z.number().int().gte(0).lte(64)
  })
  .strict();

export type GenerateManifestSigningKeyPairInput = z.infer<typeof GenerateManifestSigningKeyPairInputSchema>;

export type ManifestSigningKeyPair = {
  private_key: ManifestSigningPrivateKey;
  public_key: ManifestSigningPublicKey;
};

export type BuildManifestKeySetInput = z.infer<typeof BuildManifestKeySetInputSchema>;

export type SignManifestInput = {
  manifest: UnsignedManifest;
  signing_key: ManifestSigningPrivateKey;
};

export type VerifyManifestSignatureInput = z.input<typeof VerifyManifestSignatureInputSchema>;

export type VerifyManifestSignatureOutput = {
  manifest: ManifestContract;
  unsigned_manifest: UnsignedManifest;
  signing_key: ManifestSigningPublicKey;
};

export type RotateManifestSigningKeysInput = z.input<typeof RotateManifestSigningKeysInputSchema>;

export type RotateManifestSigningKeysOutput = {
  active_signing_private_key: ManifestSigningPrivateKey;
  rotated_manifest_keys: ManifestKeysContract;
  etag: string;
};

const canonicalJsonStringify = (value: unknown): string => {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(item => canonicalJsonStringify(item)).join(',')}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
    left.localeCompare(right)
  );
  const renderedEntries = entries.map(
    ([key, entryValue]) => `${JSON.stringify(key)}:${canonicalJsonStringify(entryValue)}`
  );
  return `{${renderedEntries.join(',')}}`;
};

const toPublicJwk = (key: ManifestSigningPublicKey): JWK => {
  if (key.kty === 'OKP') {
    return {
      kid: key.kid,
      use: key.use,
      alg: key.alg,
      kty: key.kty,
      crv: key.crv,
      x: key.x
    };
  }

  if (!key.y) {
    throw new Error('EC key requires y');
  }

  return {
    kid: key.kid,
    use: key.use,
    alg: key.alg,
    kty: key.kty,
    crv: key.crv,
    x: key.x,
    y: key.y
  };
};

const extractPublicKeyFromJwk = ({
  alg,
  kid,
  jwk
}: {
  alg: ManifestSigningAlgorithm;
  kid: string;
  jwk: JWK;
}): CryptoResult<ManifestSigningPublicKey> => {
  if (alg === 'EdDSA') {
    const parsedKey = ManifestSigningPublicKeySchema.safeParse({
      kid,
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      alg,
      use: 'sig'
    });
    if (!parsedKey.success) {
      return err('manifest_signing_key_invalid', parsedKey.error.message);
    }
    return ok(parsedKey.data);
  }

  const parsedKey = ManifestSigningPublicKeySchema.safeParse({
    kid,
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    alg,
    use: 'sig'
  });
  if (!parsedKey.success) {
    return err('manifest_signing_key_invalid', parsedKey.error.message);
  }

  return ok(parsedKey.data);
};

const validateManifestTemporalWindow = ({
  manifest,
  now,
  maxClockSkewSeconds,
  requireTemporalValidity
}: {
  manifest: ManifestContract;
  now: Date;
  maxClockSkewSeconds: number;
  requireTemporalValidity: boolean;
}): CryptoResult<null> => {
  const issuedAt = new Date(manifest.issued_at);
  const expiresAt = new Date(manifest.expires_at);
  if (Number.isNaN(issuedAt.getTime()) || Number.isNaN(expiresAt.getTime()) || expiresAt <= issuedAt) {
    return err('manifest_time_invalid', 'Manifest issued_at/expires_at window is invalid');
  }

  if (!requireTemporalValidity) {
    return ok(null);
  }

  const skewMillis = maxClockSkewSeconds * 1000;
  if (issuedAt.getTime() - skewMillis > now.getTime()) {
    return err('manifest_not_yet_valid', 'Manifest is not yet valid');
  }

  if (expiresAt.getTime() + skewMillis <= now.getTime()) {
    return err('manifest_expired', 'Manifest has expired');
  }

  return ok(null);
};

export const toCanonicalManifestPayload = (manifest: UnsignedManifest) => canonicalJsonStringify(manifest);

export const stripManifestSignature = (
  manifest: ManifestContract
): CryptoResult<UnsignedManifest> => {
  const parsedManifest = OpenApiManifestSchema.safeParse(manifest);
  if (!parsedManifest.success) {
    return err('manifest_invalid', parsedManifest.error.message);
  }

  const unsignedManifestCandidate = Object.fromEntries(
    Object.entries(parsedManifest.data).filter(([key]) => key !== 'signature')
  );
  const parsedUnsignedManifest = UnsignedManifestSchema.safeParse(unsignedManifestCandidate);
  if (!parsedUnsignedManifest.success) {
    return err('manifest_invalid', parsedUnsignedManifest.error.message);
  }

  return ok(parsedUnsignedManifest.data);
};

export const generateManifestSigningKeyPair = async ({
  alg,
  kid
}: GenerateManifestSigningKeyPairInput): Promise<CryptoResult<ManifestSigningKeyPair>> => {
  const parsedInput = GenerateManifestSigningKeyPairInputSchema.safeParse({alg, kid});
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message);
  }

  let effectiveKid: string;
  if (parsedInput.data.kid) {
    effectiveKid = parsedInput.data.kid;
  } else {
    const generatedKeyId = generateKeyId({prefix: 'manifest_'});
    if (!generatedKeyId.ok) {
      return err(generatedKeyId.error.code, generatedKeyId.error.message);
    }
    effectiveKid = generatedKeyId.value;
  }

  try {
    const generatedKeys = await generateKeyPair(parsedInput.data.alg, {
      extractable: true
    });
    const exportedPublicJwk = await exportJWK(generatedKeys.publicKey);
    const exportedPrivateJwk = await exportJWK(generatedKeys.privateKey);

    const publicKey = extractPublicKeyFromJwk({
      alg: parsedInput.data.alg,
      kid: effectiveKid,
      jwk: exportedPublicJwk
    });
    if (!publicKey.ok) {
      return publicKey;
    }

    const privateKey = ManifestSigningPrivateKeySchema.safeParse({
      kid: effectiveKid,
      alg: parsedInput.data.alg,
      private_jwk: {
        kty: exportedPrivateJwk.kty,
        crv: exportedPrivateJwk.crv,
        x: exportedPrivateJwk.x,
        ...(exportedPrivateJwk.y ? {y: exportedPrivateJwk.y} : {}),
        d: exportedPrivateJwk.d
      }
    });
    if (!privateKey.success) {
      return err('manifest_signing_key_invalid', privateKey.error.message);
    }

    return ok({
      private_key: privateKey.data,
      public_key: publicKey.value
    });
  } catch {
    return err('manifest_signing_key_invalid', 'Unable to generate manifest signing key pair');
  }
};

export const buildManifestKeySet = ({keys}: BuildManifestKeySetInput): CryptoResult<ManifestKeysContract> => {
  const parsedInput = BuildManifestKeySetInputSchema.safeParse({keys});
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message);
  }

  const normalizedKeys: ManifestSigningPublicKey[] = [];
  for (const key of parsedInput.data.keys) {
    const parsedKey = ManifestSigningPublicKeySchema.safeParse(key);
    if (!parsedKey.success) {
      return err('invalid_input', parsedKey.error.message);
    }
    normalizedKeys.push(parsedKey.data);
  }

  const seenKeyIds = new Set<string>();
  for (const key of normalizedKeys) {
    if (seenKeyIds.has(key.kid)) {
      return err('manifest_key_mismatch', `Duplicate key id detected: ${key.kid}`);
    }
    seenKeyIds.add(key.kid);
  }

  const parsedManifestKeys = OpenApiManifestKeysSchema.safeParse({
    keys: normalizedKeys
  });
  if (!parsedManifestKeys.success) {
    return err('manifest_key_mismatch', parsedManifestKeys.error.message);
  }

  return ok(parsedManifestKeys.data);
};

export const signManifest = async ({
  manifest,
  signing_key
}: SignManifestInput): Promise<CryptoResult<ManifestContract>> => {
  const parsedManifest = UnsignedManifestSchema.safeParse(manifest);
  if (!parsedManifest.success) {
    return err('manifest_invalid', parsedManifest.error.message);
  }

  const parsedSigningKey = ManifestSigningPrivateKeySchema.safeParse(signing_key);
  if (!parsedSigningKey.success) {
    return err('manifest_signing_key_invalid', parsedSigningKey.error.message);
  }

  try {
    const signingKey = await importJWK(
      {
        ...parsedSigningKey.data.private_jwk,
        kid: parsedSigningKey.data.kid,
        alg: parsedSigningKey.data.alg,
        use: 'sig'
      },
      parsedSigningKey.data.alg
    );

    const payload = toCanonicalManifestPayload(parsedManifest.data);
    if (Buffer.byteLength(payload, 'utf8') > MAX_MANIFEST_PAYLOAD_BYTES) {
      return err('manifest_invalid', `Manifest payload exceeds ${MAX_MANIFEST_PAYLOAD_BYTES} bytes`);
    }

    const jws = await new CompactSign(textEncoder.encode(payload))
      .setProtectedHeader({
        alg: parsedSigningKey.data.alg,
        kid: parsedSigningKey.data.kid,
        typ: SIGNING_HEADER_TYPE
      })
      .sign(signingKey);

    const signedManifest = OpenApiManifestSchema.safeParse({
      ...parsedManifest.data,
      signature: {
        alg: parsedSigningKey.data.alg,
        kid: parsedSigningKey.data.kid,
        jws
      }
    });
    if (!signedManifest.success) {
      return err('manifest_invalid', signedManifest.error.message);
    }

    return ok(signedManifest.data);
  } catch {
    return err('manifest_signing_failed', 'Unable to sign manifest payload');
  }
};

export const verifyManifestSignature = async ({
  manifest,
  manifest_keys,
  require_temporal_validity = true,
  max_clock_skew_seconds = 0,
  now
}: VerifyManifestSignatureInput): Promise<CryptoResult<VerifyManifestSignatureOutput>> => {
  const parsedInput = VerifyManifestSignatureInputSchema.safeParse({
    manifest,
    manifest_keys,
    require_temporal_validity,
    max_clock_skew_seconds,
    now
  });
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message);
  }

  if (parsedInput.data.manifest.signature.jws.length > MAX_MANIFEST_JWS_LENGTH) {
    return err('invalid_input', `Manifest signature.jws exceeds ${MAX_MANIFEST_JWS_LENGTH} characters`);
  }

  const normalizedManifestKeySet = buildManifestKeySet({
    keys: parsedInput.data.manifest_keys.keys
  });
  if (!normalizedManifestKeySet.ok) {
    if (normalizedManifestKeySet.error.code === 'manifest_key_mismatch') {
      return normalizedManifestKeySet;
    }

    return err('invalid_input', normalizedManifestKeySet.error.message);
  }

  const parsedAlgorithm = ManifestSigningAlgorithmSchema.safeParse(parsedInput.data.manifest.signature.alg);
  if (!parsedAlgorithm.success) {
    return err('invalid_algorithm', 'Manifest signature uses unsupported algorithm');
  }

  const signingKey = normalizedManifestKeySet.value.keys.find(
    key => key.kid === parsedInput.data.manifest.signature.kid
  );
  if (!signingKey) {
    return err('manifest_key_not_found', 'Manifest signing key id is unknown');
  }

  const parsedSigningKey = ManifestSigningPublicKeySchema.safeParse(signingKey);
  if (!parsedSigningKey.success) {
    return err('manifest_key_mismatch', parsedSigningKey.error.message);
  }

  if (parsedSigningKey.data.alg !== parsedInput.data.manifest.signature.alg) {
    return err('manifest_key_mismatch', 'Manifest signature algorithm does not match key metadata');
  }

  const unsignedManifest = stripManifestSignature(parsedInput.data.manifest);
  if (!unsignedManifest.ok) {
    return unsignedManifest;
  }

  const temporalValidation = validateManifestTemporalWindow({
    manifest: parsedInput.data.manifest,
    now: parsedInput.data.now ?? new Date(),
    maxClockSkewSeconds: parsedInput.data.max_clock_skew_seconds,
    requireTemporalValidity: parsedInput.data.require_temporal_validity
  });
  if (!temporalValidation.ok) {
    return temporalValidation;
  }

  try {
    const publicKey = await importJWK(toPublicJwk(parsedSigningKey.data), parsedSigningKey.data.alg);
    const verificationResult = await compactVerify(parsedInput.data.manifest.signature.jws, publicKey, {
      algorithms: [parsedAlgorithm.data]
    });
    const protectedHeader = decodeProtectedHeader(parsedInput.data.manifest.signature.jws);

    if (
      protectedHeader.alg !== parsedInput.data.manifest.signature.alg ||
      protectedHeader.kid !== parsedInput.data.manifest.signature.kid
    ) {
      return err('manifest_signature_invalid', 'Manifest JWS protected header does not match signature metadata');
    }

    if (protectedHeader.typ !== SIGNING_HEADER_TYPE) {
      return err('manifest_signature_invalid', 'Manifest JWS typ header is invalid');
    }

    const expectedPayload = toCanonicalManifestPayload(unsignedManifest.value);
    if (Buffer.byteLength(expectedPayload, 'utf8') > MAX_MANIFEST_PAYLOAD_BYTES) {
      return err('manifest_invalid', `Manifest payload exceeds ${MAX_MANIFEST_PAYLOAD_BYTES} bytes`);
    }

    const verifiedPayload = textDecoder.decode(verificationResult.payload);
    if (verifiedPayload !== expectedPayload) {
      return err('manifest_payload_mismatch', 'Manifest payload does not match signed JWS payload');
    }

    return ok({
      manifest: parsedInput.data.manifest,
      unsigned_manifest: unsignedManifest.value,
      signing_key: parsedSigningKey.data
    });
  } catch {
    return err('manifest_signature_invalid', 'Manifest JWS verification failed');
  }
};

export const computeManifestKeysEtag = ({
  manifest_keys
}: {
  manifest_keys: ManifestKeysContract;
}): CryptoResult<string> => {
  const parsedManifestKeys = OpenApiManifestKeysSchema.safeParse(manifest_keys);
  if (!parsedManifestKeys.success) {
    return err('invalid_input', parsedManifestKeys.error.message);
  }

  const digest = createHash('sha256')
    .update(canonicalJsonStringify(parsedManifestKeys.data), 'utf8')
    .digest('base64url');

  return ok(`W/"${digest}"`);
};

export const rotateManifestSigningKeys = async ({
  current_manifest_keys,
  signing_alg,
  new_kid,
  retain_previous_key_count
}: RotateManifestSigningKeysInput): Promise<CryptoResult<RotateManifestSigningKeysOutput>> => {
  const parsedInput = RotateManifestSigningKeysInputSchema.safeParse({
    current_manifest_keys,
    signing_alg,
    new_kid,
    retain_previous_key_count
  });
  if (!parsedInput.success) {
    return err('manifest_key_rotation_invalid', parsedInput.error.message);
  }

  const normalizedCurrentKeySet = buildManifestKeySet({
    keys: parsedInput.data.current_manifest_keys.keys
  });
  if (!normalizedCurrentKeySet.ok) {
    if (normalizedCurrentKeySet.error.code === 'manifest_key_mismatch') {
      return normalizedCurrentKeySet;
    }

    return err('manifest_key_rotation_invalid', normalizedCurrentKeySet.error.message);
  }

  const generatedKeyPair = await generateManifestSigningKeyPair({
    alg: parsedInput.data.signing_alg,
    ...(parsedInput.data.new_kid ? {kid: parsedInput.data.new_kid} : {})
  });
  if (!generatedKeyPair.ok) {
    if (generatedKeyPair.error.code === 'manifest_signing_key_invalid') {
      return generatedKeyPair;
    }

    return err('manifest_key_rotation_invalid', generatedKeyPair.error.message);
  }

  if (
    normalizedCurrentKeySet.value.keys.some(
      currentKey => currentKey.kid === generatedKeyPair.value.public_key.kid
    )
  ) {
    return err(
      'manifest_key_mismatch',
      `Manifest key rotation generated duplicate key id: ${generatedKeyPair.value.public_key.kid}`
    );
  }

  const retainedKeys = normalizedCurrentKeySet.value.keys.slice(
    0,
    parsedInput.data.retain_previous_key_count
  );
  const rotatedKeySet = buildManifestKeySet({
    keys: [generatedKeyPair.value.public_key, ...retainedKeys]
  });
  if (!rotatedKeySet.ok) {
    if (rotatedKeySet.error.code === 'manifest_key_mismatch') {
      return rotatedKeySet;
    }

    return err('manifest_key_rotation_invalid', rotatedKeySet.error.message);
  }

  const computedEtag = computeManifestKeysEtag({
    manifest_keys: rotatedKeySet.value
  });
  if (!computedEtag.ok) {
    return err('manifest_keys_etag_failed', computedEtag.error.message);
  }

  return ok({
    active_signing_private_key: generatedKeyPair.value.private_key,
    rotated_manifest_keys: rotatedKeySet.value,
    etag: computedEtag.value
  });
};
