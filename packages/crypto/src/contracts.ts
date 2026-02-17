import {z} from 'zod';

import {
  ManifestSchema,
  OpenApiManifestKeysSchema,
  OpenApiManifestSchema,
  SecretMaterialSchema,
  type OpenApiManifest,
  type OpenApiManifestKeys,
  type SecretMaterial
} from '@broker-interceptor/schemas';

export const KeyIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/u);

export const ManifestSigningAlgorithmSchema = z.enum(['EdDSA', 'ES256']);

const JwkCurveSchema = z.string().min(1).max(32);
const JwkBase64UrlComponentSchema = z.string().min(1).max(256).regex(/^[A-Za-z0-9_-]+$/u);

const ManifestSigningPublicKeyCommonSchema = z
  .object({
    kid: KeyIdSchema,
    use: z.literal('sig')
  })
  .strict();

const ManifestSigningOkpPublicKeySchema = ManifestSigningPublicKeyCommonSchema.extend({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  x: JwkBase64UrlComponentSchema,
  alg: z.literal('EdDSA')
}).strict();

const ManifestSigningEcPublicKeySchema = ManifestSigningPublicKeyCommonSchema.extend({
  kty: z.literal('EC'),
  crv: z.literal('P-256'),
  x: JwkBase64UrlComponentSchema,
  y: JwkBase64UrlComponentSchema,
  alg: z.literal('ES256')
}).strict();

export const ManifestSigningPublicKeySchema = z.union([
  ManifestSigningOkpPublicKeySchema,
  ManifestSigningEcPublicKeySchema
]);

const PrivateJwkSchema = z
  .object({
    kty: z.enum(['OKP', 'EC']),
    crv: JwkCurveSchema,
    x: JwkBase64UrlComponentSchema,
    y: JwkBase64UrlComponentSchema.optional(),
    d: JwkBase64UrlComponentSchema
  })
  .strict();

export const ManifestSigningPrivateKeySchema = z
  .object({
    kid: KeyIdSchema,
    alg: ManifestSigningAlgorithmSchema,
    private_jwk: PrivateJwkSchema
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.alg === 'EdDSA') {
      if (value.private_jwk.kty !== 'OKP') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'EdDSA signing keys must use kty=OKP',
          path: ['private_jwk', 'kty']
        });
      }

      if (value.private_jwk.crv !== 'Ed25519') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'EdDSA signing keys must use crv=Ed25519',
          path: ['private_jwk', 'crv']
        });
      }

      if (value.private_jwk.y !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'EdDSA OKP private keys must not include y',
          path: ['private_jwk', 'y']
        });
      }
      return;
    }

    if (value.private_jwk.kty !== 'EC') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ES256 signing keys must use kty=EC',
        path: ['private_jwk', 'kty']
      });
    }

    if (value.private_jwk.crv !== 'P-256') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ES256 signing keys must use crv=P-256',
        path: ['private_jwk', 'crv']
      });
    }

    if (!value.private_jwk.y) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ES256 signing keys require y',
        path: ['private_jwk', 'y']
      });
    }
  });

export const UnsignedManifestSchema = ManifestSchema.omit({
  signature: true
});

const MAX_WRAPPED_DATA_KEY_B64_LENGTH = 16_384;
const MAX_IV_B64_LENGTH = 64;
const MAX_CIPHERTEXT_B64_LENGTH = 1_398_104;
const MAX_AUTH_TAG_B64_LENGTH = 64;
const MAX_AAD_B64_LENGTH = 21_848;

export const EnvelopeCiphertextSchema = z
  .object({
    version: z.literal(1),
    content_encryption_alg: z.literal('A256GCM'),
    key_encryption_alg: z.string().trim().min(1).max(64),
    key_id: KeyIdSchema,
    wrapped_data_key_b64: z.string().min(1).max(MAX_WRAPPED_DATA_KEY_B64_LENGTH),
    iv_b64: z.string().min(1).max(MAX_IV_B64_LENGTH),
    ciphertext_b64: z.string().min(1).max(MAX_CIPHERTEXT_B64_LENGTH),
    auth_tag_b64: z.string().min(1).max(MAX_AUTH_TAG_B64_LENGTH),
    aad_b64: z.string().min(1).max(MAX_AAD_B64_LENGTH).optional()
  })
  .strict();

export const EncryptedSecretMaterialSchema = z
  .object({
    type: SecretMaterialSchema.shape.type,
    envelope: EnvelopeCiphertextSchema
  })
  .strict();

export type ManifestContract = OpenApiManifest;
export type ManifestKeysContract = OpenApiManifestKeys;
export type ManifestSigningPrivateKey = z.infer<typeof ManifestSigningPrivateKeySchema>;
export type ManifestSigningPublicKey = z.infer<typeof ManifestSigningPublicKeySchema>;
export type ManifestSigningAlgorithm = z.infer<typeof ManifestSigningAlgorithmSchema>;
export type UnsignedManifest = z.infer<typeof UnsignedManifestSchema>;
export type EnvelopeCiphertext = z.infer<typeof EnvelopeCiphertextSchema>;
export type EncryptedSecretMaterial = z.infer<typeof EncryptedSecretMaterialSchema>;
export type SecretMaterialContract = SecretMaterial;

export {
  OpenApiManifestKeysSchema,
  OpenApiManifestSchema,
  SecretMaterialSchema,
  type OpenApiManifest,
  type OpenApiManifestKeys,
  type SecretMaterial
};
