# @broker-interceptor/crypto

Security-focused crypto package for broker envelope encryption and manifest signing.

## Package Scope

`@broker-interceptor/crypto` owns:

- Envelope encryption primitives for secret material (`A256GCM` + key wrapping abstraction)
- Manifest signing and verification primitives (JWS, `EdDSA`/`ES256`)
- Key-id generation/validation helpers
- Deterministic manifest key-set ETag hashing

DTO/runtime contracts are sourced from:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/schemas/openapi.yaml`
- `@broker-interceptor/schemas` exports

## Exposed Interface

Main exports from `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/index.ts`:

- Envelope:
`buildEnvelopeAad`, `createAesGcmKeyManagementService`, `encryptWithEnvelope`, `decryptWithEnvelope`, `encryptSecretMaterial`, `decryptSecretMaterial`
- Manifest signing:
`generateManifestSigningKeyPair`, `buildManifestKeySet`, `rotateManifestSigningKeys`, `signManifest`, `verifyManifestSignature`, `stripManifestSignature`, `toCanonicalManifestPayload`, `computeManifestKeysEtag`
- Storage factory contracts:
`createCryptoStorageService_INCOMPLETE`, `StorageCallContext`, `CryptoStorageRepositories_INCOMPLETE`, `CryptoStorageService_INCOMPLETE`
- Storage bridge placeholders:
`createSecretEnvelopeVersion_INCOMPLETE`, `getActiveSecretEnvelope_INCOMPLETE`, `getSecretEnvelopeVersion_INCOMPLETE`, `setActiveSecretEnvelopeVersion_INCOMPLETE`, `createManifestSigningKeyRecord_INCOMPLETE`, `getActiveManifestSigningKeyRecord_INCOMPLETE`, `setActiveManifestSigningKey_INCOMPLETE`, `retireManifestSigningKey_INCOMPLETE`, `revokeManifestSigningKey_INCOMPLETE`, `listManifestVerificationKeysWithEtag_INCOMPLETE`, `persistManifestKeysetMetadata_INCOMPLETE`, `acquireCryptoRotationLock_INCOMPLETE`, `releaseCryptoRotationLock_INCOMPLETE`, `getCryptoVerificationDefaultsByTenant_INCOMPLETE`, `upsertCryptoVerificationDefaults_INCOMPLETE`, `rotateManifestSigningKeysWithStore_INCOMPLETE`
- Key/id + encoding:
`generateKeyId`, `KeyIdSchema`, `decodeBase64`, `encodeBase64`, `equalByteArrays`
- Contracts + result/error:
`ManifestSigningPrivateKeySchema`, `EnvelopeCiphertextSchema`, `CryptoResult`, `ok`, `err`, and exported crypto types

## Usage

### 1) Envelope encryption

```ts
import {
  buildEnvelopeAad,
  createAesGcmKeyManagementService,
  encryptSecretMaterial,
  decryptSecretMaterial
} from '@broker-interceptor/crypto';

const kms = createAesGcmKeyManagementService({
  active_key_id: 'kek_v1',
  keys: {
    kek_v1: Buffer.alloc(32, 1).toString('base64')
  }
});
if (!kms.ok) throw new Error(kms.error.message);

const aad = buildEnvelopeAad({
  tenant_id: 't_1',
  integration_id: 'i_1',
  secret_type: 'api_key'
});

const encrypted = await encryptSecretMaterial({
  secret_material: {type: 'api_key', value: 'sk-live-123'},
  key_management_service: kms.value,
  requested_key_id: 'kek_v1',
  aad
});
if (!encrypted.ok) throw new Error(encrypted.error.message);

const decrypted = await decryptSecretMaterial({
  encrypted_secret_material: encrypted.value,
  key_management_service: kms.value,
  expected_aad: aad
});
if (!decrypted.ok) throw new Error(decrypted.error.message);
```

### 2) Manifest sign/verify

```ts
import {
  generateManifestSigningKeyPair,
  buildManifestKeySet,
  signManifest,
  verifyManifestSignature
} from '@broker-interceptor/crypto';

const keyPair = await generateManifestSigningKeyPair({alg: 'EdDSA', kid: 'manifest_v1'});
if (!keyPair.ok) throw new Error(keyPair.error.message);

const keySet = buildManifestKeySet({keys: [keyPair.value.public_key]});
if (!keySet.ok) throw new Error(keySet.error.message);

const signed = await signManifest({
  manifest: unsignedManifest,
  signing_key: keyPair.value.private_key
});
if (!signed.ok) throw new Error(signed.error.message);

const verified = await verifyManifestSignature({
  manifest: signed.value,
  manifest_keys: keySet.value
});
if (!verified.ok) throw new Error(verified.error.message);
```

### 3) Storage integration (app-owned clients)

```ts
import {createCryptoStorageService_INCOMPLETE} from '@broker-interceptor/crypto';

const cryptoStorage = createCryptoStorageService_INCOMPLETE({
  createSecretEnvelopeVersion: (input, context) =>
    secretRepo.createVersion(input, {
      tx: context?.transaction_client
    }),
  getActiveManifestSigningKeyRecord: context =>
    keyRepo.getActiveKey({
      tx: context?.transaction_client
    })
});

// App controls DB lifecycle and can pass a shared transaction client down the call chain.
const result = await cryptoStorage.getActiveManifestSigningKeyRecord_INCOMPLETE({
  transaction_client: txClient
});
if (!result.ok) throw new Error(result.error.message);
```

## `_INCOMPLETE` Tracking (Crypto Domain)

### Internal `packages/crypto` incomplete methods

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `createSecretEnvelopeVersion_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.createSecretEnvelopeVersion` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `getActiveSecretEnvelope_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.getActiveSecretEnvelope` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `getSecretEnvelopeVersion_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.getSecretEnvelopeVersion` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `setActiveSecretEnvelopeVersion_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.setActiveSecretEnvelopeVersion` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `createManifestSigningKeyRecord_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.createManifestSigningKeyRecord` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `getActiveManifestSigningKeyRecord_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.getActiveManifestSigningKeyRecord` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `setActiveManifestSigningKey_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.setActiveManifestSigningKey` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `retireManifestSigningKey_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.retireManifestSigningKey` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `revokeManifestSigningKey_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.revokeManifestSigningKey` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `listManifestVerificationKeysWithEtag_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.listManifestVerificationKeysWithEtag` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `persistManifestKeysetMetadata_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.persistManifestKeysetMetadata` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `acquireCryptoRotationLock_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.acquireCryptoRotationLock` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `releaseCryptoRotationLock_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.releaseCryptoRotationLock` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `getCryptoVerificationDefaultsByTenant_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.getCryptoVerificationDefaultsByTenant` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `upsertCryptoVerificationDefaults_INCOMPLETE`
Dependency module/method: `@broker-interceptor/db.upsertCryptoVerificationDefaults` (available, app wiring pending)

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/src/storage.ts` -> `rotateManifestSigningKeysWithStore_INCOMPLETE`
Dependency module/method: app-injected `rotateManifestSigningKeysWithStore` repository implementation (pending wiring in consuming app)

### External local wiring methods pending package/module implementation

1. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/crypto.ts` -> `createLocalEnvelopeKms_INCOMPLETE`
Pending package/module:
KMS adapter package (TBD)
Missing methods expected from that module:
- `wrapDataKey`
- `unwrapDataKey`

2. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/crypto.ts` -> `encryptSecretMaterialWithCryptoPackage_INCOMPLETE`
Pending package/module:
KMS adapter package (TBD)
Missing methods expected from that module:
- `wrapDataKey`

3. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/crypto.ts` -> `decryptSecretMaterialWithCryptoPackage_INCOMPLETE`
Pending package/module:
KMS adapter package (TBD)
Missing methods expected from that module:
- `unwrapDataKey`

4. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/crypto.ts` -> `computeManifestKeysWeakEtagWithCryptoPackage_INCOMPLETE`
Pending package/module:
`@broker-interceptor/crypto` integration finalization
Missing methods:
- none in `packages/crypto` (method is a bridge naming placeholder)

5. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` -> `rotateManifestSigningKeysWithCryptoPackage_INCOMPLETE`
Pending package/module:
Persistence/key-management workflow modules (crypto primitive is now implemented)
Missing methods expected for full workflow wiring:
- `rotateManifestSigningKeys` usage wiring
- persistent key rotation storage orchestration (module-specific method TBD)

6. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/src/dependencyBridge.ts` -> `loadActiveManifestSigningKeyFromKms_INCOMPLETE`
Pending package/module:
KMS adapter package (TBD)
Missing methods expected from that module:
- active manifest signing key loader (module-specific method TBD)

7. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/src/dependencyBridge.ts` -> `signManifestWithCryptoPackage_INCOMPLETE`
Pending package/module:
KMS adapter package (TBD) for signing key source
Missing methods expected from that module:
- active manifest signing key loader (module-specific method TBD)

8. Local wiring method:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/src/dependencyBridge.ts` -> `verifyManifestSignatureWithCryptoPackage_INCOMPLETE`
Pending package/module:
Manifest key persistence module
Missing methods expected from that module:
- manifest verification key retrieval (`getManifestSigningKeys` or equivalent)

## Pending feedback

- No open feedback requests from `packages/crypto` at this time.
- Latest DB follow-up response received and applied:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/external_feedback/broker-interceptor/crypto/archive/missing_store_data_response_3.md`
- Remaining `_INCOMPLETE` status is now primarily app wiring for repository injection and cross-package orchestration.

## Quality

Run:

```bash
pnpm --filter @broker-interceptor/crypto run lint
pnpm --filter @broker-interceptor/crypto run test
pnpm --filter @broker-interceptor/crypto run test:coverage
```

Latest coverage for this package:

- Statements: `84.31%`
- Branches: `87.16%`
- Functions: `80.28%`
- Lines: `84.31%`
