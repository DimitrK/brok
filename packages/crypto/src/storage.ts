import {
  type EnvelopeCiphertext,
  type ManifestKeysContract,
  type ManifestSigningAlgorithm,
  type ManifestSigningPrivateKey,
  type ManifestSigningPublicKey,
  type SecretMaterialContract
} from './contracts.js';
import {err, type CryptoResult} from './errors.js';

type MaybePromise<T> = T | Promise<T>;

export type StorageCallContext<TTransactionClient = unknown> = {
  transaction_client?: TTransactionClient;
};

export type SecretEnvelopeVersionRecord = {
  secret_ref: string;
  tenant_id: string;
  integration_id: string;
  secret_type: SecretMaterialContract['type'];
  version: number;
  envelope: EnvelopeCiphertext;
  created_at: string;
};

export type CreateSecretEnvelopeVersionInput = Omit<SecretEnvelopeVersionRecord, 'version'>;

export type GetSecretEnvelopeInput = {
  secret_ref: string;
  version?: number;
};

export type SetActiveSecretEnvelopeVersionInput = {
  secret_ref: string;
  version: number;
};

export type ManifestSigningKeyRecord = {
  kid: string;
  alg: ManifestSigningAlgorithm;
  public_jwk: ManifestSigningPublicKey;
  private_key_ref: string;
  status: 'active' | 'retired' | 'revoked';
  created_at: string;
  activated_at?: string;
  retired_at?: string;
  revoked_at?: string;
};

export type CreateManifestSigningKeyRecordInput = Omit<ManifestSigningKeyRecord, 'status'>;

export type SetActiveManifestSigningKeyInput = {
  kid: string;
  activated_at: string;
};

export type RetireManifestSigningKeyInput = {
  kid: string;
  retired_at: string;
};

export type RevokeManifestSigningKeyInput = {
  kid: string;
  revoked_at: string;
};

export type PersistManifestKeysetMetadataInput = {
  etag: string;
  generated_at: string;
  max_age_seconds: number;
};

export type AcquireCryptoRotationLockInput = {
  lock_name: string;
  ttl_ms: number;
};

export type AcquireCryptoRotationLockOutput = {
  token: string;
  acquired_at: string;
};

export type ReleaseCryptoRotationLockInput = {
  lock_name: string;
  token: string;
};

export type ManifestVerificationKeysetWithEtag = {
  manifest_keys: ManifestKeysContract;
  etag: string;
  generated_at: string;
  max_age_seconds?: number;
};

export type CryptoVerificationDefaults = {
  tenant_id: string;
  require_temporal_validity: boolean;
  max_clock_skew_seconds: number;
};

export type GetCryptoVerificationDefaultsByTenantInput = {
  tenant_id: string;
};

export type UpsertCryptoVerificationDefaultsInput = CryptoVerificationDefaults;

export type CryptoRotationLockAcquireResult = {
  acquired: boolean;
  token: string;
};

export type CryptoRotationLockReleaseResult = {
  released: boolean;
};

export type RotateManifestSigningKeysWithStoreInput = {
  current_manifest_keys: ManifestKeysContract;
  signing_alg: ManifestSigningAlgorithm;
  new_kid?: string;
  retain_previous_key_count: number;
};

export type RotateManifestSigningKeysWithStoreOutput = {
  active_signing_private_key: ManifestSigningPrivateKey;
  rotated_manifest_keys: ManifestKeysContract;
  etag: string;
};

export type CryptoStorageRepositories_INCOMPLETE<TTransactionClient = unknown> = {
  createSecretEnvelopeVersion?: (
    input: CreateSecretEnvelopeVersionInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<SecretEnvelopeVersionRecord>>;
  getActiveSecretEnvelope?: (
    input: GetSecretEnvelopeInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<SecretEnvelopeVersionRecord>>;
  getSecretEnvelopeVersion?: (
    input: GetSecretEnvelopeInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<SecretEnvelopeVersionRecord>>;
  setActiveSecretEnvelopeVersion?: (
    input: SetActiveSecretEnvelopeVersionInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<null>>;
  createManifestSigningKeyRecord?: (
    input: CreateManifestSigningKeyRecordInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<ManifestSigningKeyRecord>>;
  getActiveManifestSigningKeyRecord?: (
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<ManifestSigningKeyRecord>>;
  setActiveManifestSigningKey?: (
    input: SetActiveManifestSigningKeyInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<null>>;
  retireManifestSigningKey?: (
    input: RetireManifestSigningKeyInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<null>>;
  revokeManifestSigningKey?: (
    input: RevokeManifestSigningKeyInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<null>>;
  listManifestVerificationKeysWithEtag?: (
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<ManifestVerificationKeysetWithEtag>>;
  persistManifestKeysetMetadata?: (
    input: PersistManifestKeysetMetadataInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<null>>;
  acquireCryptoRotationLock?: (
    input: AcquireCryptoRotationLockInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<CryptoRotationLockAcquireResult>>;
  releaseCryptoRotationLock?: (
    input: ReleaseCryptoRotationLockInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<CryptoRotationLockReleaseResult>>;
  getCryptoVerificationDefaultsByTenant?: (
    input: GetCryptoVerificationDefaultsByTenantInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<CryptoVerificationDefaults>>;
  upsertCryptoVerificationDefaults?: (
    input: UpsertCryptoVerificationDefaultsInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<CryptoVerificationDefaults>>;
  rotateManifestSigningKeysWithStore?: (
    input: RotateManifestSigningKeysWithStoreInput,
    context?: StorageCallContext<TTransactionClient>
  ) => MaybePromise<CryptoResult<RotateManifestSigningKeysWithStoreOutput>>;
};

export type CryptoStorageService_INCOMPLETE<TTransactionClient = unknown> = {
  createSecretEnvelopeVersion_INCOMPLETE: (
    input: CreateSecretEnvelopeVersionInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<SecretEnvelopeVersionRecord>>;
  getActiveSecretEnvelope_INCOMPLETE: (
    input: GetSecretEnvelopeInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<SecretEnvelopeVersionRecord>>;
  getSecretEnvelopeVersion_INCOMPLETE: (
    input: GetSecretEnvelopeInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<SecretEnvelopeVersionRecord>>;
  setActiveSecretEnvelopeVersion_INCOMPLETE: (
    input: SetActiveSecretEnvelopeVersionInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<null>>;
  createManifestSigningKeyRecord_INCOMPLETE: (
    input: CreateManifestSigningKeyRecordInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<ManifestSigningKeyRecord>>;
  getActiveManifestSigningKeyRecord_INCOMPLETE: (
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<ManifestSigningKeyRecord>>;
  setActiveManifestSigningKey_INCOMPLETE: (
    input: SetActiveManifestSigningKeyInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<null>>;
  retireManifestSigningKey_INCOMPLETE: (
    input: RetireManifestSigningKeyInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<null>>;
  revokeManifestSigningKey_INCOMPLETE: (
    input: RevokeManifestSigningKeyInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<null>>;
  listManifestVerificationKeysWithEtag_INCOMPLETE: (
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<ManifestVerificationKeysetWithEtag>>;
  persistManifestKeysetMetadata_INCOMPLETE: (
    input: PersistManifestKeysetMetadataInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<null>>;
  acquireCryptoRotationLock_INCOMPLETE: (
    input: AcquireCryptoRotationLockInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<CryptoRotationLockAcquireResult>>;
  releaseCryptoRotationLock_INCOMPLETE: (
    input: ReleaseCryptoRotationLockInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<CryptoRotationLockReleaseResult>>;
  getCryptoVerificationDefaultsByTenant_INCOMPLETE: (
    input: GetCryptoVerificationDefaultsByTenantInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<CryptoVerificationDefaults>>;
  upsertCryptoVerificationDefaults_INCOMPLETE: (
    input: UpsertCryptoVerificationDefaultsInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<CryptoVerificationDefaults>>;
  rotateManifestSigningKeysWithStore_INCOMPLETE: (
    input: RotateManifestSigningKeysWithStoreInput,
    context?: StorageCallContext<TTransactionClient>
  ) => Promise<CryptoResult<RotateManifestSigningKeysWithStoreOutput>>;
};

const missingStoreDependency = <TOutput, TInput>(
  methodName: string,
  requiredStoreMethod: string,
  input?: TInput,
  context?: StorageCallContext
): CryptoResult<TOutput> => {
  void input;
  void context;
  return err(
    'invalid_input',
    `${methodName} is _INCOMPLETE and requires @broker-interceptor/db.${requiredStoreMethod} integration`
  );
};

const callRepositoryWithInput_INCOMPLETE = async <TInput, TOutput, TTransactionClient>(
  repository:
    | ((input: TInput, context?: StorageCallContext<TTransactionClient>) => MaybePromise<CryptoResult<TOutput>>)
    | undefined,
  methodName: string,
  requiredStoreMethod: string,
  input: TInput,
  context?: StorageCallContext<TTransactionClient>
): Promise<CryptoResult<TOutput>> => {
  if (!repository) {
    return missingStoreDependency<TOutput, TInput>(methodName, requiredStoreMethod, input, context);
  }

  return repository(input, context);
};

const callRepositoryNoInput_INCOMPLETE = async <TOutput, TTransactionClient>(
  repository:
    | ((context?: StorageCallContext<TTransactionClient>) => MaybePromise<CryptoResult<TOutput>>)
    | undefined,
  methodName: string,
  requiredStoreMethod: string,
  context?: StorageCallContext<TTransactionClient>
): Promise<CryptoResult<TOutput>> => {
  if (!repository) {
    return missingStoreDependency<TOutput, undefined>(methodName, requiredStoreMethod, undefined, context);
  }

  return repository(context);
};

export const createCryptoStorageService_INCOMPLETE = <TTransactionClient = unknown>(
  repositories: CryptoStorageRepositories_INCOMPLETE<TTransactionClient>
): CryptoStorageService_INCOMPLETE<TTransactionClient> => ({
  createSecretEnvelopeVersion_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.createSecretEnvelopeVersion,
      'createSecretEnvelopeVersion_INCOMPLETE',
      'createSecretEnvelopeVersion',
      input,
      context
    ),
  getActiveSecretEnvelope_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.getActiveSecretEnvelope,
      'getActiveSecretEnvelope_INCOMPLETE',
      'getActiveSecretEnvelope',
      input,
      context
    ),
  getSecretEnvelopeVersion_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.getSecretEnvelopeVersion,
      'getSecretEnvelopeVersion_INCOMPLETE',
      'getSecretEnvelopeVersion',
      input,
      context
    ),
  setActiveSecretEnvelopeVersion_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.setActiveSecretEnvelopeVersion,
      'setActiveSecretEnvelopeVersion_INCOMPLETE',
      'setActiveSecretEnvelopeVersion',
      input,
      context
    ),
  createManifestSigningKeyRecord_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.createManifestSigningKeyRecord,
      'createManifestSigningKeyRecord_INCOMPLETE',
      'createManifestSigningKeyRecord',
      input,
      context
    ),
  getActiveManifestSigningKeyRecord_INCOMPLETE: context =>
    callRepositoryNoInput_INCOMPLETE(
      repositories.getActiveManifestSigningKeyRecord,
      'getActiveManifestSigningKeyRecord_INCOMPLETE',
      'getActiveManifestSigningKeyRecord',
      context
    ),
  setActiveManifestSigningKey_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.setActiveManifestSigningKey,
      'setActiveManifestSigningKey_INCOMPLETE',
      'setActiveManifestSigningKey',
      input,
      context
    ),
  retireManifestSigningKey_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.retireManifestSigningKey,
      'retireManifestSigningKey_INCOMPLETE',
      'retireManifestSigningKey',
      input,
      context
    ),
  revokeManifestSigningKey_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.revokeManifestSigningKey,
      'revokeManifestSigningKey_INCOMPLETE',
      'revokeManifestSigningKey',
      input,
      context
    ),
  listManifestVerificationKeysWithEtag_INCOMPLETE: context =>
    callRepositoryNoInput_INCOMPLETE(
      repositories.listManifestVerificationKeysWithEtag,
      'listManifestVerificationKeysWithEtag_INCOMPLETE',
      'listManifestVerificationKeysWithEtag',
      context
    ),
  persistManifestKeysetMetadata_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.persistManifestKeysetMetadata,
      'persistManifestKeysetMetadata_INCOMPLETE',
      'persistManifestKeysetMetadata',
      input,
      context
    ),
  acquireCryptoRotationLock_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.acquireCryptoRotationLock,
      'acquireCryptoRotationLock_INCOMPLETE',
      'acquireCryptoRotationLock',
      input,
      context
    ),
  releaseCryptoRotationLock_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.releaseCryptoRotationLock,
      'releaseCryptoRotationLock_INCOMPLETE',
      'releaseCryptoRotationLock',
      input,
      context
    ),
  getCryptoVerificationDefaultsByTenant_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.getCryptoVerificationDefaultsByTenant,
      'getCryptoVerificationDefaultsByTenant_INCOMPLETE',
      'getCryptoVerificationDefaultsByTenant',
      input,
      context
    ),
  upsertCryptoVerificationDefaults_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.upsertCryptoVerificationDefaults,
      'upsertCryptoVerificationDefaults_INCOMPLETE',
      'upsertCryptoVerificationDefaults',
      input,
      context
    ),
  rotateManifestSigningKeysWithStore_INCOMPLETE: (input, context) =>
    callRepositoryWithInput_INCOMPLETE(
      repositories.rotateManifestSigningKeysWithStore,
      'rotateManifestSigningKeysWithStore_INCOMPLETE',
      'rotateManifestSigningKeysWithStore',
      input,
      context
    )
});

export const createSecretEnvelopeVersion_INCOMPLETE = (
  input: CreateSecretEnvelopeVersionInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency('createSecretEnvelopeVersion_INCOMPLETE', 'createSecretEnvelopeVersion', input, context);

export const getActiveSecretEnvelope_INCOMPLETE = (
  input: GetSecretEnvelopeInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency('getActiveSecretEnvelope_INCOMPLETE', 'getActiveSecretEnvelope', input, context);

export const getSecretEnvelopeVersion_INCOMPLETE = (
  input: GetSecretEnvelopeInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency('getSecretEnvelopeVersion_INCOMPLETE', 'getSecretEnvelopeVersion', input, context);

export const setActiveSecretEnvelopeVersion_INCOMPLETE = (
  input: SetActiveSecretEnvelopeVersionInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'setActiveSecretEnvelopeVersion_INCOMPLETE',
    'setActiveSecretEnvelopeVersion',
    input,
    context
  );

export const createManifestSigningKeyRecord_INCOMPLETE = (
  input: CreateManifestSigningKeyRecordInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'createManifestSigningKeyRecord_INCOMPLETE',
    'createManifestSigningKeyRecord',
    input,
    context
  );

export const getActiveManifestSigningKeyRecord_INCOMPLETE = (
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'getActiveManifestSigningKeyRecord_INCOMPLETE',
    'getActiveManifestSigningKeyRecord',
    undefined,
    context
  );

export const setActiveManifestSigningKey_INCOMPLETE = (
  input: SetActiveManifestSigningKeyInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'setActiveManifestSigningKey_INCOMPLETE',
    'setActiveManifestSigningKey',
    input,
    context
  );

export const retireManifestSigningKey_INCOMPLETE = (
  input: RetireManifestSigningKeyInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'retireManifestSigningKey_INCOMPLETE',
    'retireManifestSigningKey',
    input,
    context
  );

export const revokeManifestSigningKey_INCOMPLETE = (
  input: RevokeManifestSigningKeyInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'revokeManifestSigningKey_INCOMPLETE',
    'revokeManifestSigningKey',
    input,
    context
  );

export const listManifestVerificationKeysWithEtag_INCOMPLETE = (
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'listManifestVerificationKeysWithEtag_INCOMPLETE',
    'listManifestVerificationKeysWithEtag',
    undefined,
    context
  );

export const persistManifestKeysetMetadata_INCOMPLETE = (
  input: PersistManifestKeysetMetadataInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'persistManifestKeysetMetadata_INCOMPLETE',
    'persistManifestKeysetMetadata',
    input,
    context
  );

export const acquireCryptoRotationLock_INCOMPLETE = (
  input: AcquireCryptoRotationLockInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency('acquireCryptoRotationLock_INCOMPLETE', 'acquireCryptoRotationLock', input, context);

export const releaseCryptoRotationLock_INCOMPLETE = (
  input: ReleaseCryptoRotationLockInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency('releaseCryptoRotationLock_INCOMPLETE', 'releaseCryptoRotationLock', input, context);

export const getCryptoVerificationDefaultsByTenant_INCOMPLETE = (
  input: GetCryptoVerificationDefaultsByTenantInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'getCryptoVerificationDefaultsByTenant_INCOMPLETE',
    'getCryptoVerificationDefaultsByTenant',
    input,
    context
  );

export const upsertCryptoVerificationDefaults_INCOMPLETE = (
  input: UpsertCryptoVerificationDefaultsInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'upsertCryptoVerificationDefaults_INCOMPLETE',
    'upsertCryptoVerificationDefaults',
    input,
    context
  );

export const rotateManifestSigningKeysWithStore_INCOMPLETE = (
  input: RotateManifestSigningKeysWithStoreInput,
  context?: StorageCallContext
): CryptoResult<never> =>
  missingStoreDependency(
    'rotateManifestSigningKeysWithStore_INCOMPLETE',
    'rotateManifestSigningKeysWithStore',
    input,
    context
  );
