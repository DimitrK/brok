import {createHash, randomUUID} from 'node:crypto';
import {promises as fs} from 'node:fs';
import path from 'node:path';

import {
  createAuthStorageScope,
  type AuthStorageScope,
  type SessionRecord as AuthSessionRecord,
  type WorkloadRecord as AuthWorkloadRecord
} from '@broker-interceptor/auth';
import {
  buildManifestKeySet,
  createCryptoStorageService_INCOMPLETE,
  err as cryptoErr,
  generateManifestSigningKeyPair,
  ManifestSigningPublicKeySchema,
  ManifestSigningPrivateKeySchema,
  ok as cryptoOk,
  rotateManifestSigningKeys,
  type CryptoStorageService_INCOMPLETE,
  type ManifestSigningKeyRecord,
  type ManifestSigningPrivateKey
} from '@broker-interceptor/crypto';
import {
  createCryptoRedisRotationLockAdapter,
  createForwarderRedisAdapter,
  type RedisEvalClient
} from '@broker-interceptor/db';
import {
  createForwarderDbDependencyBridge_INCOMPLETE,
  type ForwarderDbDependencyBridge
} from '@broker-interceptor/forwarder';
import {
  createSsrfGuardStorageBridge_INCOMPLETE,
  DnsRebindingObservationSchema,
  DnsResolutionCacheEntrySchema,
  SsrfDecisionProjectionSchema,
  TemplateInvalidationSignalSchema,
  type SsrfGuardErrorCode,
  type SsrfGuardStorageBridge,
  type StorageScope
} from '@broker-interceptor/ssrf-guard';
import {
  ApprovalRequestSchema,
  OpenApiHeaderListSchema,
  OpenApiIntegrationSchema,
  OpenApiManifestKeysSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateSchema,
  OpenApiWorkloadSchema,
  type ApprovalRequest,
  type CanonicalRequestDescriptor,
  type OpenApiHeaderList,
  type OpenApiIntegration,
  type OpenApiManifestKeys,
  type OpenApiPolicyRule,
  type OpenApiTemplate,
  type OpenApiWorkload
} from '@broker-interceptor/schemas';
import {z} from 'zod';
import type {Prisma} from '@prisma/client';

import type {BrokerRedisClient, ProcessInfrastructure} from './infrastructure';

const sessionRecordSchema = z
  .object({
    session_id: z.string().min(1),
    workload_id: z.string().min(1),
    tenant_id: z.string().min(1),
    cert_fingerprint256: z.string().min(1),
    token_hash: z.string().min(1),
    expires_at: z.string().datetime({offset: true}),
    dpop_jkt: z.string().min(1).optional(),
    scopes: z.array(z.string()).default([])
  })
  .strict();

const integrationSecretHeadersSchema = z.record(z.string(), OpenApiHeaderListSchema);
const manifestSigningPrivateKeyMaterialSchema = z
  .object({
    private_key_ref: z.string().min(1),
    private_key: ManifestSigningPrivateKeySchema,
    status: z.enum(['active', 'retired']),
    created_at: z.string().datetime({offset: true})
  })
  .strict();

const persistedDataPlaneStateSchema = z
  .object({
    version: z.literal(1).default(1),
    workloads: z.array(OpenApiWorkloadSchema).default([]),
    integrations: z.array(OpenApiIntegrationSchema).default([]),
    templates: z.array(OpenApiTemplateSchema).default([]),
    policies: z.array(OpenApiPolicyRuleSchema).default([]),
    approvals: z.array(ApprovalRequestSchema).default([]),
    sessions: z.array(sessionRecordSchema).default([]),
    integration_secret_headers: integrationSecretHeadersSchema.default({}),
    dpop_required_workload_ids: z.array(z.string()).default([]),
    dpop_required_tenant_ids: z.array(z.string()).default([]),
    manifest_signing_private_keys: z.array(manifestSigningPrivateKeyMaterialSchema).default([]),
    manifest_signing_active_private_key_ref: z.string().min(1).optional(),
    manifest_signing_private_key: ManifestSigningPrivateKeySchema.optional(),
    manifest_keys: OpenApiManifestKeysSchema.optional()
  })
  .strict();

type PersistedDataPlaneState = z.infer<typeof persistedDataPlaneStateSchema>;
type SessionRecord = z.infer<typeof sessionRecordSchema>;
type ManifestSigningPrivateKeyMaterial = z.infer<typeof manifestSigningPrivateKeyMaterialSchema>;
type SsrfDecisionProjection = z.infer<typeof SsrfDecisionProjectionSchema>;
type TemplateInvalidationSignal = z.infer<typeof TemplateInvalidationSignalSchema>;

type SessionSaveInput = {
  sessionId: string;
  workloadId: string;
  tenantId: string;
  certFingerprint256: string;
  tokenHash: string;
  expiresAt: string;
  dpopKeyThumbprint?: string;
};

type RateLimitCounter = {
  count: number;
  resetAtMs: number;
};
type AuthSessionRecordWithScopes = AuthSessionRecord & {
  scopes?: string[];
};

type RotationLockAdapter = ReturnType<typeof createCryptoRedisRotationLockAdapter>;

/**
 * Wraps a node-redis v4 client to match the RedisEvalClient interface.
 * RedisEvalClient expects: eval(script, keys[], args[])
 * node-redis v4 uses: eval(script, {keys: [...], arguments: [...]})
 */
const toRedisEvalClient = (redis: BrokerRedisClient): RedisEvalClient => ({
  get: key => redis.get(key),
  set: async (key, value, options) => (await redis.set(key, value, options)) as 'OK' | null,
  del: (...keys) => redis.del(keys),
  eval: (script, keys, args) => redis.eval(script, {keys, arguments: args.map(arg => String(arg))})
});

type ManifestTemplateRule = {
  integration_id: string;
  provider: string;
  hosts: string[];
  schemes: Array<'https'>;
  ports: number[];
  path_groups: string[];
};
type SsrfTemplateBindingState = {
  template_id: string;
  version: number;
};
type SharedManifestRotationRequest = {
  reason: string;
  retainPreviousKeyCount: number;
};
type ForwarderIdempotencyScope = {
  tenant_id: string;
  workload_id: string;
  integration_id: string;
  action_group: string;
  idempotency_key: string;
};
type ForwarderIdempotencyRecordCreateResult = {
  created: boolean;
  conflict: null | 'key_exists' | 'fingerprint_mismatch';
};
type ForwarderIdempotencyRecordUpdateResult = {
  updated: boolean;
};
type ForwarderIdempotencyRecordView = {
  state: 'in_progress' | 'completed' | 'failed';
  request_fingerprint_sha256: string;
  correlation_id: string;
  created_at: string;
  expires_at: string;
  upstream_status_code?: number;
  response_bytes?: number;
  error_code?: string;
};

const clone = <T>(value: T): T => structuredClone(value);
const manifestStatePrivateKeyReferencePrefix = 'state://manifest-signing-key/';
const manifestRotationLockName = 'manifest-signing-rotation';
const manifestRotationLockTtlMs = 30_000;
const forwarderIdempotencyRecordViewSchema = z
  .object({
    state: z.enum(['in_progress', 'completed', 'failed']),
    request_fingerprint_sha256: z.string().min(1),
    correlation_id: z.string().min(1),
    created_at: z.string().datetime({offset: true}),
    expires_at: z.string().datetime({offset: true}),
    upstream_status_code: z.number().int().min(100).max(599).optional(),
    response_bytes: z.number().int().min(0).optional(),
    error_code: z.string().min(1).optional()
  })
  .passthrough();

const privateKeyRefForKid = (kid: string) => `${manifestStatePrivateKeyReferencePrefix}${kid}`;
const kidFromPrivateKeyRef = (privateKeyRef: string): string | null => {
  if (!privateKeyRef.startsWith(manifestStatePrivateKeyReferencePrefix)) {
    return null;
  }
  const kid = privateKeyRef.slice(manifestStatePrivateKeyReferencePrefix.length);
  return kid.length > 0 ? kid : null;
};

const nowIso = () => new Date().toISOString();

const descriptorFingerprint = (descriptor: CanonicalRequestDescriptor) =>
  createHash('sha256').update(JSON.stringify(descriptor)).digest('hex');

const etagForManifestKeys = (keys: OpenApiManifestKeys) => {
  const stableKeys = [...keys.keys].sort((left, right) => left.kid.localeCompare(right.kid));
  const hash = createHash('sha256').update(JSON.stringify(stableKeys)).digest('hex');
  return `W/"${hash}"`;
};

const defaultState = (): PersistedDataPlaneState =>
  persistedDataPlaneStateSchema.parse({
    version: 1,
    workloads: [],
    integrations: [],
    templates: [],
    policies: [],
    approvals: [],
    sessions: [],
    integration_secret_headers: {},
    dpop_required_workload_ids: [],
    dpop_required_tenant_ids: []
  });

const parseState = (state: unknown): PersistedDataPlaneState =>
  persistedDataPlaneStateSchema.parse(state ?? defaultState());

const publicKeyFromPrivateKey = (privateKey: ManifestSigningPrivateKey) => {
  if (privateKey.alg === 'EdDSA') {
    return {
      kid: privateKey.kid,
      kty: 'OKP' as const,
      crv: 'Ed25519' as const,
      x: privateKey.private_jwk.x,
      alg: 'EdDSA' as const,
      use: 'sig' as const
    };
  }

  if (typeof privateKey.private_jwk.y !== 'string' || privateKey.private_jwk.y.length === 0) {
    throw new Error(`Manifest ES256 signing key ${privateKey.kid} is missing y coordinate`);
  }

  return {
    kid: privateKey.kid,
    kty: 'EC' as const,
    crv: 'P-256' as const,
    x: privateKey.private_jwk.x,
    y: privateKey.private_jwk.y,
    alg: 'ES256' as const,
    use: 'sig' as const
  };
};

const normalizeManifestPrivateKeyMaterials = ({
  state,
  fallbackCreatedAt
}: {
  state: PersistedDataPlaneState;
  fallbackCreatedAt: string;
}): {
  materials: ManifestSigningPrivateKeyMaterial[];
  activePrivateKeyRef: string;
} => {
  const byRef = new Map<string, ManifestSigningPrivateKeyMaterial>();

  for (const material of state.manifest_signing_private_keys) {
    const kidFromRef = kidFromPrivateKeyRef(material.private_key_ref);
    if (kidFromRef && kidFromRef !== material.private_key.kid) {
      throw new Error(
        `Manifest private key reference ${material.private_key_ref} does not match key id ${material.private_key.kid}`
      );
    }
    byRef.set(material.private_key_ref, material);
  }

  const legacyPrivateKey = state.manifest_signing_private_key;
  if (legacyPrivateKey) {
    const legacyRef = privateKeyRefForKid(legacyPrivateKey.kid);
    if (!byRef.has(legacyRef)) {
      byRef.set(
        legacyRef,
        manifestSigningPrivateKeyMaterialSchema.parse({
          private_key_ref: legacyRef,
          private_key: legacyPrivateKey,
          status: 'retired',
          created_at: fallbackCreatedAt
        })
      );
    }
  }

  if (byRef.size === 0) {
    throw new Error('Manifest private key material normalization requires at least one key');
  }

  const preferredActiveRef = state.manifest_signing_active_private_key_ref;
  const legacyActiveRef = legacyPrivateKey ? privateKeyRefForKid(legacyPrivateKey.kid) : undefined;
  const activePrivateKeyRef =
    (preferredActiveRef && byRef.has(preferredActiveRef) ? preferredActiveRef : undefined) ??
    (legacyActiveRef && byRef.has(legacyActiveRef) ? legacyActiveRef : undefined) ??
    Array.from(byRef.keys())[0];

  const materials = Array.from(byRef.values())
    .map(material =>
      manifestSigningPrivateKeyMaterialSchema.parse({
        ...material,
        status: material.private_key_ref === activePrivateKeyRef ? 'active' : 'retired'
      })
    )
    .sort((left, right) => left.private_key_ref.localeCompare(right.private_key_ref));

  return {materials, activePrivateKeyRef};
};

const mergeManifestVerificationKeys = ({
  existingKeys,
  materialKeys
}: {
  existingKeys: OpenApiManifestKeys['keys'];
  materialKeys: OpenApiManifestKeys['keys'];
}) => {
  const keysByKid = new Map<string, OpenApiManifestKeys['keys'][number]>();
  for (const key of existingKeys) {
    keysByKid.set(key.kid, key);
  }
  for (const key of materialKeys) {
    keysByKid.set(key.kid, key);
  }
  return Array.from(keysByKid.values());
};

const ensureManifestSigningMaterial = async (rawState: PersistedDataPlaneState): Promise<PersistedDataPlaneState> => {
  const fallbackCreatedAt = nowIso();
  const nextState = clone(rawState);

  if (!nextState.manifest_signing_private_key && nextState.manifest_signing_private_keys.length === 0) {
    const generated = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: `manifest_${randomUUID()}`
    });
    if (!generated.ok) {
      throw new Error(`Unable to generate manifest signing key: ${generated.error.code}`);
    }

    nextState.manifest_signing_private_key = generated.value.private_key;
    nextState.manifest_signing_private_keys = [
      manifestSigningPrivateKeyMaterialSchema.parse({
        private_key_ref: privateKeyRefForKid(generated.value.private_key.kid),
        private_key: generated.value.private_key,
        status: 'active',
        created_at: fallbackCreatedAt
      })
    ];
    nextState.manifest_signing_active_private_key_ref = privateKeyRefForKid(generated.value.private_key.kid);
  }

  const normalizedMaterials = normalizeManifestPrivateKeyMaterials({
    state: nextState,
    fallbackCreatedAt
  });
  const activeMaterial = normalizedMaterials.materials.find(
    material => material.private_key_ref === normalizedMaterials.activePrivateKeyRef
  );
  if (!activeMaterial) {
    throw new Error('Unable to determine active manifest signing private key material');
  }

  const currentKeys = rawState.manifest_keys?.keys ?? [];
  const materialKeys = normalizedMaterials.materials.map(material => publicKeyFromPrivateKey(material.private_key));
  const mergedKeys = mergeManifestVerificationKeys({
    existingKeys: currentKeys,
    materialKeys
  });

  const manifestKeysResult = buildManifestKeySet({keys: mergedKeys});
  if (!manifestKeysResult.ok) {
    throw new Error(`Unable to build manifest key set: ${manifestKeysResult.error.code}`);
  }

  return persistedDataPlaneStateSchema.parse({
    ...nextState,
    manifest_signing_private_keys: normalizedMaterials.materials,
    manifest_signing_active_private_key_ref: normalizedMaterials.activePrivateKeyRef,
    manifest_signing_private_key: activeMaterial.private_key,
    manifest_keys: manifestKeysResult.value
  });
};

const readStateFile = async ({statePath}: {statePath: string}) => {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository path is a deliberate service configuration boundary.
    const text = await fs.readFile(statePath, 'utf8');
    return parseState(JSON.parse(text) as unknown);
  } catch (error) {
    const nodeError = error as NodeJS.ErrnoException;
    if (nodeError.code === 'ENOENT') {
      return defaultState();
    }

    throw error;
  }
};

const canonicalHostFromUrl = (value: string) => new URL(value).hostname.toLowerCase();

const toSessionRecord = (value: {
  sessionId: string;
  workloadId: string;
  tenantId: string;
  certFingerprint256: string;
  tokenHash: string;
  expiresAt: string;
  dpopKeyThumbprint?: string;
  scopes?: string[];
}): SessionRecord =>
  sessionRecordSchema.parse({
    session_id: value.sessionId,
    workload_id: value.workloadId,
    tenant_id: value.tenantId,
    cert_fingerprint256: value.certFingerprint256,
    token_hash: value.tokenHash,
    expires_at: value.expiresAt,
    ...(value.dpopKeyThumbprint ? {dpop_jkt: value.dpopKeyThumbprint} : {}),
    scopes: value.scopes ?? []
  });

const toAuthSessionRecordWithScopes = ({
  session,
  scopes
}: {
  session: SessionSaveInput;
  scopes: string[];
}): AuthSessionRecordWithScopes => ({
  sessionId: session.sessionId,
  workloadId: session.workloadId,
  tenantId: session.tenantId,
  certFingerprint256: session.certFingerprint256,
  tokenHash: session.tokenHash,
  expiresAt: session.expiresAt,
  ...(session.dpopKeyThumbprint ? {dpopKeyThumbprint: session.dpopKeyThumbprint} : {}),
  scopes
});

const authSessionScopes = (value: AuthSessionRecord): string[] => {
  const unknownScopes = (value as {scopes?: unknown}).scopes;
  if (!Array.isArray(unknownScopes)) {
    return [];
  }

  return unknownScopes.filter((scope): scope is string => typeof scope === 'string');
};

const toCryptoManifestSigningKeyRecord = (record: {
  kid: string;
  alg: 'EdDSA' | 'ES256';
  public_jwk: unknown;
  private_key_ref: string;
  status: 'active' | 'retired' | 'revoked';
  created_at: string;
  activated_at?: string;
  retired_at?: string;
  revoked_at?: string;
}): ManifestSigningKeyRecord => ({
  kid: record.kid,
  alg: record.alg,
  public_jwk: ManifestSigningPublicKeySchema.parse(record.public_jwk),
  private_key_ref: record.private_key_ref,
  status: record.status,
  created_at: record.created_at,
  ...(record.activated_at ? {activated_at: record.activated_at} : {}),
  ...(record.retired_at ? {retired_at: record.retired_at} : {}),
  ...(record.revoked_at ? {revoked_at: record.revoked_at} : {})
});

const manifestPublicKeysEqual = ({
  expected,
  actual
}: {
  expected: ReturnType<typeof publicKeyFromPrivateKey>;
  actual: ManifestSigningKeyRecord['public_jwk'];
}) => {
  if (expected.kid !== actual.kid || expected.alg !== actual.alg || expected.kty !== actual.kty) {
    return false;
  }

  if (expected.kty === 'OKP' && actual.kty === 'OKP') {
    return expected.crv === actual.crv && expected.x === actual.x && expected.use === actual.use;
  }

  if (expected.kty === 'EC' && actual.kty === 'EC') {
    return (
      expected.crv === actual.crv && expected.x === actual.x && expected.y === actual.y && expected.use === actual.use
    );
  }

  return false;
};

const toErrorCode = (error: unknown) => {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return undefined;
  }

  const code = (error as {code?: unknown}).code;
  return typeof code === 'string' ? code : undefined;
};

const toErrorMessage = (error: unknown) => {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }

  return 'Unexpected dependency error';
};

const toCryptoStoreFailure = ({method, error}: {method: string; error: unknown}) => {
  const code = toErrorCode(error);
  const message = `${method}: ${toErrorMessage(error)}`;
  if (code === 'not_found') {
    return method.toLowerCase().includes('manifest')
      ? cryptoErr('manifest_key_not_found', message)
      : cryptoErr('invalid_input', message);
  }

  if (code === 'state_transition_invalid') {
    return cryptoErr('manifest_key_rotation_invalid', message);
  }

  if (code === 'unique_violation' || code === 'conflict') {
    return cryptoErr('manifest_key_rotation_invalid', message);
  }

  return cryptoErr('invalid_input', message);
};

export type DataPlaneRepositoryCreateInput = {
  statePath?: string;
  initialState?: unknown;
  approvalTtlSeconds: number;
  manifestTtlSeconds: number;
  processInfrastructure?: ProcessInfrastructure;
};

export class DataPlaneRepository {
  private readonly statePath?: string;
  private readonly approvalTtlSeconds: number;
  private readonly manifestTtlSeconds: number;
  private readonly processInfrastructure?: ProcessInfrastructure;
  private readonly authStorageScope: AuthStorageScope | null;
  private readonly cryptoStorageService: CryptoStorageService_INCOMPLETE<Prisma.TransactionClient> | null;
  private readonly forwarderDbBridge: ForwarderDbDependencyBridge<Prisma.TransactionClient> | null;
  private readonly ssrfGuardStorageBridge: SsrfGuardStorageBridge;
  private writeChain: Promise<void> = Promise.resolve();

  private readonly dpopReplayJtiExpiryByKey = new Map<string, number>();
  private readonly rateLimitCountersByKey = new Map<string, RateLimitCounter>();
  private readonly ssrfTemplateBindingsByScope = new Map<string, SsrfTemplateBindingState>();

  private constructor({
    state,
    statePath,
    approvalTtlSeconds,
    manifestTtlSeconds,
    processInfrastructure
  }: {
    state: PersistedDataPlaneState;
    statePath?: string;
    approvalTtlSeconds: number;
    manifestTtlSeconds: number;
    processInfrastructure?: ProcessInfrastructure;
  }) {
    this.state = state;
    this.statePath = statePath;
    this.approvalTtlSeconds = approvalTtlSeconds;
    this.manifestTtlSeconds = manifestTtlSeconds;
    this.processInfrastructure = processInfrastructure;
    this.authStorageScope = this.createAuthStorageScope();
    this.cryptoStorageService = this.createSharedCryptoStorageService();
    this.forwarderDbBridge = this.createForwarderDbBridge();
    this.ssrfGuardStorageBridge = this.createSsrfGuardStorageBridge();
  }

  private readonly state: PersistedDataPlaneState;

  public static async create({
    statePath,
    initialState,
    approvalTtlSeconds,
    manifestTtlSeconds,
    processInfrastructure
  }: DataPlaneRepositoryCreateInput): Promise<DataPlaneRepository> {
    const loadedState = statePath ? await readStateFile({statePath}) : parseState(initialState);
    const state = await ensureManifestSigningMaterial(loadedState);

    const repository = new DataPlaneRepository({
      state,
      statePath,
      approvalTtlSeconds,
      manifestTtlSeconds,
      processInfrastructure
    });
    await repository.ensureSharedManifestSigningMaterial();
    return repository;
  }

  private buildRedisKey({
    category,
    key
  }: {
    category: 'dpop' | 'rate_limit' | 'ssrf_dns_cache' | 'ssrf_dns_rebinding';
    key: string;
  }) {
    const prefix = this.processInfrastructure?.redisKeyPrefix ?? 'broker-api:data-plane';
    const hashedKey = createHash('sha256').update(key).digest('hex');
    return `${prefix}:${category}:${hashedKey}`;
  }

  private buildSsrfTemplateInvalidationChannel() {
    const prefix = this.processInfrastructure?.redisKeyPrefix ?? 'broker-api:data-plane';
    return `${prefix}:ssrf:template_invalidation:v1`;
  }

  private buildSsrfTemplateInvalidationOutboxKey() {
    const prefix = this.processInfrastructure?.redisKeyPrefix ?? 'broker-api:data-plane';
    return `${prefix}:ssrf:template_invalidation_outbox:v1`;
  }

  private buildSsrfDecisionProjectionOutboxKey() {
    const prefix = this.processInfrastructure?.redisKeyPrefix ?? 'broker-api:data-plane';
    return `${prefix}:ssrf:decision_projection_outbox:v1`;
  }

  private buildSsrfScopeKey(scope: StorageScope) {
    return `${scope.tenant_id}:${scope.workload_id}:${scope.integration_id}`;
  }

  private normalizeIpSet(ips: string[]) {
    return Array.from(new Set(ips.map(ip => ip.trim()).filter(ip => ip.length > 0))).sort((left, right) =>
      left.localeCompare(right)
    );
  }

  private hashIpSet(ips: string[]) {
    return createHash('sha256')
      .update(JSON.stringify(this.normalizeIpSet(ips)))
      .digest('hex');
  }

  private toRepositoryContext(transactionClient?: unknown): {transaction_client: unknown} | undefined {
    return transactionClient === undefined ? undefined : {transaction_client: transactionClient};
  }

  private resolveManifestSigningPrivateKeyByReference({
    privateKeyRef
  }: {
    privateKeyRef: string;
  }): ManifestSigningPrivateKey | null {
    const material = this.state.manifest_signing_private_keys.find(item => item.private_key_ref === privateKeyRef);
    if (material) {
      return clone(material.private_key);
    }

    const legacyManifestKey = this.state.manifest_signing_private_key;
    if (legacyManifestKey && privateKeyRefForKid(legacyManifestKey.kid) === privateKeyRef) {
      return clone(legacyManifestKey);
    }

    return null;
  }

  private getLocalManifestSigningPrivateKeyByKid({kid}: {kid: string}): ManifestSigningPrivateKey | null {
    const material = this.state.manifest_signing_private_keys.find(item => item.private_key.kid === kid);
    if (material) {
      return clone(material.private_key);
    }

    const legacyManifestKey = this.state.manifest_signing_private_key;
    if (legacyManifestKey && legacyManifestKey.kid === kid) {
      return clone(legacyManifestKey);
    }

    return null;
  }

  private async applySharedManifestRotationResult({
    activeSigningPrivateKey,
    rotatedManifestKeys,
    retainPreviousKeyCount
  }: {
    activeSigningPrivateKey: ManifestSigningPrivateKey;
    rotatedManifestKeys: OpenApiManifestKeys;
    retainPreviousKeyCount: number;
  }) {
    const activePrivateKeyRef = privateKeyRefForKid(activeSigningPrivateKey.kid);
    await this.withWriteLock(() => {
      const existingByRef = new Map(
        this.state.manifest_signing_private_keys.map(material => [material.private_key_ref, material])
      );
      const rotatedKids = new Set(rotatedManifestKeys.keys.map(key => key.kid));
      const retainedPrivateKeys = Array.from(existingByRef.values())
        .filter(
          material => material.private_key_ref !== activePrivateKeyRef && rotatedKids.has(material.private_key.kid)
        )
        .sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime())
        .slice(0, Math.max(0, retainPreviousKeyCount))
        .map(material =>
          manifestSigningPrivateKeyMaterialSchema.parse({
            ...material,
            status: 'retired'
          })
        );

      const activeMaterial = manifestSigningPrivateKeyMaterialSchema.parse({
        private_key_ref: activePrivateKeyRef,
        private_key: activeSigningPrivateKey,
        status: 'active',
        created_at: existingByRef.get(activePrivateKeyRef)?.created_at ?? nowIso()
      });

      this.state.manifest_signing_private_keys = [activeMaterial, ...retainedPrivateKeys];
      this.state.manifest_signing_active_private_key_ref = activePrivateKeyRef;
      this.state.manifest_signing_private_key = clone(activeSigningPrivateKey);
      this.state.manifest_keys = clone(rotatedManifestKeys);
    });
  }

  private async rotateManifestSigningPrivateKeyShared({
    reason,
    retainPreviousKeyCount
  }: SharedManifestRotationRequest): Promise<ManifestSigningPrivateKey> {
    const sharedCryptoStorage = this.cryptoStorageService;
    if (!sharedCryptoStorage) {
      throw new Error('Manifest signing key rotation requires shared crypto storage');
    }

    const lockResult = await sharedCryptoStorage.acquireCryptoRotationLock_INCOMPLETE({
      lock_name: manifestRotationLockName,
      ttl_ms: manifestRotationLockTtlMs
    });
    if (!lockResult.ok) {
      throw new Error(`Unable to acquire manifest signing rotation lock (${reason}): ${lockResult.error.message}`);
    }
    if (!lockResult.value.acquired) {
      throw new Error(`Manifest signing rotation lock is held by another process (${reason})`);
    }

    let operationError: unknown;
    let rotatedKey: ManifestSigningPrivateKey | null = null;
    try {
      const sharedKeysetResult = await sharedCryptoStorage.listManifestVerificationKeysWithEtag_INCOMPLETE();
      if (!sharedKeysetResult.ok && sharedKeysetResult.error.code !== 'manifest_key_not_found') {
        throw new Error(`Unable to load shared manifest keyset before rotation: ${sharedKeysetResult.error.message}`);
      }

      const currentManifestKeys = sharedKeysetResult.ok
        ? sharedKeysetResult.value.manifest_keys
        : this.getManifestVerificationKeys();
      const signingAlgorithm = this.getManifestSigningPrivateKey().alg;

      const executeRotate = async (transactionClient?: Prisma.TransactionClient) => {
        const rotateResult = await sharedCryptoStorage.rotateManifestSigningKeysWithStore_INCOMPLETE(
          {
            current_manifest_keys: currentManifestKeys,
            signing_alg: signingAlgorithm,
            retain_previous_key_count: retainPreviousKeyCount
          },
          transactionClient ? {transaction_client: transactionClient} : undefined
        );
        if (!rotateResult.ok) {
          throw new Error(`Unable to rotate manifest signing keys: ${rotateResult.error.message}`);
        }

        await this.applySharedManifestRotationResult({
          activeSigningPrivateKey: rotateResult.value.active_signing_private_key,
          rotatedManifestKeys: rotateResult.value.rotated_manifest_keys,
          retainPreviousKeyCount
        });
        return rotateResult.value.active_signing_private_key;
      };

      rotatedKey = this.isSharedInfrastructureEnabled()
        ? await this.withSharedTransaction(transactionClient => executeRotate(transactionClient))
        : await executeRotate();
    } catch (error) {
      operationError = error;
    }

    const releaseResult = await sharedCryptoStorage.releaseCryptoRotationLock_INCOMPLETE({
      lock_name: manifestRotationLockName,
      token: lockResult.value.token
    });

    if (!releaseResult.ok || !releaseResult.value.released) {
      const releaseMessage = releaseResult.ok
        ? 'Rotation lock token was not accepted by Redis'
        : releaseResult.error.message;
      if (operationError) {
        throw new Error(
          `${toErrorMessage(operationError)}; additionally failed to release rotation lock: ${releaseMessage}`
        );
      }
      if (rotatedKey) {
        return rotatedKey;
      }
      throw new Error(`Failed to release manifest signing rotation lock: ${releaseMessage}`);
    }

    if (operationError) {
      throw operationError instanceof Error ? operationError : new Error(toErrorMessage(operationError));
    }

    if (!rotatedKey) {
      throw new Error('Manifest signing key rotation completed without an active signing key result');
    }

    return rotatedKey;
  }

  private createAuthStorageScope(): AuthStorageScope | null {
    const redisClient = this.processInfrastructure?.redis;
    if (!redisClient) {
      return null;
    }

    const sharedSessionRepository = this.processInfrastructure?.dbRepositories?.sessionRepository;
    const sharedWorkloadRepository = this.processInfrastructure?.dbRepositories?.workloadRepository;
    const postgresClient = this.processInfrastructure?.prisma;

    return createAuthStorageScope({
      clients: {
        redis: redisClient as unknown as {
          get: (...args: unknown[]) => unknown;
          set: (...args: unknown[]) => unknown;
          del: (...args: unknown[]) => unknown;
        },
        ...(postgresClient ? {postgres: postgresClient as unknown as Record<string, unknown>} : {})
      },
      repositories: {
        sessionStore: {
          upsertSession: async ({session}) => {
            const scopes = authSessionScopes(session);
            if (sharedSessionRepository) {
              await sharedSessionRepository.upsertSession({
                sessionId: session.sessionId,
                workloadId: session.workloadId,
                tenantId: session.tenantId,
                certFingerprint256: session.certFingerprint256,
                tokenHash: session.tokenHash,
                expiresAt: session.expiresAt,
                ...(session.dpopKeyThumbprint ? {dpopKeyThumbprint: session.dpopKeyThumbprint} : {}),
                scopes
              });
              return;
            }

            await this.withWriteLock(() => {
              this.cleanupExpiredSessions();
              const nextRecord = sessionRecordSchema.parse({
                session_id: session.sessionId,
                workload_id: session.workloadId,
                tenant_id: session.tenantId,
                cert_fingerprint256: session.certFingerprint256,
                token_hash: session.tokenHash,
                expires_at: session.expiresAt,
                ...(session.dpopKeyThumbprint ? {dpop_jkt: session.dpopKeyThumbprint} : {}),
                scopes
              });
              this.state.sessions = this.state.sessions.filter(item => item.session_id !== nextRecord.session_id);
              this.state.sessions.push(nextRecord);
            });
          },
          getSessionByTokenHash: async ({tokenHash}) => {
            if (sharedSessionRepository) {
              const session = await sharedSessionRepository.getSessionByTokenHash({
                token_hash: tokenHash
              });
              if (!session) {
                return null;
              }

              return {
                sessionId: session.sessionId,
                workloadId: session.workloadId,
                tenantId: session.tenantId,
                certFingerprint256: session.certFingerprint256,
                tokenHash: session.tokenHash,
                expiresAt: session.expiresAt,
                ...(session.dpopKeyThumbprint ? {dpopKeyThumbprint: session.dpopKeyThumbprint} : {}),
                ...(session.scopes ? {scopes: session.scopes} : {})
              } as AuthSessionRecordWithScopes;
            }

            const session = this.getSessionByTokenHash({
              tokenHash
            });
            if (!session) {
              return null;
            }

            return {
              sessionId: session.session_id,
              workloadId: session.workload_id,
              tenantId: session.tenant_id,
              certFingerprint256: session.cert_fingerprint256,
              tokenHash: session.token_hash,
              expiresAt: session.expires_at,
              ...(session.dpop_jkt ? {dpopKeyThumbprint: session.dpop_jkt} : {}),
              scopes: clone(session.scopes)
            } as AuthSessionRecordWithScopes;
          },
          revokeSessionById: async ({sessionId}) => {
            if (sharedSessionRepository) {
              await sharedSessionRepository.revokeSessionById({
                session_id: sessionId
              });
              return;
            }

            await this.withWriteLock(() => {
              this.state.sessions = this.state.sessions.filter(item => item.session_id !== sessionId);
            });
          }
        },
        workloadStore: {
          getWorkloadBySanUri: async ({sanUri}) => {
            if (sharedWorkloadRepository) {
              const workload = await sharedWorkloadRepository.getBySanUri({
                san_uri: sanUri
              });
              if (!workload) {
                return null;
              }

              return {
                workloadId: workload.workload_id,
                tenantId: workload.tenant_id,
                enabled: workload.enabled,
                ...(workload.ip_allowlist ? {ipAllowlist: workload.ip_allowlist} : {})
              } as AuthWorkloadRecord;
            }

            const workload = this.getWorkloadBySanUri({
              sanUri
            });
            if (!workload) {
              return null;
            }

            return {
              workloadId: workload.workload_id,
              tenantId: workload.tenant_id,
              enabled: workload.enabled,
              ...(workload.ip_allowlist ? {ipAllowlist: workload.ip_allowlist} : {})
            } as AuthWorkloadRecord;
          }
        },
        replayStore: {
          reserveDpopJti: async ({replayScope, jti, expiresAt, redisClient: replayRedisClient}) => {
            const ttlMs = expiresAt.getTime() - Date.now();
            if (ttlMs <= 0) {
              return false;
            }

            const replayKey = `${replayScope}:${jti}`;
            const redisKey = this.buildRedisKey({
              category: 'dpop',
              key: replayKey
            });
            const result = await (
              replayRedisClient as unknown as {
                set: (key: string, value: string, options: {NX: boolean; PX: number}) => Promise<'OK' | null>;
              }
            ).set(redisKey, '1', {
              NX: true,
              PX: ttlMs
            });
            return result === 'OK';
          }
        }
      }
    });
  }

  private createForwarderDbBridge(): ForwarderDbDependencyBridge<Prisma.TransactionClient> | null {
    const redis = this.processInfrastructure?.redis;
    if (!redis) {
      return null;
    }

    const forwarderRedisAdapter = createForwarderRedisAdapter({
      keyPrefix: `${this.processInfrastructure?.redisKeyPrefix ?? 'broker-api:data-plane'}:forwarder`
    });

    return createForwarderDbDependencyBridge_INCOMPLETE<Prisma.TransactionClient>({
      repositories: {
        acquireForwarderExecutionLock: input =>
          forwarderRedisAdapter.acquireForwarderExecutionLock({
            scope: input.scope,
            ttl_ms: input.ttl_ms,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          }),
        releaseForwarderExecutionLock: input =>
          forwarderRedisAdapter.releaseForwarderExecutionLock({
            scope: input.scope,
            lock_token: input.lock_token,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          }),
        createForwarderIdempotencyRecord: input =>
          forwarderRedisAdapter.createForwarderIdempotencyRecord({
            scope: input.scope,
            request_fingerprint_sha256: input.request_fingerprint_sha256,
            correlation_id: input.correlation_id,
            expires_at: input.expires_at,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          }),
        getForwarderIdempotencyRecord: input =>
          forwarderRedisAdapter.getForwarderIdempotencyRecord({
            scope: input.scope,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          }),
        completeForwarderIdempotencyRecord: input =>
          forwarderRedisAdapter.completeForwarderIdempotencyRecord({
            scope: input.scope,
            correlation_id: input.correlation_id,
            upstream_status_code: input.upstream_status_code,
            response_bytes: input.response_bytes,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          }),
        failForwarderIdempotencyRecord: input =>
          forwarderRedisAdapter.failForwarderIdempotencyRecord({
            scope: input.scope,
            correlation_id: input.correlation_id,
            error_code: input.error_code,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          })
      }
    });
  }

  private getForwarderDbBridgeOrThrow({
    method
  }: {
    method: string;
  }): ForwarderDbDependencyBridge<Prisma.TransactionClient> {
    if (!this.forwarderDbBridge) {
      throw new Error(`${method}: forwarder persistence bridge is not configured`);
    }
    return this.forwarderDbBridge;
  }

  public isForwarderPersistenceEnabledShared() {
    return this.forwarderDbBridge !== null;
  }

  public async acquireForwarderExecutionLockShared({
    scope,
    ttlMs,
    transactionClient
  }: {
    scope: ForwarderIdempotencyScope;
    ttlMs: number;
    transactionClient?: Prisma.TransactionClient;
  }): Promise<{acquired: boolean; lock_token: string}> {
    const bridge = this.getForwarderDbBridgeOrThrow({
      method: 'acquireForwarderExecutionLock'
    });
    try {
      return await bridge.acquireForwarderExecutionLock_INCOMPLETE(
        {
          scope,
          ttl_ms: ttlMs
        },
        transactionClient ? {transactionClient} : undefined
      );
    } catch (error) {
      throw new Error(`acquireForwarderExecutionLock: ${toErrorMessage(error)}`);
    }
  }

  public async releaseForwarderExecutionLockShared({
    scope,
    lockToken,
    transactionClient
  }: {
    scope: ForwarderIdempotencyScope;
    lockToken: string;
    transactionClient?: Prisma.TransactionClient;
  }): Promise<{released: boolean}> {
    const bridge = this.getForwarderDbBridgeOrThrow({
      method: 'releaseForwarderExecutionLock'
    });
    try {
      return await bridge.releaseForwarderExecutionLock_INCOMPLETE(
        {
          scope,
          lock_token: lockToken
        },
        transactionClient ? {transactionClient} : undefined
      );
    } catch (error) {
      throw new Error(`releaseForwarderExecutionLock: ${toErrorMessage(error)}`);
    }
  }

  public async createForwarderIdempotencyRecordShared({
    scope,
    requestFingerprintSha256,
    correlationId,
    expiresAt,
    transactionClient
  }: {
    scope: ForwarderIdempotencyScope;
    requestFingerprintSha256: string;
    correlationId: string;
    expiresAt: string;
    transactionClient?: Prisma.TransactionClient;
  }): Promise<ForwarderIdempotencyRecordCreateResult> {
    const bridge = this.getForwarderDbBridgeOrThrow({
      method: 'createForwarderIdempotencyRecord'
    });
    try {
      return await bridge.createForwarderIdempotencyRecord_INCOMPLETE(
        {
          scope,
          request_fingerprint_sha256: requestFingerprintSha256,
          correlation_id: correlationId,
          expires_at: expiresAt
        },
        transactionClient ? {transactionClient} : undefined
      );
    } catch (error) {
      throw new Error(`createForwarderIdempotencyRecord: ${toErrorMessage(error)}`);
    }
  }

  public async getForwarderIdempotencyRecordShared({
    scope,
    transactionClient
  }: {
    scope: ForwarderIdempotencyScope;
    transactionClient?: Prisma.TransactionClient;
  }): Promise<ForwarderIdempotencyRecordView | null> {
    const bridge = this.getForwarderDbBridgeOrThrow({
      method: 'getForwarderIdempotencyRecord'
    });
    try {
      const record = await bridge.getForwarderIdempotencyRecord_INCOMPLETE(
        {scope},
        transactionClient ? {transactionClient} : undefined
      );
      if (!record) {
        return null;
      }
      return forwarderIdempotencyRecordViewSchema.parse(record);
    } catch (error) {
      throw new Error(`getForwarderIdempotencyRecord: ${toErrorMessage(error)}`);
    }
  }

  public async completeForwarderIdempotencyRecordShared({
    scope,
    correlationId,
    upstreamStatusCode,
    responseBytes,
    transactionClient
  }: {
    scope: ForwarderIdempotencyScope;
    correlationId: string;
    upstreamStatusCode: number;
    responseBytes: number;
    transactionClient?: Prisma.TransactionClient;
  }): Promise<ForwarderIdempotencyRecordUpdateResult> {
    const bridge = this.getForwarderDbBridgeOrThrow({
      method: 'completeForwarderIdempotencyRecord'
    });
    try {
      return await bridge.completeForwarderIdempotencyRecord_INCOMPLETE(
        {
          scope,
          correlation_id: correlationId,
          upstream_status_code: upstreamStatusCode,
          response_bytes: responseBytes
        },
        transactionClient ? {transactionClient} : undefined
      );
    } catch (error) {
      throw new Error(`completeForwarderIdempotencyRecord: ${toErrorMessage(error)}`);
    }
  }

  public async failForwarderIdempotencyRecordShared({
    scope,
    correlationId,
    errorCode,
    transactionClient
  }: {
    scope: ForwarderIdempotencyScope;
    correlationId: string;
    errorCode: string;
    transactionClient?: Prisma.TransactionClient;
  }): Promise<ForwarderIdempotencyRecordUpdateResult> {
    const bridge = this.getForwarderDbBridgeOrThrow({
      method: 'failForwarderIdempotencyRecord'
    });
    try {
      return await bridge.failForwarderIdempotencyRecord_INCOMPLETE(
        {
          scope,
          correlation_id: correlationId,
          error_code: errorCode
        },
        transactionClient ? {transactionClient} : undefined
      );
    } catch (error) {
      throw new Error(`failForwarderIdempotencyRecord: ${toErrorMessage(error)}`);
    }
  }

  private createSsrfGuardStorageBridge(): SsrfGuardStorageBridge {
    const redis = this.processInfrastructure?.redis;
    const sharedIntegrationRepository = this.processInfrastructure?.dbRepositories?.integrationRepository;
    const sharedAuditRepository = this.processInfrastructure?.dbRepositories?.auditEventRepository as
      | {
          appendSsrfGuardDecisionProjection?: (input: {
            projection: SsrfDecisionProjection;
            transaction_client?: unknown;
          }) => Promise<SsrfDecisionProjection>;
        }
      | undefined;
    const sharedTemplateRepository = this.processInfrastructure?.dbRepositories?.templateRepository as
      | {
          persistTemplateInvalidationOutbox?: (input: {
            signal: TemplateInvalidationSignal;
            transaction_client?: unknown;
          }) => Promise<void>;
        }
      | undefined;
    const appendSsrfGuardDecisionProjection = sharedAuditRepository?.appendSsrfGuardDecisionProjection;
    const persistTemplateInvalidationOutbox = sharedTemplateRepository?.persistTemplateInvalidationOutbox;

    const ssrfStorageRepositories = {
      ...(sharedIntegrationRepository
        ? {
            getIntegrationTemplateForExecute: ({
              tenant_id,
              workload_id,
              integration_id,
              transaction_client
            }: {
              tenant_id: string;
              workload_id: string;
              integration_id: string;
              transaction_client?: unknown;
            }) =>
              sharedIntegrationRepository.getIntegrationTemplateForExecute({
                tenant_id,
                workload_id,
                integration_id,
                ...(transaction_client !== undefined ? {transaction_client} : {})
              })
          }
        : {}),
      ...(redis && typeof redis.get === 'function'
        ? {
            readDnsResolutionCache: async ({normalized_host}: {normalized_host: string}) => {
              const cacheKey = this.buildRedisKey({
                category: 'ssrf_dns_cache',
                key: normalized_host
              });
              const payload = await redis.get(cacheKey);
              if (!payload) {
                return null;
              }
              return DnsResolutionCacheEntrySchema.parse(JSON.parse(payload) as unknown);
            }
          }
        : {}),
      ...(redis && typeof redis.set === 'function'
        ? {
            upsertDnsResolutionCache: async ({normalized_host, entry}: {normalized_host: string; entry: unknown}) => {
              const parsedEntry = DnsResolutionCacheEntrySchema.parse(entry);
              const cacheKey = this.buildRedisKey({
                category: 'ssrf_dns_cache',
                key: normalized_host
              });
              await redis.set(cacheKey, JSON.stringify(parsedEntry), {
                EX: parsedEntry.ttl_seconds
              });
              return {
                outcome: 'applied' as const,
                applied: true,
                entry: parsedEntry
              };
            }
          }
        : {}),
      ...(redis && typeof redis.rPush === 'function'
        ? {
            appendDnsRebindingObservation: async ({
              normalized_host,
              observation
            }: {
              normalized_host: string;
              observation: unknown;
            }) => {
              const parsedObservation = DnsRebindingObservationSchema.parse(observation);
              const rebindingKey = this.buildRedisKey({
                category: 'ssrf_dns_rebinding',
                key: normalized_host
              });
              const historySizeRaw = await redis.rPush(rebindingKey, JSON.stringify(parsedObservation));
              if (typeof redis.lTrim === 'function') {
                await redis.lTrim(rebindingKey, -100, -1);
              }
              const historySize =
                typeof historySizeRaw === 'number' && Number.isFinite(historySizeRaw) ? historySizeRaw : 0;
              return {
                observation: parsedObservation,
                history_size: Math.max(0, Math.min(100, historySize))
              };
            }
          }
        : {}),
      ...(appendSsrfGuardDecisionProjection !== undefined || (redis && typeof redis.rPush === 'function')
        ? {
            appendSsrfGuardDecisionProjection: async ({
              projection,
              transaction_client
            }: {
              projection: unknown;
              transaction_client?: unknown;
            }) => {
              const parsedProjection = SsrfDecisionProjectionSchema.parse(projection);
              if (appendSsrfGuardDecisionProjection) {
                const persisted = await appendSsrfGuardDecisionProjection({
                  projection: parsedProjection,
                  ...(transaction_client !== undefined ? {transaction_client} : {})
                });
                return SsrfDecisionProjectionSchema.parse(persisted);
              }

              if (redis && typeof redis.rPush === 'function') {
                const projectionOutboxKey = this.buildSsrfDecisionProjectionOutboxKey();
                await redis.rPush(projectionOutboxKey, JSON.stringify(parsedProjection));
                if (typeof redis.lTrim === 'function') {
                  await redis.lTrim(projectionOutboxKey, -1000, -1);
                }
              }

              return parsedProjection;
            }
          }
        : {}),
      ...(persistTemplateInvalidationOutbox
        ? {
            persistTemplateInvalidationOutbox: async ({
              signal,
              transaction_client
            }: {
              signal: unknown;
              transaction_client?: unknown;
            }) =>
              persistTemplateInvalidationOutbox({
                signal: TemplateInvalidationSignalSchema.parse(signal),
                ...(transaction_client !== undefined ? {transaction_client} : {})
              })
          }
        : {}),
      ...(redis && typeof redis.publish === 'function'
        ? {
            publishTemplateInvalidationSignal: async ({signal}: {signal: unknown}) => {
              const parsedSignal = TemplateInvalidationSignalSchema.parse(signal);
              const payload = JSON.stringify(parsedSignal);
              const invalidationChannel = this.buildSsrfTemplateInvalidationChannel();
              await redis.publish(invalidationChannel, payload);
              if (typeof redis.rPush === 'function') {
                const outboxKey = this.buildSsrfTemplateInvalidationOutboxKey();
                await redis.rPush(outboxKey, payload);
                if (typeof redis.lTrim === 'function') {
                  await redis.lTrim(outboxKey, -1000, -1);
                }
              }
            }
          }
        : {})
    };

    return createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: ssrfStorageRepositories,
      ...(redis ? {clients: {redis}} : {})
    });
  }

  public async loadSsrfActiveTemplateForExecuteShared({
    scope,
    transactionClient
  }: {
    scope: StorageScope;
    transactionClient?: Prisma.TransactionClient;
  }): Promise<OpenApiTemplate | null> {
    const template = await this.ssrfGuardStorageBridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope,
      ...(transactionClient ? {transaction_client: transactionClient} : {})
    });
    return template ? OpenApiTemplateSchema.parse(template) : null;
  }

  public async readSsrfDnsResolutionCacheShared({
    normalizedHost,
    now = new Date()
  }: {
    normalizedHost: string;
    now?: Date;
  }) {
    const cached = await this.ssrfGuardStorageBridge.readDnsResolutionCacheFromRedis_INCOMPLETE({
      normalized_host: normalizedHost
    });
    if (!cached) {
      return null;
    }

    const expiresAtEpochMs = cached.resolved_at_epoch_ms + cached.ttl_seconds * 1000;
    if (expiresAtEpochMs <= now.getTime()) {
      return null;
    }

    return cached;
  }

  public async writeSsrfDnsResolutionCacheShared({
    normalizedHost,
    resolvedIps,
    now = new Date(),
    ttlSeconds = 60
  }: {
    normalizedHost: string;
    resolvedIps: string[];
    now?: Date;
    ttlSeconds?: number;
  }) {
    return this.ssrfGuardStorageBridge.writeDnsResolutionCacheToRedisMock_INCOMPLETE({
      normalized_host: normalizedHost,
      entry: {
        resolved_ips: this.normalizeIpSet(resolvedIps),
        resolved_at_epoch_ms: now.getTime(),
        ttl_seconds: ttlSeconds
      }
    });
  }

  public async appendSsrfDnsRebindingObservationShared({
    normalizedHost,
    resolvedIps,
    now = new Date()
  }: {
    normalizedHost: string;
    resolvedIps: string[];
    now?: Date;
  }) {
    const normalizedIps = this.normalizeIpSet(resolvedIps);
    return this.ssrfGuardStorageBridge.appendDnsRebindingObservationToRedisMock_INCOMPLETE({
      normalized_host: normalizedHost,
      observation: {
        ip_set_hash: this.hashIpSet(normalizedIps),
        resolved_ips: normalizedIps,
        observed_at_epoch_ms: now.getTime()
      }
    });
  }

  public async appendSsrfDecisionProjectionShared({
    projection,
    transactionClient
  }: {
    projection: {
      event_id: string;
      timestamp: string;
      tenant_id: string;
      workload_id: string;
      integration_id: string;
      template_id: string;
      template_version: number;
      destination_host: string;
      destination_port: number;
      resolved_ips: string[];
      decision: 'allowed' | 'denied';
      reason_code: SsrfGuardErrorCode;
      correlation_id: string;
    };
    transactionClient?: Prisma.TransactionClient;
  }) {
    return this.ssrfGuardStorageBridge.appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE({
      projection: SsrfDecisionProjectionSchema.parse(projection),
      ...(transactionClient ? {transaction_client: transactionClient} : {})
    });
  }

  public async syncSsrfTemplateBindingShared({
    scope,
    template,
    now = new Date()
  }: {
    scope: StorageScope;
    template: OpenApiTemplate;
    now?: Date;
  }) {
    const normalizedTemplate = OpenApiTemplateSchema.parse(template);
    await this.ssrfGuardStorageBridge.persistActiveTemplateForExecuteInDbMock_INCOMPLETE({
      scope,
      template: normalizedTemplate
    });

    const scopeKey = this.buildSsrfScopeKey(scope);
    const previousBinding = this.ssrfTemplateBindingsByScope.get(scopeKey) ?? null;
    const nextBinding: SsrfTemplateBindingState = {
      template_id: normalizedTemplate.template_id,
      version: normalizedTemplate.version
    };
    this.ssrfTemplateBindingsByScope.set(scopeKey, nextBinding);

    if (
      previousBinding &&
      (previousBinding.template_id !== nextBinding.template_id || previousBinding.version !== nextBinding.version)
    ) {
      await this.ssrfGuardStorageBridge.publishTemplateInvalidationSignalToRedisMock_INCOMPLETE({
        signal: {
          template_id: nextBinding.template_id,
          version: nextBinding.version,
          tenant_id: scope.tenant_id,
          updated_at: now.toISOString()
        }
      });
      return true;
    }

    return false;
  }

  private createSharedCryptoStorageService(): CryptoStorageService_INCOMPLETE<Prisma.TransactionClient> | null {
    const secretRepository = this.processInfrastructure?.dbRepositories?.secretRepository;
    if (!secretRepository) {
      return null;
    }

    const redis = this.processInfrastructure?.redis;
    const rotationLockAdapter: RotationLockAdapter | null = redis
      ? createCryptoRedisRotationLockAdapter({
          keyPrefix: `${this.processInfrastructure?.redisKeyPrefix ?? 'broker-api:data-plane'}:crypto`
        })
      : null;

    return createCryptoStorageService_INCOMPLETE<Prisma.TransactionClient>({
      createManifestSigningKeyRecord: async (input, context) => {
        try {
          const record = await secretRepository.createManifestSigningKeyRecord(
            input,
            this.toRepositoryContext(context?.transaction_client)
          );
          return cryptoOk(toCryptoManifestSigningKeyRecord(record));
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'createManifestSigningKeyRecord',
            error
          });
        }
      },
      getActiveManifestSigningKeyRecord: async context => {
        try {
          const record = await secretRepository.getActiveManifestSigningKeyRecord(
            this.toRepositoryContext(context?.transaction_client)
          );
          if (!record) {
            return cryptoErr(
              'manifest_key_not_found',
              'getActiveManifestSigningKeyRecord: No active manifest signing key is configured'
            );
          }

          return cryptoOk(toCryptoManifestSigningKeyRecord(record));
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'getActiveManifestSigningKeyRecord',
            error
          });
        }
      },
      setActiveManifestSigningKey: async (input, context) => {
        try {
          await secretRepository.setActiveManifestSigningKey(
            input,
            this.toRepositoryContext(context?.transaction_client)
          );
          return cryptoOk(null);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'setActiveManifestSigningKey',
            error
          });
        }
      },
      retireManifestSigningKey: async (input, context) => {
        try {
          await secretRepository.retireManifestSigningKey(input, this.toRepositoryContext(context?.transaction_client));
          return cryptoOk(null);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'retireManifestSigningKey',
            error
          });
        }
      },
      revokeManifestSigningKey: async (input, context) => {
        try {
          await secretRepository.revokeManifestSigningKey(input, this.toRepositoryContext(context?.transaction_client));
          return cryptoOk(null);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'revokeManifestSigningKey',
            error
          });
        }
      },
      listManifestVerificationKeysWithEtag: async context => {
        try {
          const keyset = await secretRepository.listManifestVerificationKeysWithEtag(
            this.toRepositoryContext(context?.transaction_client)
          );
          if (!keyset) {
            return cryptoErr(
              'manifest_key_not_found',
              'listManifestVerificationKeysWithEtag: No manifest keyset metadata is configured'
            );
          }

          return cryptoOk(keyset);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'listManifestVerificationKeysWithEtag',
            error
          });
        }
      },
      persistManifestKeysetMetadata: async (input, context) => {
        try {
          await secretRepository.persistManifestKeysetMetadata(
            input,
            this.toRepositoryContext(context?.transaction_client)
          );
          return cryptoOk(null);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'persistManifestKeysetMetadata',
            error
          });
        }
      },
      getCryptoVerificationDefaultsByTenant: async (input, context) => {
        try {
          const defaults = await secretRepository.getCryptoVerificationDefaultsByTenant(
            input,
            this.toRepositoryContext(context?.transaction_client)
          );
          return cryptoOk(defaults);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'getCryptoVerificationDefaultsByTenant',
            error
          });
        }
      },
      upsertCryptoVerificationDefaults: async (input, context) => {
        try {
          const defaults = await secretRepository.upsertCryptoVerificationDefaults(
            input,
            this.toRepositoryContext(context?.transaction_client)
          );
          return cryptoOk(defaults);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'upsertCryptoVerificationDefaults',
            error
          });
        }
      },
      acquireCryptoRotationLock: async input => {
        if (!rotationLockAdapter || !redis) {
          return cryptoErr(
            'invalid_input',
            'acquireCryptoRotationLock: Redis-backed crypto rotation lock adapter is not configured'
          );
        }

        try {
          const lock = await rotationLockAdapter.acquireCryptoRotationLock({
            lock_name: input.lock_name,
            ttl_ms: input.ttl_ms,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          });
          return cryptoOk(lock);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'acquireCryptoRotationLock',
            error
          });
        }
      },
      releaseCryptoRotationLock: async input => {
        if (!rotationLockAdapter || !redis) {
          return cryptoErr(
            'invalid_input',
            'releaseCryptoRotationLock: Redis-backed crypto rotation lock adapter is not configured'
          );
        }

        try {
          const released = await rotationLockAdapter.releaseCryptoRotationLock({
            lock_name: input.lock_name,
            token: input.token,
            context: {
              clients: {
                redis: toRedisEvalClient(redis)
              }
            }
          });
          return cryptoOk(released);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'releaseCryptoRotationLock',
            error
          });
        }
      },
      rotateManifestSigningKeysWithStore: async (input, context) => {
        const rotated = await rotateManifestSigningKeys({
          current_manifest_keys: input.current_manifest_keys,
          signing_alg: input.signing_alg,
          ...(input.new_kid ? {new_kid: input.new_kid} : {}),
          retain_previous_key_count: input.retain_previous_key_count
        });
        if (!rotated.ok) {
          return rotated;
        }

        const operationIso = nowIso();
        const repositoryContext = this.toRepositoryContext(context?.transaction_client);

        try {
          const previouslyActive = await secretRepository.getActiveManifestSigningKeyRecord(repositoryContext);

          await secretRepository.createManifestSigningKeyRecord(
            {
              kid: rotated.value.active_signing_private_key.kid,
              alg: rotated.value.active_signing_private_key.alg,
              public_jwk: publicKeyFromPrivateKey(rotated.value.active_signing_private_key),
              private_key_ref: privateKeyRefForKid(rotated.value.active_signing_private_key.kid),
              created_at: operationIso
            },
            repositoryContext
          );

          await secretRepository.setActiveManifestSigningKey(
            {
              kid: rotated.value.active_signing_private_key.kid,
              activated_at: operationIso
            },
            repositoryContext
          );

          if (
            previouslyActive &&
            previouslyActive.kid !== rotated.value.active_signing_private_key.kid &&
            previouslyActive.status === 'active'
          ) {
            await secretRepository.retireManifestSigningKey(
              {
                kid: previouslyActive.kid,
                retired_at: operationIso
              },
              repositoryContext
            );
          }

          await secretRepository.persistManifestKeysetMetadata(
            {
              etag: rotated.value.etag,
              generated_at: operationIso,
              max_age_seconds: this.manifestTtlSeconds
            },
            repositoryContext
          );
          return cryptoOk(rotated.value);
        } catch (error) {
          return toCryptoStoreFailure({
            method: 'rotateManifestSigningKeysWithStore',
            error
          });
        }
      }
    });
  }

  private async ensureSharedManifestSigningMaterial() {
    const sharedCryptoStorage = this.cryptoStorageService;
    if (!sharedCryptoStorage) {
      return;
    }
    const manifestSigningPrivateKey = this.getManifestSigningPrivateKey();

    const localPublicKey = publicKeyFromPrivateKey(manifestSigningPrivateKey);

    const activeKeyResult = await sharedCryptoStorage.getActiveManifestSigningKeyRecord_INCOMPLETE();
    if (!activeKeyResult.ok && activeKeyResult.error.code !== 'manifest_key_not_found') {
      throw new Error(`Unable to load active manifest signing key metadata: ${activeKeyResult.error.message}`);
    }

    if (!activeKeyResult.ok && activeKeyResult.error.code === 'manifest_key_not_found') {
      const createResult = await sharedCryptoStorage.createManifestSigningKeyRecord_INCOMPLETE({
        kid: manifestSigningPrivateKey.kid,
        alg: manifestSigningPrivateKey.alg,
        public_jwk: localPublicKey,
        private_key_ref: privateKeyRefForKid(manifestSigningPrivateKey.kid),
        created_at: nowIso()
      });
      if (!createResult.ok && createResult.error.code !== 'manifest_key_rotation_invalid') {
        throw new Error(`Unable to create manifest signing key metadata: ${createResult.error.message}`);
      }

      const setActiveResult = await sharedCryptoStorage.setActiveManifestSigningKey_INCOMPLETE({
        kid: manifestSigningPrivateKey.kid,
        activated_at: nowIso()
      });
      if (!setActiveResult.ok && setActiveResult.error.code !== 'manifest_key_rotation_invalid') {
        throw new Error(`Unable to activate manifest signing key metadata: ${setActiveResult.error.message}`);
      }

      const verifiedActiveKeyResult = await sharedCryptoStorage.getActiveManifestSigningKeyRecord_INCOMPLETE();
      if (!verifiedActiveKeyResult.ok) {
        throw new Error(
          `Unable to verify active manifest signing key metadata after bootstrap: ${verifiedActiveKeyResult.error.message}`
        );
      }

      if (
        verifiedActiveKeyResult.value.kid !== manifestSigningPrivateKey.kid ||
        !manifestPublicKeysEqual({
          expected: localPublicKey,
          actual: verifiedActiveKeyResult.value.public_jwk
        })
      ) {
        throw new Error(
          'Bootstrap manifest signing key metadata does not match local signing key material after create/activate'
        );
      }
    }

    const keysetResult = await sharedCryptoStorage.listManifestVerificationKeysWithEtag_INCOMPLETE();
    if (!keysetResult.ok && keysetResult.error.code !== 'manifest_key_not_found') {
      throw new Error(`Unable to load manifest verification keyset metadata: ${keysetResult.error.message}`);
    }

    if (!keysetResult.ok && keysetResult.error.code === 'manifest_key_not_found') {
      const persistResult = await sharedCryptoStorage.persistManifestKeysetMetadata_INCOMPLETE({
        etag: etagForManifestKeys(this.getManifestVerificationKeys()),
        generated_at: nowIso(),
        max_age_seconds: this.manifestTtlSeconds
      });
      if (!persistResult.ok) {
        throw new Error(`Unable to persist manifest keyset metadata: ${persistResult.error.message}`);
      }
    }
  }

  private async persistState() {
    if (!this.statePath) {
      return;
    }

    const payload = `${JSON.stringify(this.state, null, 2)}\n`;
    const directoryPath = path.dirname(this.statePath);
    const temporaryPath = `${this.statePath}.tmp`;

    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository path is a deliberate service configuration boundary.
    await fs.mkdir(directoryPath, {recursive: true});
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository path is a deliberate service configuration boundary.
    await fs.writeFile(temporaryPath, payload, 'utf8');
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository path is a deliberate service configuration boundary.
    await fs.rename(temporaryPath, this.statePath);
  }

  private async withWriteLock<T>(operation: () => Promise<T> | T): Promise<T> {
    const next = this.writeChain.then(async () => {
      const result = await operation();
      await this.persistState();
      return result;
    });

    this.writeChain = next.then(
      () => undefined,
      () => undefined
    );

    return next;
  }

  private cleanupExpiredSessions(now = new Date()) {
    const nowMs = now.getTime();
    this.state.sessions = this.state.sessions.filter(session => new Date(session.expires_at).getTime() > nowMs);
  }

  private cleanupExpiredApprovals(now = new Date()) {
    const nowMs = now.getTime();
    for (const approval of this.state.approvals) {
      if (approval.status !== 'pending') {
        continue;
      }

      if (new Date(approval.expires_at).getTime() <= nowMs) {
        approval.status = 'expired';
      }
    }
  }

  private cleanupExpiredReplayKeys(now = new Date()) {
    const nowMs = now.getTime();
    for (const [key, expiresAtMs] of this.dpopReplayJtiExpiryByKey.entries()) {
      if (expiresAtMs <= nowMs) {
        this.dpopReplayJtiExpiryByKey.delete(key);
      }
    }
  }

  public getWorkloadBySanUri({sanUri}: {sanUri: string}): OpenApiWorkload | null {
    const workload = this.state.workloads.find(item => item.mtls_san_uri === sanUri);
    return workload ? clone(workload) : null;
  }

  public async getWorkloadBySanUriShared({sanUri}: {sanUri: string}): Promise<OpenApiWorkload | null> {
    const sharedWorkloadRepository = this.processInfrastructure?.dbRepositories?.workloadRepository;
    if (!sharedWorkloadRepository) {
      return this.getWorkloadBySanUri({sanUri});
    }

    return sharedWorkloadRepository.getBySanUri({
      san_uri: sanUri
    });
  }

  public getWorkloadById({workloadId}: {workloadId: string}): OpenApiWorkload | null {
    const workload = this.state.workloads.find(item => item.workload_id === workloadId);
    return workload ? clone(workload) : null;
  }

  public isWorkloadDpopRequired({workloadId}: {workloadId: string}) {
    return this.state.dpop_required_workload_ids.includes(workloadId);
  }

  public isTenantDpopRequired({tenantId}: {tenantId: string}) {
    return this.state.dpop_required_tenant_ids.includes(tenantId);
  }

  public getIntegrationByTenantAndId({
    tenantId,
    integrationId
  }: {
    tenantId: string;
    integrationId: string;
  }): OpenApiIntegration | null {
    const integration = this.state.integrations.find(
      item => item.integration_id === integrationId && item.tenant_id === tenantId
    );
    return integration ? clone(integration) : null;
  }

  public async getIntegrationByTenantAndIdShared({
    tenantId,
    integrationId
  }: {
    tenantId: string;
    integrationId: string;
  }): Promise<OpenApiIntegration | null> {
    const sharedIntegrationRepository = this.processInfrastructure?.dbRepositories?.integrationRepository;
    if (!sharedIntegrationRepository) {
      return this.getIntegrationByTenantAndId({
        tenantId,
        integrationId
      });
    }

    return sharedIntegrationRepository.getById({
      integration_id: integrationId,
      tenant_id: tenantId
    });
  }

  public listTenantIntegrations({tenantId}: {tenantId: string}): OpenApiIntegration[] {
    return clone(this.state.integrations.filter(item => item.tenant_id === tenantId));
  }

  public getLatestTemplateById({templateId}: {templateId: string}): OpenApiTemplate | null {
    const versions = this.state.templates.filter(item => item.template_id === templateId);
    if (versions.length === 0) {
      return null;
    }

    const highestVersion = versions.reduce(
      (maxVersion, item) => (item.version > maxVersion ? item.version : maxVersion),
      0
    );
    const template = versions.find(item => item.version === highestVersion);
    return template ? clone(template) : null;
  }

  public async getLatestTemplateByIdShared({
    tenantId,
    templateId
  }: {
    tenantId: string;
    templateId: string;
  }): Promise<OpenApiTemplate | null> {
    const sharedTemplateRepository = this.processInfrastructure?.dbRepositories?.templateRepository;
    if (!sharedTemplateRepository) {
      return this.getLatestTemplateById({
        templateId
      });
    }

    return sharedTemplateRepository.getLatestTemplateByTenantTemplateId({
      tenant_id: tenantId,
      template_id: templateId
    });
  }

  public listTenantPolicies({tenantId}: {tenantId: string}): OpenApiPolicyRule[] {
    return clone(this.state.policies.filter(item => item.scope.tenant_id === tenantId));
  }

  public async listPolicyRulesForDescriptorShared({
    descriptor
  }: {
    descriptor: CanonicalRequestDescriptor;
  }): Promise<OpenApiPolicyRule[]> {
    const sharedPolicyRepository = this.processInfrastructure?.dbRepositories?.policyRuleRepository;
    if (!sharedPolicyRepository) {
      return this.listTenantPolicies({
        tenantId: descriptor.tenant_id
      });
    }

    return sharedPolicyRepository.listPolicyRulesForDescriptorScope({
      descriptor
    });
  }

  public async saveSession({session, scopes}: {session: SessionSaveInput; scopes: string[]}): Promise<SessionRecord> {
    if (this.authStorageScope) {
      const authSessionRecord = toAuthSessionRecordWithScopes({
        session,
        scopes
      });
      await this.authStorageScope.persistSessionRecord({
        session: authSessionRecord
      });
      return toSessionRecord({
        ...authSessionRecord,
        scopes: authSessionScopes(authSessionRecord)
      });
    }

    const sharedSessionRepository = this.processInfrastructure?.dbRepositories?.sessionRepository;
    if (sharedSessionRepository) {
      const upsertedSession = await sharedSessionRepository.upsertSession({
        sessionId: session.sessionId,
        workloadId: session.workloadId,
        tenantId: session.tenantId,
        certFingerprint256: session.certFingerprint256,
        tokenHash: session.tokenHash,
        expiresAt: session.expiresAt,
        ...(session.dpopKeyThumbprint ? {dpopKeyThumbprint: session.dpopKeyThumbprint} : {}),
        scopes
      });

      return toSessionRecord({
        sessionId: upsertedSession.sessionId,
        workloadId: upsertedSession.workloadId,
        tenantId: upsertedSession.tenantId,
        certFingerprint256: upsertedSession.certFingerprint256,
        tokenHash: upsertedSession.tokenHash,
        expiresAt: upsertedSession.expiresAt,
        ...(upsertedSession.dpopKeyThumbprint ? {dpopKeyThumbprint: upsertedSession.dpopKeyThumbprint} : {}),
        scopes: upsertedSession.scopes
      });
    }

    return this.withWriteLock(() => {
      this.cleanupExpiredSessions();

      const record = sessionRecordSchema.parse({
        session_id: session.sessionId,
        workload_id: session.workloadId,
        tenant_id: session.tenantId,
        cert_fingerprint256: session.certFingerprint256,
        token_hash: session.tokenHash,
        expires_at: session.expiresAt,
        ...(session.dpopKeyThumbprint ? {dpop_jkt: session.dpopKeyThumbprint} : {}),
        scopes
      });

      this.state.sessions.push(record);
      return clone(record);
    });
  }

  public getSessionByTokenHash({tokenHash, now = new Date()}: {tokenHash: string; now?: Date}): SessionRecord | null {
    this.cleanupExpiredSessions(now);

    const session = this.state.sessions.find(item => item.token_hash === tokenHash);
    return session ? clone(session) : null;
  }

  public async getSessionByTokenHashShared({
    tokenHash,
    now = new Date()
  }: {
    tokenHash: string;
    now?: Date;
  }): Promise<SessionRecord | null> {
    if (this.authStorageScope) {
      const session = await this.authStorageScope.getSessionRecordByTokenHash({
        tokenHash
      });
      if (!session) {
        return null;
      }

      return toSessionRecord({
        sessionId: session.sessionId,
        workloadId: session.workloadId,
        tenantId: session.tenantId,
        certFingerprint256: session.certFingerprint256,
        tokenHash: session.tokenHash,
        expiresAt: session.expiresAt,
        ...(session.dpopKeyThumbprint ? {dpopKeyThumbprint: session.dpopKeyThumbprint} : {}),
        scopes: authSessionScopes(session)
      });
    }

    const sharedSessionRepository = this.processInfrastructure?.dbRepositories?.sessionRepository;
    if (!sharedSessionRepository) {
      return this.getSessionByTokenHash({
        tokenHash,
        now
      });
    }

    const session = await sharedSessionRepository.getSessionByTokenHash({
      token_hash: tokenHash
    });
    if (!session) {
      return null;
    }

    return toSessionRecord({
      sessionId: session.sessionId,
      workloadId: session.workloadId,
      tenantId: session.tenantId,
      certFingerprint256: session.certFingerprint256,
      tokenHash: session.tokenHash,
      expiresAt: session.expiresAt,
      ...(session.dpopKeyThumbprint ? {dpopKeyThumbprint: session.dpopKeyThumbprint} : {}),
      scopes: session.scopes
    });
  }

  public async createOrReuseApprovalRequest({
    descriptor,
    summary,
    correlationId,
    now = new Date()
  }: {
    descriptor: CanonicalRequestDescriptor;
    summary: ApprovalRequest['summary'];
    correlationId: string;
    now?: Date;
  }): Promise<ApprovalRequest> {
    const sharedApprovalRepository = this.processInfrastructure?.dbRepositories?.approvalRequestRepository;
    if (sharedApprovalRepository) {
      const existingApproval = await sharedApprovalRepository.findOpenApprovalByCanonicalDescriptor({
        descriptor
      });
      if (existingApproval) {
        return existingApproval;
      }

      const expiresAt = new Date(now.getTime() + this.approvalTtlSeconds * 1000);
      return sharedApprovalRepository.createApprovalRequestFromCanonicalDescriptor({
        correlation_id: correlationId,
        expires_at: expiresAt.toISOString(),
        summary,
        canonical_descriptor: descriptor
      });
    }

    return this.withWriteLock(() => {
      this.cleanupExpiredApprovals(now);

      const fingerprint = descriptorFingerprint(descriptor);
      const existing = this.state.approvals.find(
        item =>
          item.status === 'pending' &&
          new Date(item.expires_at).getTime() > now.getTime() &&
          descriptorFingerprint(item.canonical_descriptor) === fingerprint
      );

      if (existing) {
        return clone(existing);
      }

      const expiresAt = new Date(now.getTime() + this.approvalTtlSeconds * 1000);
      const approval = ApprovalRequestSchema.parse({
        approval_id: `appr_${randomUUID()}`,
        status: 'pending',
        expires_at: expiresAt.toISOString(),
        correlation_id: correlationId,
        summary,
        canonical_descriptor: descriptor
      });

      this.state.approvals.push(approval);
      return clone(approval);
    });
  }

  public getInjectedHeadersForIntegration({integrationId}: {integrationId: string}): OpenApiHeaderList {
    // eslint-disable-next-line security/detect-object-injection -- Integration ID indexes a bounded in-memory map populated from validated repository state.
    const raw = this.state.integration_secret_headers[integrationId];
    const parsed = OpenApiHeaderListSchema.safeParse(raw ?? []);
    if (!parsed.success) {
      return [];
    }

    return clone(parsed.data);
  }

  public incrementRateLimitCounter({
    key,
    intervalSeconds,
    maxRequests,
    now = new Date()
  }: {
    key: string;
    intervalSeconds: number;
    maxRequests: number;
    now?: Date;
  }): {allowed: boolean; remaining: number; reset_at: string} {
    const nowMs = now.getTime();
    const existing = this.rateLimitCountersByKey.get(key);
    const intervalMs = intervalSeconds * 1000;

    if (!existing || existing.resetAtMs <= nowMs) {
      const resetAtMs = nowMs + intervalMs;
      this.rateLimitCountersByKey.set(key, {
        count: 1,
        resetAtMs
      });

      return {
        allowed: true,
        remaining: Math.max(0, maxRequests - 1),
        reset_at: new Date(resetAtMs).toISOString()
      };
    }

    if (existing.count >= maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        reset_at: new Date(existing.resetAtMs).toISOString()
      };
    }

    existing.count += 1;
    this.rateLimitCountersByKey.set(key, existing);

    return {
      allowed: true,
      remaining: Math.max(0, maxRequests - existing.count),
      reset_at: new Date(existing.resetAtMs).toISOString()
    };
  }

  public async incrementRateLimitCounterShared({
    key,
    intervalSeconds,
    maxRequests,
    now = new Date()
  }: {
    key: string;
    intervalSeconds: number;
    maxRequests: number;
    now?: Date;
  }): Promise<{allowed: boolean; remaining: number; reset_at: string}> {
    const redisClient = this.processInfrastructure?.redis;
    if (!redisClient) {
      return this.incrementRateLimitCounter({
        key,
        intervalSeconds,
        maxRequests,
        now
      });
    }

    const intervalMs = intervalSeconds * 1000;
    const redisKey = this.buildRedisKey({
      category: 'rate_limit',
      key
    });

    const count = await redisClient.incr(redisKey);
    let ttlMs = await redisClient.pTTL(redisKey);
    if (ttlMs < 0) {
      await redisClient.pExpire(redisKey, intervalMs);
      ttlMs = intervalMs;
    }

    const allowed = count <= maxRequests;
    return {
      allowed,
      remaining: allowed ? Math.max(0, maxRequests - count) : 0,
      reset_at: new Date(now.getTime() + ttlMs).toISOString()
    };
  }

  public checkAndStoreDpopReplayJti({
    key,
    expiresAt,
    now = new Date()
  }: {
    key: string;
    expiresAt: Date;
    now?: Date;
  }): boolean {
    this.cleanupExpiredReplayKeys(now);
    const expiresAtMs = expiresAt.getTime();
    if (this.dpopReplayJtiExpiryByKey.has(key)) {
      return false;
    }

    this.dpopReplayJtiExpiryByKey.set(key, expiresAtMs);
    return true;
  }

  public getDpopReplayStore() {
    if (this.authStorageScope) {
      return this.authStorageScope.createDpopReplayJtiStore();
    }

    return {
      checkAndStore: async (jti: string, expiresAt: Date) => {
        const redisClient = this.processInfrastructure?.redis;
        if (!redisClient) {
          return this.checkAndStoreDpopReplayJti({
            key: jti,
            expiresAt
          });
        }

        const nowMs = Date.now();
        const ttlMs = expiresAt.getTime() - nowMs;
        if (ttlMs <= 0) {
          return false;
        }

        const redisKey = this.buildRedisKey({
          category: 'dpop',
          key: jti
        });

        const result = await redisClient.set(redisKey, '1', {
          NX: true,
          PX: ttlMs
        });
        return result === 'OK';
      }
    };
  }

  public getManifestSigningPrivateKey(): ManifestSigningPrivateKey {
    const activePrivateKeyRef = this.state.manifest_signing_active_private_key_ref;
    if (activePrivateKeyRef) {
      const activeKey = this.resolveManifestSigningPrivateKeyByReference({
        privateKeyRef: activePrivateKeyRef
      });
      if (activeKey) {
        return activeKey;
      }
    }

    const legacyKey = this.state.manifest_signing_private_key;
    if (!legacyKey) {
      throw new Error('Manifest signing key is not configured');
    }

    return clone(legacyKey);
  }

  public async getManifestSigningPrivateKeyShared(): Promise<ManifestSigningPrivateKey> {
    const sharedCryptoStorage = this.cryptoStorageService;
    if (!sharedCryptoStorage) {
      return this.getManifestSigningPrivateKey();
    }

    const activeKeyResult = await sharedCryptoStorage.getActiveManifestSigningKeyRecord_INCOMPLETE();

    // If no active key in shared store, bootstrap local key
    if (!activeKeyResult.ok && activeKeyResult.error.code === 'manifest_key_not_found') {
      return this.syncLocalKeyToSharedStore();
    }

    if (!activeKeyResult.ok) {
      throw new Error(`Unable to load active manifest signing key metadata: ${activeKeyResult.error.message}`);
    }

    let localManifestSigningKey = this.resolveManifestSigningPrivateKeyByReference({
      privateKeyRef: activeKeyResult.value.private_key_ref
    });

    if (!localManifestSigningKey) {
      const fallbackByKid = this.getLocalManifestSigningPrivateKeyByKid({
        kid: activeKeyResult.value.kid
      });
      if (fallbackByKid) {
        localManifestSigningKey = fallbackByKid;
      }
    }

    if (!localManifestSigningKey) {
      const localActiveKey = this.getManifestSigningPrivateKey();
      if (!this.processInfrastructure?.redis) {
        throw new Error(
          `Manifest signing key mismatch between broker-api state (${localActiveKey.kid}) and shared store (${activeKeyResult.value.kid})`
        );
      }

      // Sync local key to shared store instead of rotating
      return this.syncLocalKeyToSharedStore();
    }

    const localPublicKey = publicKeyFromPrivateKey(localManifestSigningKey);
    if (activeKeyResult.value.kid !== localManifestSigningKey.kid) {
      if (!this.processInfrastructure?.redis) {
        throw new Error(
          `Manifest signing key mismatch between broker-api state (${localManifestSigningKey.kid}) and shared store (${activeKeyResult.value.kid})`
        );
      }

      // Sync local key to shared store instead of rotating
      return this.syncLocalKeyToSharedStore();
    }

    if (
      !manifestPublicKeysEqual({
        expected: localPublicKey,
        actual: activeKeyResult.value.public_jwk
      })
    ) {
      if (!this.processInfrastructure?.redis) {
        throw new Error(
          `Manifest signing public key mismatch for kid ${localManifestSigningKey.kid} between broker-api state and shared store`
        );
      }

      // Sync local key to shared store instead of rotating
      return this.syncLocalKeyToSharedStore();
    }

    return localManifestSigningKey;
  }

  /**
   * Syncs the local manifest signing key to the shared store.
   * Creates the key record if it doesn't exist, retires current active key, then sets new one as active.
   * Question: Is this needed? Is it still possible to have many workloads in a given tenant?
   */
  private async syncLocalKeyToSharedStore(): Promise<ManifestSigningPrivateKey> {
    const sharedCryptoStorage = this.cryptoStorageService;
    if (!sharedCryptoStorage) {
      throw new Error('Cannot sync local key to shared store: crypto storage service is not available');
    }

    const localKey = this.getManifestSigningPrivateKey();
    const localPublicKey = publicKeyFromPrivateKey(localKey);

    // Try to create the key record (will fail if already exists, which is fine)
    const createResult = await sharedCryptoStorage.createManifestSigningKeyRecord_INCOMPLETE({
      kid: localKey.kid,
      alg: localKey.alg,
      public_jwk: localPublicKey,
      private_key_ref: privateKeyRefForKid(localKey.kid),
      created_at: nowIso()
    });

    // Ignore "already exists" errors (manifest_key_rotation_invalid)
    if (!createResult.ok && createResult.error.code !== 'manifest_key_rotation_invalid') {
      throw new Error(`Unable to create manifest signing key record: ${createResult.error.message}`);
    }

    // Retire the current active key first (DB has unique constraint: only one active key allowed)
    const currentActiveResult = await sharedCryptoStorage.getActiveManifestSigningKeyRecord_INCOMPLETE();
    if (currentActiveResult.ok && currentActiveResult.value.kid !== localKey.kid) {
      const retireResult = await sharedCryptoStorage.retireManifestSigningKey_INCOMPLETE({
        kid: currentActiveResult.value.kid,
        retired_at: nowIso()
      });
      if (!retireResult.ok) {
        throw new Error(`Unable to retire previous active key: ${retireResult.error.message}`);
      }
    }

    // Set the local key as active
    const setActiveResult = await sharedCryptoStorage.setActiveManifestSigningKey_INCOMPLETE({
      kid: localKey.kid,
      activated_at: nowIso()
    });

    if (!setActiveResult.ok) {
      throw new Error(`Unable to activate manifest signing key: ${setActiveResult.error.message}`);
    }

    return localKey;
  }

  public getManifestVerificationKeys(): OpenApiManifestKeys {
    return clone(this.state.manifest_keys ?? OpenApiManifestKeysSchema.parse({keys: []}));
  }

  public async getManifestVerificationKeysShared(): Promise<OpenApiManifestKeys> {
    const sharedCryptoStorage = this.cryptoStorageService;
    if (!sharedCryptoStorage) {
      return this.getManifestVerificationKeys();
    }

    const keysetResult = await sharedCryptoStorage.listManifestVerificationKeysWithEtag_INCOMPLETE();
    if (!keysetResult.ok) {
      throw new Error(`Unable to load manifest verification keys: ${keysetResult.error.message}`);
    }

    return clone(keysetResult.value.manifest_keys);
  }

  public getManifestTtlSeconds() {
    return this.manifestTtlSeconds;
  }

  public listManifestTemplateRulesForTenant({tenantId}: {tenantId: string}): ManifestTemplateRule[] {
    const integrations = this.listTenantIntegrations({tenantId}).filter(item => item.enabled);
    const rules: ManifestTemplateRule[] = [];

    for (const integration of integrations) {
      const template = this.getLatestTemplateById({templateId: integration.template_id});
      if (!template) {
        continue;
      }

      rules.push({
        integration_id: integration.integration_id,
        provider: integration.provider,
        hosts: clone(template.allowed_hosts),
        schemes: clone(template.allowed_schemes),
        ports: clone(template.allowed_ports),
        path_groups: template.path_groups.flatMap(group => group.path_patterns)
      });
    }

    return rules;
  }

  public async listManifestTemplateRulesForTenantShared({
    tenantId
  }: {
    tenantId: string;
  }): Promise<ManifestTemplateRule[]> {
    const globalTemplateTenantId = 'global';
    const sharedIntegrationRepository = this.processInfrastructure?.dbRepositories?.integrationRepository;
    const sharedTemplateRepository = this.processInfrastructure?.dbRepositories?.templateRepository;
    if (!sharedIntegrationRepository || !sharedTemplateRepository) {
      return this.listManifestTemplateRulesForTenant({
        tenantId
      });
    }

    const [integrations, tenantTemplates, globalTemplates] = await Promise.all([
      sharedIntegrationRepository.listByTenant({
        tenant_id: tenantId
      }),
      sharedTemplateRepository.listLatestTemplatesByTenant({
        tenant_id: tenantId
      }),
      sharedTemplateRepository.listLatestTemplatesByTenant({
        tenant_id: globalTemplateTenantId
      })
    ]);

    const enabledIntegrations = integrations.filter(item => item.enabled);

    if (enabledIntegrations.length === 0) {
      return [];
    }

    const templatesById = new Map<string, (typeof tenantTemplates)[number]>();
    for (const template of globalTemplates) {
      templatesById.set(template.template_id, template);
    }
    for (const template of tenantTemplates) {
      templatesById.set(template.template_id, template);
    }
    const rules: ManifestTemplateRule[] = [];
    for (const integration of enabledIntegrations) {
      const template = templatesById.get(integration.template_id);
      if (!template) {
        continue;
      }

      rules.push({
        integration_id: integration.integration_id,
        provider: integration.provider,
        hosts: clone(template.allowed_hosts),
        schemes: clone(template.allowed_schemes),
        ports: clone(template.allowed_ports),
        path_groups: template.path_groups.flatMap(group => group.path_patterns)
      });
    }

    return rules;
  }

  public buildApprovalSummary({
    descriptor,
    actionGroup,
    riskTier,
    integrationId
  }: {
    descriptor: CanonicalRequestDescriptor;
    actionGroup: string;
    riskTier: 'low' | 'medium' | 'high';
    integrationId: string;
  }): ApprovalRequest['summary'] {
    const parsedUrl = new URL(descriptor.canonical_url);
    return {
      integration_id: integrationId,
      action_group: actionGroup,
      risk_tier: riskTier,
      destination_host: canonicalHostFromUrl(descriptor.canonical_url),
      method: descriptor.method,
      path: parsedUrl.pathname
    };
  }

  public buildSessionScopes({requestedScopes}: {requestedScopes: string[] | undefined}): string[] {
    if (!requestedScopes || requestedScopes.length === 0) {
      return ['execute', 'manifest.read'];
    }

    const uniqueScopes = [...new Set(requestedScopes.map(item => item.trim()).filter(Boolean))];
    return uniqueScopes;
  }

  public isSharedInfrastructureEnabled() {
    return this.processInfrastructure?.enabled ?? false;
  }

  public isSsrfTemplateLookupBridgeWiredShared() {
    return Boolean(this.processInfrastructure?.dbRepositories?.integrationRepository);
  }

  public async withSharedTransaction<T>(operation: (client: Prisma.TransactionClient) => Promise<T>) {
    if (!this.processInfrastructure?.enabled) {
      throw new Error('Shared transaction requested while infrastructure is disabled');
    }

    return this.processInfrastructure.withTransaction(operation);
  }

  public createEventId() {
    return `evt_${randomUUID()}`;
  }

  public getNowIso() {
    return nowIso();
  }
}
