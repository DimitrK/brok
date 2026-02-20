import {promises as fs} from 'node:fs';
import path from 'node:path';
import {isIP} from 'node:net';

import {
  createAuthStorageScope,
  type AuthEnrollmentTokenStoreAdapter,
  type AuthPostgresClient,
  type AuthRedisClient,
  type AuthStorageScope
} from '@broker-interceptor/auth';
import {validateTemplatePublish} from '@broker-interceptor/canonicalizer';
import {
  DbRepositoryError,
  createAuthRedisStores,
  createDbRepositories,
  runInTransaction
} from '@broker-interceptor/db';
import {derivePolicyFromApprovalDecision} from '@broker-interceptor/policy-engine';
import {
  ApprovalRequestSchema,
  OpenApiAuditEventSchema,
  OpenApiAdminAccessRequestListResponseSchema,
  OpenApiAdminUserListResponseSchema,
  OpenApiAdminUserSchema,
  OpenApiAdminSignupPolicySchema,
  OpenApiIntegrationSchema,
  OpenApiManifestKeysSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateSchema,
  OpenApiTenantSummarySchema,
  OpenApiWorkloadSchema,
  type OpenApiApprovalDecisionRequest,
  type OpenApiAdminAccessRequestStatus,
  type OpenApiAdminRole,
  type OpenApiAdminSessionPrincipal,
  type OpenApiAdminSignupPolicy,
  type OpenApiAdminSignupPolicyUpdateRequest,
  type OpenApiAdminUserStatus,
  type ApprovalRequest,
  type OpenApiAuditEvent,
  type OpenApiIntegration,
  type OpenApiIntegrationWrite,
  type OpenApiManifestKeys,
  type OpenApiPolicyRule,
  type OpenApiTemplate,
  type OpenApiTenantSummary,
  type OpenApiWorkload
} from '@broker-interceptor/schemas';
import {createNoopLogger, type StructuredLogger} from '@broker-interceptor/logging';
import {z} from 'zod';

import type {AdminPrincipal} from './auth';
import {
  computeManifestKeysWeakEtagWithCryptoPackage,
  createOpaqueToken,
  encryptSecretMaterialWithCryptoPackage,
  generateId,
  hashToken
} from './crypto';
import {badRequest, conflict, notFound, serviceUnavailable} from './errors';
import type {AdminRedisClient, ProcessInfrastructure} from './infrastructure';

const enrollmentTokenRecordSchema = z
  .object({
    token_hash: z.string().min(1),
    workload_id: z.string().min(1),
    expires_at: z.string().datetime({offset: true}),
    used_at: z.string().datetime({offset: true}).optional()
  })
  .strict();

const legacySecretVersionRecordSchema = z
  .object({
    version: z.number().int().gte(1),
    key_id: z.string(),
    created_at: z.string().datetime({offset: true}),
    nonce_b64: z.string(),
    ciphertext_b64: z.string(),
    auth_tag_b64: z.string()
  })
  .strict();

const envelopeSecretVersionRecordSchema = z
  .object({
    version: z.number().int().gte(1),
    key_id: z.string(),
    created_at: z.string().datetime({offset: true}),
    content_encryption_alg: z.literal('A256GCM'),
    key_encryption_alg: z.string().min(1),
    wrapped_data_key_b64: z.string().min(1),
    iv_b64: z.string().min(1),
    ciphertext_b64: z.string().min(1),
    auth_tag_b64: z.string().min(1),
    aad_b64: z.string().min(1).optional()
  })
  .strict();

const secretVersionRecordSchema = z.union([legacySecretVersionRecordSchema, envelopeSecretVersionRecordSchema]);

const secretRecordSchema = z
  .object({
    secret_ref: z.string().min(1),
    tenant_id: z.string().min(1),
    integration_id: z.string().min(1),
    type: z.enum(['api_key', 'oauth_refresh_token']),
    active_version: z.number().int().gte(1),
    versions: z.array(secretVersionRecordSchema).min(1)
  })
  .strict();

const persistedStateSchema = z
  .object({
    version: z.literal(1),
    tenants: z.array(OpenApiTenantSummarySchema),
    workloads: z.array(OpenApiWorkloadSchema),
    integrations: z.array(OpenApiIntegrationSchema),
    templates: z.array(OpenApiTemplateSchema),
    policies: z.array(OpenApiPolicyRuleSchema),
    approvals: z.array(ApprovalRequestSchema),
    audit_events: z.array(OpenApiAuditEventSchema),
    enrollment_tokens: z.array(enrollmentTokenRecordSchema),
    secrets: z.array(secretRecordSchema),
    manifest_keys: OpenApiManifestKeysSchema
  })
  .strict();

type PersistedState = z.infer<typeof persistedStateSchema>;

type CreateWorkloadInput = {
  tenantId: string;
  name: string;
  ipAllowlist?: string[];
  enrollmentMode?: 'broker_ca' | 'external_ca';
};

type UpdateWorkloadInput = {
  workloadId: string;
  enabled?: boolean;
  ipAllowlist?: string[];
};

type CreateIntegrationInput = {
  tenantId: string;
  payload: OpenApiIntegrationWrite;
  secretKey: Buffer;
  secretKeyId: string;
};

type UpdateIntegrationInput = {
  integrationId: string;
  enabled?: boolean;
  templateId?: string;
};

type DecideApprovalInput = {
  approvalId: string;
  decision: 'approved' | 'denied';
  request: OpenApiApprovalDecisionRequest;
};

type ApprovalDecisionResult = {
  approval: ApprovalRequest;
  derivedPolicy: OpenApiPolicyRule | null;
};

type AuditFilter = {
  timeMin?: Date;
  timeMax?: Date;
  tenantId?: string;
  workloadId?: string;
  integrationId?: string;
  actionGroup?: string;
  decision?: 'allowed' | 'denied' | 'approval_required' | 'throttled';
};

const clone = <T>(value: T): T => structuredClone(value);

const addSeconds = (value: Date, seconds: number) => new Date(value.getTime() + seconds * 1000);

const GLOBAL_TEMPLATE_TENANT_ID = 'global';
const GLOBAL_TEMPLATE_TENANT_NAME = 'Global Templates';

type EnrollmentTokenIssueInput = {
  token_hash: string;
  workload_id: string;
  tenant_id: string;
  expires_at: string;
  created_at: string;
};

type EnrollmentTokenConsumeInput = {
  token_hash: string;
  workload_id: string;
  now: string;
};

type EnrollmentTokenRepositoryWithIssueConsume = {
  issueEnrollmentToken: (input: EnrollmentTokenIssueInput) => Promise<unknown>;
  consumeEnrollmentTokenOnce: (input: EnrollmentTokenConsumeInput) => Promise<unknown>;
};

export type RepositoryAdminIdentity = {
  identity_id: string;
  issuer: string;
  subject: string;
  email: string;
  name?: string;
  status: 'active' | 'pending' | 'disabled';
  roles: OpenApiAdminSessionPrincipal['roles'];
  tenant_ids: string[];
  created_at: string;
  updated_at: string;
};

export type RepositoryAdminAccessRequest = {
  request_id: string;
  issuer: string;
  subject: string;
  email: string;
  name?: string;
  requested_roles: OpenApiAdminSessionPrincipal['roles'];
  requested_tenant_ids: string[];
  status: 'pending' | 'approved' | 'denied' | 'canceled';
  reason?: string;
  decided_by?: string;
  decided_at?: string;
  created_at: string;
  updated_at: string;
};

type AdminAuthRepositoryForAdmin = {
  getAdminSignupPolicy: () => Promise<OpenApiAdminSignupPolicy>;
  setAdminSignupPolicy: (input: {
    policy: OpenApiAdminSignupPolicyUpdateRequest;
    actor: string;
  }) => Promise<OpenApiAdminSignupPolicy>;
  listAdminIdentities: (input: {
    status?: OpenApiAdminUserStatus;
    tenant_id?: string;
    role?: OpenApiAdminRole;
    search?: string;
    limit?: number;
    cursor?: string;
  }) => Promise<{
    users: RepositoryAdminIdentity[];
    next_cursor?: string;
  }>;
  getAdminIdentityById: (input: {
    identity_id: string;
  }) => Promise<RepositoryAdminIdentity | null>;
  findAdminIdentityByIssuerSubject: (input: {
    issuer: string;
    subject: string;
  }) => Promise<RepositoryAdminIdentity | null>;
  createAdminIdentity: (input: {
    principal: OpenApiAdminSessionPrincipal;
    status?: 'active' | 'pending' | 'disabled';
  }) => Promise<RepositoryAdminIdentity>;
  createAdminAccessRequest: (input: {
    principal: OpenApiAdminSessionPrincipal;
    request_id?: string;
    reason?: string;
  }) => Promise<RepositoryAdminAccessRequest>;
  transitionAdminAccessRequestStatus: (input: {
    request_id: string;
    status: 'approved' | 'denied' | 'canceled';
    actor: string;
    reason?: string;
  }) => Promise<RepositoryAdminAccessRequest>;
  listAdminAccessRequests: (input: {
    status?: OpenApiAdminAccessRequestStatus;
    tenant_id?: string;
    role?: OpenApiAdminRole;
    search?: string;
    limit?: number;
    cursor?: string;
  }) => Promise<{
    requests: RepositoryAdminAccessRequest[];
    next_cursor?: string;
  }>;
  updateAdminIdentityStatus: (input: {
    identity_id: string;
    status: 'active' | 'pending' | 'disabled';
  }) => Promise<RepositoryAdminIdentity>;
  updateAdminIdentityBindings: (input: {
    identity_id: string;
    patch: {
      roles?: OpenApiAdminSessionPrincipal['roles'];
      tenant_ids?: string[];
    };
  }) => Promise<RepositoryAdminIdentity>;
  upsertAdminRoleBindings: (input: {
    issuer: string;
    subject: string;
    roles: OpenApiAdminSessionPrincipal['roles'];
    tenant_ids?: string[];
  }) => Promise<RepositoryAdminIdentity>;
};

type DbRepositoriesForAdmin = ReturnType<typeof createDbRepositories> & {
  enrollmentTokenRepository: EnrollmentTokenRepositoryWithIssueConsume;
  adminAuthRepository: AdminAuthRepositoryForAdmin;
};

type AuthRedisStoresForAdmin = {
  enrollmentTokenStore: AuthEnrollmentTokenStoreAdapter;
};

type AuthEnrollmentTokenStorageScope = Pick<
  AuthStorageScope,
  'issueEnrollmentTokenRecord' | 'consumeEnrollmentTokenRecordByHash'
>;

type EnrollmentTokenLookupRecord = {
  workloadId: string;
  usedAt: Date | null;
  expiresAt: Date;
};

type EnrollmentTokenLookupClient = {
  enrollmentToken: {
    findUnique: (input: {where: {tokenHash: string}}) => Promise<EnrollmentTokenLookupRecord | null>;
  };
};

const createDbRepositoriesForAdmin = (dbClient: unknown): DbRepositoriesForAdmin =>
  createDbRepositories(dbClient as Parameters<typeof createDbRepositories>[0]) as unknown as DbRepositoriesForAdmin;

const runInTransactionForAdmin = async <T>(
  dbClient: unknown,
  operation: (transactionClient: unknown) => Promise<T>
): Promise<T> =>
  (runInTransaction as unknown as (
    dbClient: unknown,
    operation: (transactionClient: unknown) => Promise<T>
  ) => Promise<T>)(dbClient, operation);

const createAuthRedisStoresForAdmin = ({keyPrefix}: {keyPrefix: string}): AuthRedisStoresForAdmin =>
  (createAuthRedisStores as unknown as (input: {keyPrefix: string}) => AuthRedisStoresForAdmin)({
    keyPrefix
  });

const createAuthRedisClientAdapter = ({redis}: {redis: AdminRedisClient}): AuthRedisClient => ({
  get: (...args: unknown[]) => {
    const [key] = args;
    if (typeof key !== 'string') {
      throw new TypeError('Redis get expects a string key');
    }

    return redis.get(key);
  },
  set: (...args: unknown[]) => {
    const [key, value, options] = args;
    if (typeof key !== 'string') {
      throw new TypeError('Redis set expects a string key');
    }

    if (typeof value !== 'string') {
      throw new TypeError('Redis set expects a string value');
    }

    return options === undefined ? redis.set(key, value) : redis.set(key, value, options as never);
  },
  del: (...args: unknown[]) => {
    if (args.length === 0 || args.some(key => typeof key !== 'string')) {
      throw new TypeError('Redis del expects one or more string keys');
    }

    const keys = args.filter((key): key is string => typeof key === 'string');
    return redis.del(keys);
  }
});

type TransactionCapableDbClient = {
  $transaction?: <T>(operation: (transactionClient: unknown) => Promise<T>) => Promise<T>;
};

const createTransactionCapableDbClientForSecretWrites = (dbClient: unknown): unknown => {
  const maybeTransactionCapable = dbClient as TransactionCapableDbClient & Record<string, unknown>;
  if (typeof maybeTransactionCapable.$transaction === 'function') {
    return maybeTransactionCapable;
  }

  // packages/db secret repository requires a transactional-capable client for envelope writes.
  // When called from app-managed transaction scope, reuse the same transaction client.
  const transactionCapableClient = Object.create(maybeTransactionCapable) as TransactionCapableDbClient &
    Record<string, unknown>;
  transactionCapableClient.$transaction = async <T>(
    operation: (transactionClient: unknown) => Promise<T>
  ): Promise<T> => operation(dbClient);
  return transactionCapableClient;
};

const mapDbRepositoryError = (error: unknown): never => {
  if (!(error instanceof DbRepositoryError)) {
    throw error;
  }

  switch (error.code) {
    case 'validation_error': {
      throw badRequest('db_validation_error', error.message);
    }
    case 'unique_violation':
    case 'conflict': {
      throw conflict('db_conflict', error.message);
    }
    case 'not_found': {
      throw notFound('db_not_found', error.message);
    }
    case 'integrity_violation': {
      throw conflict('db_integrity_violation', error.message);
    }
    case 'state_transition_invalid': {
      throw conflict('db_state_transition_invalid', error.message);
    }
    case 'dependency_missing':
    case 'unexpected_error': {
      throw serviceUnavailable('db_unavailable', error.message);
    }
  }
};

const logRedisEnrollmentCacheFailure = ({
  logger,
  operation,
  error
}: {
  logger: StructuredLogger;
  operation: 'issue' | 'consume';
  error: unknown;
}) => {
  const message = error instanceof Error ? error.message : 'Unknown error';
  logger.warn({
    event: 'repository.enrollment.cache_failed',
    component: 'repository.enrollment',
    message: `Enrollment token cache ${operation} failed`,
    reason_code: 'enrollment_token_cache_failed',
    metadata: {
      operation,
      error: message
    }
  });
};

const validateIpAllowlist = (allowlist: string[]) => {
  for (const entry of allowlist) {
    if (entry.includes('/')) {
      const [ip, mask] = entry.split('/');
      if (!ip || !mask) {
        throw badRequest('ip_allowlist_invalid', `Invalid CIDR entry: ${entry}`);
      }

      const version = isIP(ip);
      if (version === 0) {
        throw badRequest('ip_allowlist_invalid', `Invalid CIDR IP entry: ${entry}`);
      }

      const maskValue = Number.parseInt(mask, 10);
      const maxMask = version === 4 ? 32 : 128;
      if (Number.isNaN(maskValue) || maskValue < 0 || maskValue > maxMask) {
        throw badRequest('ip_allowlist_invalid', `Invalid CIDR mask entry: ${entry}`);
      }

      continue;
    }

    if (isIP(entry) === 0) {
      throw badRequest('ip_allowlist_invalid', `Invalid IP allowlist entry: ${entry}`);
    }
  }
};

const buildDefaultState = ({manifestKeys}: {manifestKeys: OpenApiManifestKeys}): PersistedState =>
  persistedStateSchema.parse({
    version: 1,
    tenants: [],
    workloads: [],
    integrations: [],
    templates: [],
    policies: [],
    approvals: [],
    audit_events: [],
    enrollment_tokens: [],
    secrets: [],
    manifest_keys: manifestKeys
  });

const readStateFile = async ({
  statePath,
  manifestKeys
}: {
  statePath?: string;
  manifestKeys: OpenApiManifestKeys;
}): Promise<PersistedState> => {
  if (!statePath) {
    return buildDefaultState({manifestKeys});
  }

  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository state path is process-configured and intentionally dynamic.
    const text = await fs.readFile(statePath, 'utf8');
    const parsed = JSON.parse(text) as unknown;
    const state = persistedStateSchema.parse(parsed);
    return {
      ...state,
      manifest_keys: manifestKeys
    };
  } catch (error) {
    const nodeError = error as NodeJS.ErrnoException;
    if (nodeError.code === 'ENOENT') {
      return buildDefaultState({manifestKeys});
    }

    throw error;
  }
};

export type CreateControlPlaneRepositoryInput = {
  statePath?: string;
  manifestKeys: OpenApiManifestKeys;
  enrollmentTokenTtlSeconds: number;
  processInfrastructure?: ProcessInfrastructure;
  logger?: StructuredLogger;
};

export class ControlPlaneRepository {
  private readonly enrollmentTokenTtlSeconds: number;
  private readonly statePath?: string;
  private readonly processInfrastructure?: ProcessInfrastructure;
  private readonly state: PersistedState;
  private readonly dbRepositories?: DbRepositoriesForAdmin;
  private readonly authEnrollmentTokenStorageScope?: AuthEnrollmentTokenStorageScope;
  private readonly logger: StructuredLogger;
  private writeChain: Promise<void> = Promise.resolve();

  public constructor({
    state,
    statePath,
    enrollmentTokenTtlSeconds,
    processInfrastructure,
    logger
  }: {
    state: PersistedState;
    statePath?: string;
    enrollmentTokenTtlSeconds: number;
    processInfrastructure?: ProcessInfrastructure;
    logger?: StructuredLogger;
  }) {
    this.state = state;
    this.statePath = statePath;
    this.enrollmentTokenTtlSeconds = enrollmentTokenTtlSeconds;
    this.processInfrastructure = processInfrastructure;
    this.logger = logger ?? createNoopLogger();

    if (processInfrastructure?.enabled) {
      if (!processInfrastructure.prisma) {
        throw new Error('Database infrastructure is enabled but Prisma client is unavailable');
      }

      this.dbRepositories = createDbRepositoriesForAdmin(processInfrastructure.prisma);

      if (processInfrastructure.redis) {
        const authRedisStores = createAuthRedisStoresForAdmin({
          keyPrefix: processInfrastructure.redisKeyPrefix
        });
        const authRedisClient = createAuthRedisClientAdapter({
          redis: processInfrastructure.redis
        });
        const authPostgresClient = processInfrastructure.prisma as unknown as AuthPostgresClient;
        this.authEnrollmentTokenStorageScope = createAuthStorageScope({
          clients: {
            redis: authRedisClient,
            postgres: authPostgresClient
          },
          repositories: {
            enrollmentTokenStore: authRedisStores.enrollmentTokenStore
          }
        });
      }
    }
  }

  public static async create({
    statePath,
    manifestKeys,
    enrollmentTokenTtlSeconds,
    processInfrastructure,
    logger
  }: CreateControlPlaneRepositoryInput): Promise<ControlPlaneRepository> {
    const state = await readStateFile({statePath, manifestKeys});

    return new ControlPlaneRepository({
      state,
      statePath,
      enrollmentTokenTtlSeconds,
      processInfrastructure,
      logger
    });
  }

  public getProcessInfrastructure() {
    return this.processInfrastructure;
  }

  private isDbEnabled() {
    return Boolean(this.processInfrastructure?.enabled && this.dbRepositories);
  }

  private requireDbRepositories(): DbRepositoriesForAdmin {
    if (!this.dbRepositories) {
      throw serviceUnavailable('db_unavailable', 'Database repositories are not configured');
    }

    return this.dbRepositories;
  }

  private async ensureGlobalTemplateTenant() {
    const db = this.requireDbRepositories();
    const existing = await db.tenantRepository.getById({tenant_id: GLOBAL_TEMPLATE_TENANT_ID});
    if (existing) {
      return;
    }

    await db.tenantRepository.create({
      request: {
        name: GLOBAL_TEMPLATE_TENANT_NAME
      },
      tenant_id: GLOBAL_TEMPLATE_TENANT_ID
    });
  }

  private async persistState() {
    if (!this.statePath) {
      return;
    }

    const payload = `${JSON.stringify(this.state, null, 2)}\n`;
    const directory = path.dirname(this.statePath);
    const temporaryPath = `${this.statePath}.tmp`;

    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository state path is process-configured and intentionally dynamic.
    await fs.mkdir(directory, {recursive: true});
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository state path is process-configured and intentionally dynamic.
    await fs.writeFile(temporaryPath, payload, 'utf8');
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Repository state path is process-configured and intentionally dynamic.
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

  private updateExpiredApprovals(now = new Date()) {
    let changed = false;
    for (const approval of this.state.approvals) {
      if (approval.status !== 'pending') {
        continue;
      }

      if (new Date(approval.expires_at) <= now) {
        approval.status = 'expired';
        changed = true;
      }
    }

    return changed;
  }

  private findTenant(tenantId: string): OpenApiTenantSummary {
    const tenant = this.state.tenants.find(item => item.tenant_id === tenantId);
    if (!tenant) {
      throw notFound('tenant_not_found', `Tenant ${tenantId} was not found`);
    }

    return tenant;
  }

  private findTemplate(templateId: string): OpenApiTemplate {
    const template = this.state.templates.find(item => item.template_id === templateId);
    if (!template) {
      throw notFound('template_not_found', `Template ${templateId} was not found`);
    }

    return template;
  }

  private findWorkload(workloadId: string): OpenApiWorkload {
    const workload = this.state.workloads.find(item => item.workload_id === workloadId);
    if (!workload) {
      throw notFound('workload_not_found', `Workload ${workloadId} was not found`);
    }

    return workload;
  }

  private findIntegration(integrationId: string): OpenApiIntegration {
    const integration = this.state.integrations.find(item => item.integration_id === integrationId);
    if (!integration) {
      throw notFound('integration_not_found', `Integration ${integrationId} was not found`);
    }

    return integration;
  }

  public async listTenants() {
    if (this.isDbEnabled()) {
      try {
        const tenants = await this.requireDbRepositories().tenantRepository.list();
        return tenants.filter(tenant => tenant.tenant_id !== GLOBAL_TEMPLATE_TENANT_ID);
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return clone(this.state.tenants);
  }

  public async createTenant({name}: {name: string}) {
    if (this.isDbEnabled()) {
      try {
        return await this.requireDbRepositories().tenantRepository.create({
          request: {
            name
          }
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      const tenant = OpenApiTenantSummarySchema.parse({
        tenant_id: generateId('t_'),
        name
      });
      this.state.tenants.push(tenant);
      return clone(tenant);
    });
  }

  public async getAdminSignupPolicy(): Promise<OpenApiAdminSignupPolicy> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin signup policy requires database infrastructure');
    }

    try {
      const policy = await this.requireDbRepositories().adminAuthRepository.getAdminSignupPolicy();
      return OpenApiAdminSignupPolicySchema.parse(policy);
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async setAdminSignupPolicy({
    policy,
    actor
  }: {
    policy: OpenApiAdminSignupPolicyUpdateRequest;
    actor: string;
  }): Promise<OpenApiAdminSignupPolicy> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin signup policy requires database infrastructure');
    }

    try {
      const updated = await this.requireDbRepositories().adminAuthRepository.setAdminSignupPolicy({
        policy,
        actor
      });
      return OpenApiAdminSignupPolicySchema.parse(updated);
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async listAdminUsers({
    status,
    tenantId,
    role,
    search,
    limit,
    cursor
  }: {
    status?: OpenApiAdminUserStatus;
    tenantId?: string;
    role?: OpenApiAdminRole;
    search?: string;
    limit?: number;
    cursor?: string;
  }): Promise<{users: RepositoryAdminIdentity[]; next_cursor?: string}> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin user listing requires database infrastructure');
    }

    try {
      return OpenApiAdminUserListResponseSchema.parse(
        await this.requireDbRepositories().adminAuthRepository.listAdminIdentities({
          ...(status ? {status} : {}),
          ...(tenantId ? {tenant_id: tenantId} : {}),
          ...(role ? {role} : {}),
          ...(search ? {search} : {}),
          ...(typeof limit === 'number' ? {limit} : {}),
          ...(cursor ? {cursor} : {})
        })
      );
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async getAdminUserByIdentityId({identityId}: {identityId: string}): Promise<RepositoryAdminIdentity | null> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin user lookups require database infrastructure');
    }

    try {
      const user = await this.requireDbRepositories().adminAuthRepository.getAdminIdentityById({
        identity_id: identityId
      });
      return user ? OpenApiAdminUserSchema.parse(user) : null;
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async setAdminUserStatus({
    identityId,
    status
  }: {
    identityId: string;
    status: 'active' | 'pending' | 'disabled';
  }): Promise<RepositoryAdminIdentity> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin user updates require database infrastructure');
    }

    try {
      return OpenApiAdminUserSchema.parse(
        await this.requireDbRepositories().adminAuthRepository.updateAdminIdentityStatus({
          identity_id: identityId,
          status
        })
      );
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async updateAdminUserRolesAndTenants({
    identityId,
    roles,
    tenantIds
  }: {
    identityId: string;
    roles?: OpenApiAdminSessionPrincipal['roles'];
    tenantIds?: string[];
  }): Promise<RepositoryAdminIdentity> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin user updates require database infrastructure');
    }

    try {
      return OpenApiAdminUserSchema.parse(
        await this.requireDbRepositories().adminAuthRepository.updateAdminIdentityBindings({
          identity_id: identityId,
          patch: {
            ...(roles ? {roles} : {}),
            ...(tenantIds ? {tenant_ids: tenantIds} : {})
          }
        })
      );
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async updateAdminUser({
    identityId,
    status,
    roles,
    tenantIds
  }: {
    identityId: string;
    status?: 'active' | 'pending' | 'disabled';
    roles?: OpenApiAdminSessionPrincipal['roles'];
    tenantIds?: string[];
  }): Promise<RepositoryAdminIdentity> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin user updates require database infrastructure');
    }

    if (status === undefined && roles === undefined && tenantIds === undefined) {
      throw badRequest('admin_user_update_invalid', 'At least one of status, roles, or tenant_ids must be provided');
    }

    const prisma = this.processInfrastructure?.prisma;
    if (!prisma) {
      throw serviceUnavailable('db_unavailable', 'Admin user updates require database infrastructure');
    }

    try {
      const updated = await runInTransactionForAdmin(prisma, async transactionClient => {
        const repositories = createDbRepositoriesForAdmin(transactionClient);
        let result: RepositoryAdminIdentity | undefined;

        if (roles !== undefined || tenantIds !== undefined) {
          result = await repositories.adminAuthRepository.updateAdminIdentityBindings({
            identity_id: identityId,
            patch: {
              ...(roles !== undefined ? {roles} : {}),
              ...(tenantIds !== undefined ? {tenant_ids: tenantIds} : {})
            }
          });
        }

        if (status !== undefined) {
          result = await repositories.adminAuthRepository.updateAdminIdentityStatus({
            identity_id: identityId,
            status
          });
        }

        if (!result) {
          throw badRequest('admin_user_update_invalid', 'At least one of status, roles, or tenant_ids must be provided');
        }

        return result;
      });

      return OpenApiAdminUserSchema.parse(updated);
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async listAdminAccessRequests({
    status,
    tenantId,
    role,
    search,
    limit,
    cursor
  }: {
    status?: OpenApiAdminAccessRequestStatus;
    tenantId?: string;
    role?: OpenApiAdminRole;
    search?: string;
    limit?: number;
    cursor?: string;
  }): Promise<{requests: RepositoryAdminAccessRequest[]; next_cursor?: string}> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin access requests require database infrastructure');
    }

    try {
      return OpenApiAdminAccessRequestListResponseSchema.parse(
        await this.requireDbRepositories().adminAuthRepository.listAdminAccessRequests({
          ...(status ? {status} : {}),
          ...(tenantId ? {tenant_id: tenantId} : {}),
          ...(role ? {role} : {}),
          ...(search ? {search} : {}),
          ...(typeof limit === 'number' ? {limit} : {}),
          ...(cursor ? {cursor} : {})
        })
      );
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async findAdminIdentityByIssuerSubject({
    issuer,
    subject
  }: {
    issuer: string;
    subject: string;
  }): Promise<RepositoryAdminIdentity | null> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin identity lookups require database infrastructure');
    }

    try {
      return await this.requireDbRepositories().adminAuthRepository.findAdminIdentityByIssuerSubject({
        issuer,
        subject
      });
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async createAdminIdentity({
    principal,
    status
  }: {
    principal: OpenApiAdminSessionPrincipal;
    status?: 'active' | 'pending' | 'disabled';
  }): Promise<RepositoryAdminIdentity> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin identity creation requires database infrastructure');
    }

    try {
      return await this.requireDbRepositories().adminAuthRepository.createAdminIdentity({
        principal,
        ...(status ? {status} : {})
      });
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async createAdminAccessRequest({
    principal,
    requestId,
    reason
  }: {
    principal: OpenApiAdminSessionPrincipal;
    requestId?: string;
    reason?: string;
  }): Promise<RepositoryAdminAccessRequest> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin access requests require database infrastructure');
    }

    try {
      return await this.requireDbRepositories().adminAuthRepository.createAdminAccessRequest({
        ...(requestId ? {request_id: requestId} : {}),
        ...(reason ? {reason} : {}),
        principal
      });
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async transitionAdminAccessRequestStatus({
    requestId,
    status,
    actor,
    reason
  }: {
    requestId: string;
    status: 'approved' | 'denied' | 'canceled';
    actor: string;
    reason?: string;
  }): Promise<RepositoryAdminAccessRequest> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin access requests require database infrastructure');
    }

    try {
      return await this.requireDbRepositories().adminAuthRepository.transitionAdminAccessRequestStatus({
        request_id: requestId,
        status,
        actor,
        ...(reason ? {reason} : {})
      });
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async upsertAdminRoleBindings({
    issuer,
    subject,
    roles,
    tenantIds
  }: {
    issuer: string;
    subject: string;
    roles: OpenApiAdminSessionPrincipal['roles'];
    tenantIds?: string[];
  }): Promise<RepositoryAdminIdentity> {
    if (!this.isDbEnabled()) {
      throw serviceUnavailable('db_unavailable', 'Admin role updates require database infrastructure');
    }

    try {
      return await this.requireDbRepositories().adminAuthRepository.upsertAdminRoleBindings({
        issuer,
        subject,
        roles,
        ...(tenantIds ? {tenant_ids: tenantIds} : {})
      });
    } catch (error) {
      return mapDbRepositoryError(error);
    }
  }

  public async listWorkloads({tenantId}: {tenantId: string}) {
    if (this.isDbEnabled()) {
      try {
        return await this.requireDbRepositories().workloadRepository.listByTenant({
          tenant_id: tenantId
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    this.findTenant(tenantId);
    return clone(this.state.workloads.filter(item => item.tenant_id === tenantId));
  }

  public async getWorkload({workloadId}: {workloadId: string}) {
    if (this.isDbEnabled()) {
      try {
        const workload = await this.requireDbRepositories().workloadRepository.getById({
          workload_id: workloadId
        });
        if (!workload) {
          throw notFound('workload_not_found', `Workload ${workloadId} was not found`);
        }
        return workload;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return clone(this.findWorkload(workloadId));
  }

  public async createWorkload({
    tenantId,
    name,
    ipAllowlist,
    enrollmentMode = 'broker_ca'
  }: CreateWorkloadInput): Promise<{workload: OpenApiWorkload; enrollmentToken: string}> {
    if (this.isDbEnabled()) {
      try {
        if (ipAllowlist && ipAllowlist.length > 0) {
          validateIpAllowlist(ipAllowlist);
        }

        const prisma = this.processInfrastructure?.prisma;
        if (!prisma) {
          throw serviceUnavailable('db_unavailable', 'Database client is unavailable');
        }

        const now = new Date();
        const nowIso = now.toISOString();
        const enrollmentToken = createOpaqueToken();
        const enrollmentTokenHash = hashToken(enrollmentToken);
        const expiresAt = addSeconds(now, this.enrollmentTokenTtlSeconds);

        const workload = OpenApiWorkloadSchema.parse(
          await runInTransactionForAdmin(prisma, async transactionClient => {
            const repositories = createDbRepositoriesForAdmin(transactionClient);
            const createdWorkload = OpenApiWorkloadSchema.parse(
              await repositories.workloadRepository.create({
                tenant_id: tenantId,
                request: {
                  name,
                  enrollment_mode: enrollmentMode,
                  ...(ipAllowlist && ipAllowlist.length > 0 ? {ip_allowlist: ipAllowlist} : {})
                }
              })
            );

            await repositories.enrollmentTokenRepository.issueEnrollmentToken({
              token_hash: enrollmentTokenHash,
              workload_id: createdWorkload.workload_id,
              tenant_id: tenantId,
              expires_at: expiresAt.toISOString(),
              created_at: nowIso
            });

            return createdWorkload;
          })
        );

        if (this.authEnrollmentTokenStorageScope) {
          try {
            await this.authEnrollmentTokenStorageScope.issueEnrollmentTokenRecord({
              record: {
                tokenHash: enrollmentTokenHash,
                workloadId: workload.workload_id,
                expiresAt: expiresAt.toISOString()
              }
            });
          } catch (error) {
            logRedisEnrollmentCacheFailure({
              logger: this.logger,
              operation: 'issue',
              error
            });
          }
        }

        return {
          workload,
          enrollmentToken
        };
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      this.findTenant(tenantId);
      if (ipAllowlist && ipAllowlist.length > 0) {
        validateIpAllowlist(ipAllowlist);
      }

      const workloadId = generateId('w_');
      const workload = OpenApiWorkloadSchema.parse({
        workload_id: workloadId,
        tenant_id: tenantId,
        name,
        mtls_san_uri: `spiffe://broker/tenants/${tenantId}/workloads/${workloadId}`,
        enabled: true,
        ...(ipAllowlist && ipAllowlist.length > 0 ? {ip_allowlist: ipAllowlist} : {}),
        created_at: new Date().toISOString()
      });

      const enrollmentToken = createOpaqueToken();
      const enrollmentTokenHash = hashToken(enrollmentToken);
      const expiresAt = addSeconds(new Date(), this.enrollmentTokenTtlSeconds);

      this.state.workloads.push(workload);
      this.state.enrollment_tokens.push(
        enrollmentTokenRecordSchema.parse({
          token_hash: enrollmentTokenHash,
          workload_id: workloadId,
          expires_at: expiresAt.toISOString()
        })
      );

      return {
        workload: clone(workload),
        enrollmentToken
      };
    });
  }

  public async updateWorkload({workloadId, enabled, ipAllowlist}: UpdateWorkloadInput) {
    if (this.isDbEnabled()) {
      try {
        return await this.requireDbRepositories().workloadRepository.update({
          workload_id: workloadId,
          request: {
            ...(typeof enabled === 'boolean' ? {enabled} : {}),
            ...(ipAllowlist ? {ip_allowlist: ipAllowlist} : {})
          }
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      const workload = this.findWorkload(workloadId);
      if (ipAllowlist) {
        validateIpAllowlist(ipAllowlist);
      }

      const updated = OpenApiWorkloadSchema.parse({
        ...workload,
        ...(typeof enabled === 'boolean' ? {enabled} : {}),
        ...(ipAllowlist ? {ip_allowlist: ipAllowlist} : {})
      });

      const index = this.state.workloads.findIndex(item => item.workload_id === workloadId);
      if (index < 0) {
        throw notFound('workload_not_found', `Workload ${workloadId} was not found`);
      }
      this.state.workloads.splice(index, 1, updated);

      return clone(updated);
    });
  }

  public async consumeEnrollmentToken({
    workloadId,
    enrollmentToken,
    now = new Date()
  }: {
    workloadId: string;
    enrollmentToken: string;
    now?: Date;
  }): Promise<OpenApiWorkload> {
    if (this.isDbEnabled()) {
      try {
        const prisma = this.processInfrastructure?.prisma;
        if (!prisma) {
          throw serviceUnavailable('db_unavailable', 'Database client is unavailable');
        }

        const workload = await this.getWorkload({workloadId});
        const tokenHash = hashToken(enrollmentToken);
        const nowIso = now.toISOString();

        await runInTransactionForAdmin(prisma, async transactionClient => {
          const repositories = createDbRepositoriesForAdmin(transactionClient);
          try {
            await repositories.enrollmentTokenRepository.consumeEnrollmentTokenOnce({
              token_hash: tokenHash,
              workload_id: workloadId,
              now: nowIso
            });
          } catch (error) {
            if (error instanceof DbRepositoryError && error.code === 'not_found') {
              const tokenLookupClient = transactionClient as EnrollmentTokenLookupClient;
              const record = await tokenLookupClient.enrollmentToken.findUnique({
                where: {
                  tokenHash
                }
              });

              if (!record || record.workloadId !== workloadId) {
                throw badRequest('enrollment_token_invalid', 'Enrollment token is invalid');
              }

              if (record.usedAt) {
                throw conflict('enrollment_token_used', 'Enrollment token has already been used');
              }

              if (record.expiresAt.getTime() <= now.getTime()) {
                throw badRequest('enrollment_token_expired', 'Enrollment token has expired');
              }

              throw badRequest('enrollment_token_invalid', 'Enrollment token is invalid');
            }

            throw error;
          }
        });

        if (this.authEnrollmentTokenStorageScope) {
          try {
            await this.authEnrollmentTokenStorageScope.consumeEnrollmentTokenRecordByHash({
              tokenHash
            });
          } catch (error) {
            logRedisEnrollmentCacheFailure({
              logger: this.logger,
              operation: 'consume',
              error
            });
          }
        }

        return workload;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      const workload = this.findWorkload(workloadId);
      const tokenHash = hashToken(enrollmentToken);
      const tokenRecord = this.state.enrollment_tokens.find(
        item => item.workload_id === workloadId && item.token_hash === tokenHash
      );

      if (!tokenRecord) {
        throw badRequest('enrollment_token_invalid', 'Enrollment token is invalid');
      }

      if (tokenRecord.used_at) {
        throw conflict('enrollment_token_used', 'Enrollment token has already been used');
      }

      if (new Date(tokenRecord.expires_at) <= now) {
        throw badRequest('enrollment_token_expired', 'Enrollment token has expired');
      }

      tokenRecord.used_at = now.toISOString();
      return clone(workload);
    });
  }

  public async listIntegrations({tenantId}: {tenantId: string}) {
    if (this.isDbEnabled()) {
      try {
        return await this.requireDbRepositories().integrationRepository.listByTenant({
          tenant_id: tenantId
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    this.findTenant(tenantId);
    return clone(this.state.integrations.filter(item => item.tenant_id === tenantId));
  }

  public async getIntegration({integrationId}: {integrationId: string}) {
    if (this.isDbEnabled()) {
      try {
        const integration = await this.requireDbRepositories().integrationRepository.getById({
          integration_id: integrationId
        });
        if (!integration) {
          throw notFound('integration_not_found', `Integration ${integrationId} was not found`);
        }
        return integration;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return clone(this.findIntegration(integrationId));
  }

  public async createIntegration({
    tenantId,
    payload,
    secretKey,
    secretKeyId
  }: CreateIntegrationInput): Promise<OpenApiIntegration> {
    if (this.isDbEnabled()) {
      const now = new Date().toISOString();
      const secretRef = generateId('sec_');
      const prisma = this.processInfrastructure?.prisma;
      if (!prisma) {
        throw serviceUnavailable('db_unavailable', 'Database client is unavailable');
      }

      try {
        return await runInTransactionForAdmin(prisma, async transactionClient => {
          const repositories = createDbRepositoriesForAdmin(
            createTransactionCapableDbClientForSecretWrites(transactionClient)
          );
          const template = await repositories.templateRepository.getLatestTemplateByTenantTemplateId({
            tenant_id: GLOBAL_TEMPLATE_TENANT_ID,
            template_id: payload.template_id
          });
          if (!template) {
            throw notFound('template_not_found', `Template ${payload.template_id} was not found`);
          }

          const integration = await repositories.integrationRepository.create({
            tenant_id: tenantId,
            payload,
            enabled: true
          });

          const encryptedEnvelope = await encryptSecretMaterialWithCryptoPackage({
            secretMaterial: payload.secret_material,
            key: secretKey,
            keyId: secretKeyId,
            aadContext: {
              tenant_id: tenantId,
              integration_id: integration.integration_id,
              secret_type: payload.secret_material.type
            }
          });

          await repositories.secretRepository.createSecretEnvelopeVersion({
            secret_ref: secretRef,
            tenant_id: tenantId,
            integration_id: integration.integration_id,
            secret_type: payload.secret_material.type,
            envelope: {
              key_id: encryptedEnvelope.key_id,
              content_encryption_alg: encryptedEnvelope.content_encryption_alg,
              key_encryption_alg: encryptedEnvelope.key_encryption_alg,
              wrapped_data_key_b64: encryptedEnvelope.wrapped_data_key_b64,
              iv_b64: encryptedEnvelope.iv_b64,
              ciphertext_b64: encryptedEnvelope.ciphertext_b64,
              auth_tag_b64: encryptedEnvelope.auth_tag_b64,
              ...(encryptedEnvelope.aad_b64 ? {aad_b64: encryptedEnvelope.aad_b64} : {})
            },
            created_at: now
          });

          return repositories.integrationRepository.bindSecret({
            integration_id: integration.integration_id,
            secret_ref: secretRef,
            secret_version: 1,
            last_rotated_at: now
          });
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(async () => {
      this.findTenant(tenantId);
      this.findTemplate(payload.template_id);

      const integrationId = generateId('i_');
      const secretRef = generateId('sec_');
      const encryptedEnvelope = await encryptSecretMaterialWithCryptoPackage({
        secretMaterial: payload.secret_material,
        key: secretKey,
        keyId: secretKeyId,
        aadContext: {
          tenant_id: tenantId,
          integration_id: integrationId,
          secret_type: payload.secret_material.type
        }
      });
      const now = new Date().toISOString();

      const integration = OpenApiIntegrationSchema.parse({
        integration_id: integrationId,
        tenant_id: tenantId,
        provider: payload.provider,
        name: payload.name,
        template_id: payload.template_id,
        enabled: true,
        secret_ref: secretRef,
        secret_version: 1,
        last_rotated_at: now
      });

      this.state.integrations.push(integration);
      this.state.secrets.push(
        secretRecordSchema.parse({
          secret_ref: secretRef,
          tenant_id: tenantId,
          integration_id: integrationId,
          type: payload.secret_material.type,
          active_version: 1,
          versions: [
            {
              version: 1,
              key_id: encryptedEnvelope.key_id,
              created_at: now,
              content_encryption_alg: encryptedEnvelope.content_encryption_alg,
              key_encryption_alg: encryptedEnvelope.key_encryption_alg,
              wrapped_data_key_b64: encryptedEnvelope.wrapped_data_key_b64,
              iv_b64: encryptedEnvelope.iv_b64,
              ciphertext_b64: encryptedEnvelope.ciphertext_b64,
              auth_tag_b64: encryptedEnvelope.auth_tag_b64,
              ...(encryptedEnvelope.aad_b64 ? {aad_b64: encryptedEnvelope.aad_b64} : {})
            }
          ]
        })
      );

      return clone(integration);
    });
  }

  public async updateIntegration({integrationId, enabled, templateId}: UpdateIntegrationInput) {
    if (this.isDbEnabled()) {
      try {
        if (templateId) {
          const template = await this.requireDbRepositories().templateRepository.getLatestTemplateByTenantTemplateId({
            tenant_id: GLOBAL_TEMPLATE_TENANT_ID,
            template_id: templateId
          });
          if (!template) {
            throw notFound('template_not_found', `Template ${templateId} was not found`);
          }
        }

        return await this.requireDbRepositories().integrationRepository.update({
          integration_id: integrationId,
          request: {
            ...(typeof enabled === 'boolean' ? {enabled} : {}),
            ...(templateId ? {template_id: templateId} : {})
          }
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      const integration = this.findIntegration(integrationId);

      if (templateId) {
        this.findTemplate(templateId);
      }

      const updated = OpenApiIntegrationSchema.parse({
        ...integration,
        ...(typeof enabled === 'boolean' ? {enabled} : {}),
        ...(templateId ? {template_id: templateId} : {})
      });

      const index = this.state.integrations.findIndex(item => item.integration_id === integrationId);
      if (index < 0) {
        throw notFound('integration_not_found', `Integration ${integrationId} was not found`);
      }
      this.state.integrations.splice(index, 1, updated);

      return clone(updated);
    });
  }

  public async listTemplates() {
    if (this.isDbEnabled()) {
      try {
        const prisma = this.processInfrastructure?.prisma;
        if (!prisma) {
          throw serviceUnavailable('db_unavailable', 'Template storage is unavailable');
        }

        const records = await prisma.templateVersion.findMany({
          where: {
            tenantId: GLOBAL_TEMPLATE_TENANT_ID,
            status: 'active'
          },
          orderBy: [
            {
              templateId: 'asc'
            },
            {
              version: 'asc'
            }
          ]
        });

        return records.map(record => OpenApiTemplateSchema.parse(record.templateJson));
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    const sorted = [...this.state.templates].sort((a, b) => {
      const templateIdSort = a.template_id.localeCompare(b.template_id);
      if (templateIdSort !== 0) {
        return templateIdSort;
      }

      return a.version - b.version;
    });

    return clone(sorted);
  }

  public async createTemplate({payload}: {payload: OpenApiTemplate}) {
    if (this.isDbEnabled()) {
      try {
        const existingTemplates = await this.listTemplates();
        const validation = validateTemplatePublish({
          candidate: payload,
          existing_templates: existingTemplates
        });
        if (!validation.ok) {
          switch (validation.error.code) {
            case 'template_version_conflict': {
              throw conflict('template_version_exists', validation.error.message);
            }
            case 'template_version_immutable': {
              throw conflict(validation.error.code, validation.error.message);
            }
            case 'template_version_not_incremented':
            case 'template_provider_mismatch': {
              throw badRequest(validation.error.code, validation.error.message);
            }
            default: {
              throw badRequest(validation.error.code, validation.error.message);
            }
          }
        }

        await this.ensureGlobalTemplateTenant();
        const template = await this.requireDbRepositories().templateRepository.createTemplateVersionImmutable({
          tenant_id: GLOBAL_TEMPLATE_TENANT_ID,
          template: validation.value
        });

        return {
          template_id: template.template_id,
          version: template.version
        };
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      const validation = validateTemplatePublish({
        candidate: payload,
        existing_templates: this.state.templates
      });
      if (!validation.ok) {
        switch (validation.error.code) {
          case 'template_version_conflict': {
            throw conflict('template_version_exists', validation.error.message);
          }
          case 'template_version_immutable': {
            throw conflict(validation.error.code, validation.error.message);
          }
          case 'template_version_not_incremented':
          case 'template_provider_mismatch': {
            throw badRequest(validation.error.code, validation.error.message);
          }
          default: {
            throw badRequest(validation.error.code, validation.error.message);
          }
        }
      }

      this.state.templates.push(validation.value);
      return {
        template_id: validation.value.template_id,
        version: validation.value.version
      };
    });
  }

  public async getTemplateVersion({templateId, version}: {templateId: string; version: number}) {
    if (this.isDbEnabled()) {
      try {
        const template = await this.requireDbRepositories().templateRepository.getTemplateByTenantTemplateIdVersion({
          tenant_id: GLOBAL_TEMPLATE_TENANT_ID,
          template_id: templateId,
          version
        });

        if (!template) {
          throw notFound('template_version_not_found', `Template ${templateId} version ${version} was not found`);
        }

        return template;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    const template = this.state.templates.find(item => item.template_id === templateId && item.version === version);

    if (!template) {
      throw notFound('template_version_not_found', `Template ${templateId} version ${version} was not found`);
    }

    return clone(template);
  }

  public async listPolicies() {
    if (this.isDbEnabled()) {
      try {
        const prisma = this.processInfrastructure?.prisma;
        if (!prisma) {
          throw serviceUnavailable('db_unavailable', 'Policy storage is unavailable');
        }

        const records = await prisma.policyRule.findMany({
          where: {
            enabled: true
          },
          orderBy: {
            createdAt: 'asc'
          },
          select: {
            policyJson: true
          }
        });

        return records.map(record => OpenApiPolicyRuleSchema.parse(record.policyJson));
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return clone(this.state.policies);
  }

  public async getPolicy({policyId}: {policyId: string}) {
    if (this.isDbEnabled()) {
      try {
        const policy = await this.requireDbRepositories().policyRuleRepository.getPolicyRuleById({
          policy_id: policyId
        });

        if (!policy) {
          throw notFound('policy_not_found', `Policy ${policyId} was not found`);
        }

        return policy;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    const policy = this.state.policies.find(item => item.policy_id === policyId);
    if (!policy) {
      throw notFound('policy_not_found', `Policy ${policyId} was not found`);
    }

    return clone(policy);
  }

  public async createPolicy({payload}: {payload: OpenApiPolicyRule}) {
    if (this.isDbEnabled()) {
      try {
        return await this.requireDbRepositories().policyRuleRepository.createPolicyRule({
          policy: payload
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      const policyId = payload.policy_id ?? generateId('pol_');
      if (this.state.policies.some(policy => policy.policy_id === policyId)) {
        throw conflict('policy_exists', `Policy ${policyId} already exists`);
      }

      const policy = OpenApiPolicyRuleSchema.parse({
        ...payload,
        policy_id: policyId
      });

      this.state.policies.push(policy);
      return clone(policy);
    });
  }

  public async deletePolicy({policyId}: {policyId: string}) {
    if (this.isDbEnabled()) {
      try {
        await this.requireDbRepositories().policyRuleRepository.disablePolicyRule({
          policy_id: policyId
        });
        return;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      const index = this.state.policies.findIndex(policy => policy.policy_id === policyId);
      if (index === -1) {
        throw notFound('policy_not_found', `Policy ${policyId} was not found`);
      }

      this.state.policies.splice(index, 1);
    });
  }

  public async listApprovals({status}: {status?: ApprovalRequest['status']}) {
    if (this.isDbEnabled()) {
      try {
        return await this.requireDbRepositories().approvalRequestRepository.list({
          ...(status ? {status} : {})
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      this.updateExpiredApprovals();
      const filtered = status
        ? this.state.approvals.filter(approval => approval.status === status)
        : this.state.approvals;

      return clone(filtered);
    });
  }

  public async getApproval({approvalId}: {approvalId: string}) {
    if (this.isDbEnabled()) {
      try {
        const approval = await this.requireDbRepositories().approvalRequestRepository.getById({
          approval_id: approvalId
        });
        if (!approval) {
          throw notFound('approval_not_found', `Approval ${approvalId} was not found`);
        }

        return approval;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      this.updateExpiredApprovals();
      const approval = this.state.approvals.find(item => item.approval_id === approvalId);
      if (!approval) {
        throw notFound('approval_not_found', `Approval ${approvalId} was not found`);
      }

      return clone(approval);
    });
  }

  public async decideApproval({
    approvalId,
    decision,
    request
  }: DecideApprovalInput): Promise<ApprovalDecisionResult> {
    if (this.isDbEnabled()) {
      const prisma = this.processInfrastructure?.prisma;
      if (!prisma) {
        throw serviceUnavailable('db_unavailable', 'Approval storage is unavailable');
      }

      try {
        return await runInTransactionForAdmin(prisma, async transactionClient => {
          const repositories = createDbRepositoriesForAdmin(transactionClient);
          const existing = await repositories.approvalRequestRepository.getById({
            approval_id: approvalId
          });

          if (!existing) {
            throw notFound('approval_not_found', `Approval ${approvalId} was not found`);
          }

          if (existing.status !== 'pending') {
            throw conflict('approval_not_pending', 'Approval request is no longer pending');
          }

          const updated = await repositories.approvalRequestRepository.transitionApprovalStatus({
            approval_id: approvalId,
            status: decision
          });

          let derivedPolicy: OpenApiPolicyRule | null = null;

          if (decision === 'denied' || request.mode === 'rule') {
            const derivedPolicyResult = derivePolicyFromApprovalDecision({
              approval_status: decision,
              approval_mode: request.mode,
              descriptor: updated.canonical_descriptor,
              ...(request.constraints ? {constraints: request.constraints} : {}),
              policy_id: generateId('pol_')
            });
            if (!derivedPolicyResult.ok) {
              throw badRequest(derivedPolicyResult.error.code, derivedPolicyResult.error.message);
            }
            if (!derivedPolicyResult.value) {
              throw badRequest('derived_policy_missing', 'Policy engine did not return a derived policy');
            }

            derivedPolicy = derivedPolicyResult.value;
            await repositories.policyRuleRepository.createPolicyRule({
              policy: derivedPolicy
            });
          }

          return {
            approval: updated,
            derivedPolicy
          };
        });
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      this.updateExpiredApprovals();

      const approval = this.state.approvals.find(item => item.approval_id === approvalId);
      if (!approval) {
        throw notFound('approval_not_found', `Approval ${approvalId} was not found`);
      }

      if (approval.status !== 'pending') {
        throw conflict('approval_not_pending', 'Approval request is no longer pending');
      }

      approval.status = decision;
      let derivedPolicy: OpenApiPolicyRule | null = null;

      if (decision === 'denied' || request.mode === 'rule') {
        const derivedPolicyResult = derivePolicyFromApprovalDecision({
          approval_status: decision,
          approval_mode: request.mode,
          descriptor: approval.canonical_descriptor,
          ...(request.constraints ? {constraints: request.constraints} : {}),
          policy_id: generateId('pol_')
        });
        if (!derivedPolicyResult.ok) {
          throw badRequest(derivedPolicyResult.error.code, derivedPolicyResult.error.message);
        }

        derivedPolicy = derivedPolicyResult.value;
      }

      if (derivedPolicy) {
        this.state.policies.push(derivedPolicy);
      }

      return {
        approval: clone(approval),
        derivedPolicy: derivedPolicy ? clone(derivedPolicy) : null
      };
    });
  }

  public async listAuditEvents({filter}: {filter: AuditFilter}) {
    if (this.isDbEnabled()) {
      try {
        const result = await this.requireDbRepositories().auditEventRepository.queryAuditEvents({
          ...(filter.timeMin ? {time_min: filter.timeMin.toISOString()} : {}),
          ...(filter.timeMax ? {time_max: filter.timeMax.toISOString()} : {}),
          ...(filter.tenantId ? {tenant_id: filter.tenantId} : {}),
          ...(filter.workloadId ? {workload_id: filter.workloadId} : {}),
          ...(filter.integrationId ? {integration_id: filter.integrationId} : {}),
          ...(filter.actionGroup ? {action_group: filter.actionGroup} : {}),
          ...(filter.decision ? {decision: filter.decision} : {})
        });

        return result.items;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    const filtered = this.state.audit_events.filter(event => {
      const eventTime = new Date(event.timestamp);
      if (filter.timeMin && eventTime < filter.timeMin) {
        return false;
      }

      if (filter.timeMax && eventTime > filter.timeMax) {
        return false;
      }

      if (filter.tenantId && event.tenant_id !== filter.tenantId) {
        return false;
      }

      if (filter.workloadId && event.workload_id !== filter.workloadId) {
        return false;
      }

      if (filter.integrationId && event.integration_id !== filter.integrationId) {
        return false;
      }

      if (filter.actionGroup && event.action_group !== filter.actionGroup) {
        return false;
      }

      if (filter.decision && event.decision !== filter.decision) {
        return false;
      }

      return true;
    });

    return clone(filtered);
  }

  public async appendAuditEvent({event}: {event: OpenApiAuditEvent}) {
    if (this.isDbEnabled()) {
      try {
        await this.requireDbRepositories().auditEventRepository.appendAuditEvent({event});
        return;
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    return this.withWriteLock(() => {
      this.state.audit_events.push(event);
    });
  }

  public async getManifestKeys() {
    if (this.isDbEnabled()) {
      try {
        const keyset = await this.requireDbRepositories().secretRepository.listManifestVerificationKeysWithEtag();
        if (keyset) {
          return {
            payload: keyset.manifest_keys,
            etag: keyset.etag
          };
        }
      } catch (error) {
        return mapDbRepositoryError(error);
      }
    }

    const payload = clone(this.state.manifest_keys);
    const etag = computeManifestKeysWeakEtagWithCryptoPackage({
      manifestKeys: payload
    });

    return {
      payload,
      etag
    };
  }

  public createAdminAuditEvent({
    actor,
    correlationId,
    action,
    tenantId,
    workloadId,
    integrationId,
    message,
    metadata
  }: {
    actor: AdminPrincipal;
    correlationId: string;
    action: string;
    tenantId: string;
    workloadId?: string;
    integrationId?: string;
    message?: string;
    metadata?: Record<string, unknown>;
  }) {
    return OpenApiAuditEventSchema.parse({
      event_id: generateId('evt_'),
      timestamp: new Date().toISOString(),
      tenant_id: tenantId,
      workload_id: workloadId ?? null,
      integration_id: integrationId ?? null,
      correlation_id: correlationId,
      event_type: 'admin_action',
      decision: null,
      action_group: null,
      risk_tier: null,
      destination: null,
      latency_ms: null,
      upstream_status_code: null,
      canonical_descriptor: null,
      policy: null,
      message: message ?? null,
      metadata: {
        action,
        actor_subject: actor.subject,
        actor_roles: actor.roles,
        actor_auth: actor.authContext,
        ...(metadata ?? {})
      }
    });
  }

  public createPolicyAuditEvent({
    actor,
    correlationId,
    tenantId,
    policy,
    action,
    message
  }: {
    actor: AdminPrincipal;
    correlationId: string;
    tenantId: string;
    policy: OpenApiPolicyRule;
    action: 'created' | 'deleted' | 'derived';
    message: string;
  }) {
    return OpenApiAuditEventSchema.parse({
      event_id: generateId('evt_'),
      timestamp: new Date().toISOString(),
      tenant_id: tenantId,
      workload_id: policy.scope.workload_id ?? null,
      integration_id: policy.scope.integration_id,
      correlation_id: correlationId,
      event_type: 'policy_decision',
      decision: policy.rule_type === 'deny' ? 'denied' : 'allowed',
      action_group: policy.scope.action_group,
      risk_tier: null,
      destination: null,
      latency_ms: null,
      upstream_status_code: null,
      canonical_descriptor: null,
      policy: {
        rule_id: policy.policy_id ?? null,
        rule_type: policy.rule_type,
        approval_id: null
      },
      message,
      metadata: {
        action,
        actor_subject: actor.subject,
        actor_roles: actor.roles,
        actor_auth: actor.authContext
      }
    });
  }
}

export type ApprovalStatusFilter = Exclude<ApprovalRequest['status'], 'executed' | 'canceled'>;

export const approvalStatusFilterSchema = z.enum(['pending', 'approved', 'denied', 'expired']);

export const auditFilterSchema = z
  .object({
    time_min: z.string().datetime({offset: true}).optional(),
    time_max: z.string().datetime({offset: true}).optional(),
    tenant_id: z.string().optional(),
    workload_id: z.string().optional(),
    integration_id: z.string().optional(),
    action_group: z.string().optional(),
    decision: z.enum(['allowed', 'denied', 'approval_required', 'throttled']).optional()
  })
  .strict();
