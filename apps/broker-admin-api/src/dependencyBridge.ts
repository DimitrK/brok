import {createHash} from 'node:crypto';

import {
  createAuditService,
  type AuditErrorCode,
  type AuditEventSearchQuery,
  type AuditStoreAdapter
} from '@broker-interceptor/audit';
import {
  issueExternalCaEnrollment,
  parseAndValidateCsr,
  type ExternalCaEnrollmentProvider
} from '@broker-interceptor/auth';
import {rotateManifestSigningKeys, type ManifestSigningPrivateKey} from '@broker-interceptor/crypto';
import {DbRepositoryError, createDbRepositories} from '@broker-interceptor/db';
import {validatePolicyRule} from '@broker-interceptor/policy-engine';
import {
  OpenApiAuditEventSchema,
  OpenApiAdminSessionPrincipalSchema,
  type OpenApiAdminSignupPolicy,
  type OpenApiManifestKeys,
  type OpenApiAuditEvent,
  type OpenApiAdminSessionPrincipal,
  type OpenApiPolicyRule
} from '@broker-interceptor/schemas';

import type {AdminAuthenticator, AdminPrincipal} from './auth';
import type {CertificateIssuer, IssueCertificateInput, IssueCertificateResult} from './certificateIssuer';
import {buildManifestSigningPrivateKeyRef} from './crypto';
import {extractCsrMetadata} from './csr';
import {badRequest, conflict, forbidden, isAppError, notFound, serviceUnavailable, unauthorized} from './errors';
import type {ProcessInfrastructure} from './infrastructure';
import type {ControlPlaneRepository, RepositoryAdminAccessRequest} from './repository';

export type RequiredDependency = {
  packageName: string;
  requiredMethods: string[];
  integrationStatus: 'wired' | 'pending';
};

const REQUIRED_DEPENDENCIES: ReadonlyArray<RequiredDependency> = [
  {
    packageName: '@broker-interceptor/db',
    requiredMethods: [
      'persistTenants',
      'persistWorkloads',
      'persistIntegrations',
      'persistTemplates',
      'persistPolicies',
      'persistApprovals',
      'persistAuditEvents',
      'persistEnrollmentTokens',
      'persistSecrets',
      'persistManifestKeys',
      'persistManifestKeyRotation'
    ],
    integrationStatus: 'wired'
  },
  {
    packageName: '@broker-interceptor/audit',
    requiredMethods: ['appendAuditEvent', 'queryAuditEvents'],
    integrationStatus: 'wired'
  },
  {
    packageName: '@broker-interceptor/auth',
    requiredMethods: ['parseAndValidateCsr', 'signCsrWithVault', 'issueExternalCaEnrollment'],
    integrationStatus: 'pending'
  },
  {
    packageName: '@broker-interceptor/policy-engine',
    requiredMethods: ['validatePolicyRule', 'derivePolicyFromApprovalDecision'],
    integrationStatus: 'wired'
  },
  {
    packageName: '@broker-interceptor/crypto',
    requiredMethods: [
      'generateManifestSigningKeyPair',
      'buildManifestKeySet',
      'computeManifestKeysEtag',
      'rotateManifestSigningKeys',
      'encryptSecretMaterial',
      'decryptSecretMaterial'
    ],
    integrationStatus: 'wired'
  }
] as const;

const mapAuditErrorCodeToAppError = ({code, message}: {code: AuditErrorCode; message: string}) => {
  if (
    code === 'invalid_input' ||
    code === 'invalid_search_query' ||
    code === 'invalid_time_range' ||
    code === 'redaction_profile_invalid'
  ) {
    return badRequest('audit_query_invalid', message);
  }

  return serviceUnavailable('audit_storage_unavailable', message);
};

const mapCsrValidationError = (errorCode: 'csr_invalid' | 'csr_san_mismatch' | 'csr_eku_missing') => {
  switch (errorCode) {
    case 'csr_invalid': {
      return badRequest('csr_invalid', 'CSR payload is invalid');
    }
    case 'csr_san_mismatch': {
      return badRequest('csr_san_mismatch', 'CSR SAN URIs do not include the expected workload SAN URI');
    }
    case 'csr_eku_missing': {
      return badRequest('csr_eku_missing', 'CSR EKU does not include clientAuth usage');
    }
  }
};

const mapExternalCaEnrollmentError = ({
  code,
  message
}: {
  code:
    | 'external_ca_not_configured'
    | 'external_ca_unreachable'
    | 'external_ca_profile_invalid'
    | 'external_ca_enrollment_denied';
  message: string;
}) => {
  switch (code) {
    case 'external_ca_profile_invalid':
    case 'external_ca_enrollment_denied': {
      return badRequest(code, message);
    }
    case 'external_ca_not_configured':
    case 'external_ca_unreachable': {
      return serviceUnavailable(code, message);
    }
  }
};

const mapManifestKeyRotationError = ({code, message}: {code: string; message: string}) => {
  switch (code) {
    case 'manifest_key_rotation_invalid':
    case 'manifest_signing_key_invalid':
    case 'manifest_key_mismatch': {
      return badRequest(code, message);
    }
    case 'manifest_keys_etag_failed': {
      return serviceUnavailable(code, message);
    }
    default: {
      return badRequest('manifest_key_rotation_invalid', message);
    }
  }
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

const DEFAULT_MANIFEST_KEYSET_MAX_AGE_SECONDS = 120;

type SecretRepositoryForManifestRotation = ReturnType<typeof createDbRepositories>['secretRepository'] & {
  createManifestSigningKeyRecord: (
    input: {
      kid: string;
      alg: 'EdDSA' | 'ES256';
      public_jwk: unknown;
      private_key_ref: string;
      created_at: string;
    },
    context?: {transaction_client?: unknown}
  ) => Promise<unknown>;
  setActiveManifestSigningKey: (
    input: {
      kid: string;
      activated_at: string;
    },
    context?: {transaction_client?: unknown}
  ) => Promise<unknown>;
  transitionManifestSigningKeyStatus: (
    input: {
      kid: string;
      status: 'retired' | 'revoked';
      at: string;
    },
    context?: {transaction_client?: unknown}
  ) => Promise<unknown>;
};

type DbRepositoriesForManifestRotation = ReturnType<typeof createDbRepositories> & {
  secretRepository: SecretRepositoryForManifestRotation;
};

type ExistingManifestSigningKeyRecord = {
  kid: string;
  alg: 'EdDSA' | 'ES256';
  publicJwk: unknown;
};

type ManifestSigningKeyLookupClient = {
  manifestSigningKey: {
    findMany: (input: {
      select: {
        kid: true;
        alg?: true;
        publicJwk?: true;
        status?: true;
      };
    }) => Promise<
      Array<{kid: string; alg?: 'EdDSA' | 'ES256'; publicJwk?: unknown; status?: 'active' | 'retired' | 'revoked'}>
    >;
    updateMany: (input: {
      where: {
        kid: {
          in: string[];
        };
      };
      data: {
        status: 'retired' | 'revoked';
        retiredAt?: Date;
        revokedAt?: Date;
      };
    }) => Promise<unknown>;
  };
};

const createDbRepositoriesForManifestRotation = (dbClient: unknown): DbRepositoriesForManifestRotation =>
  createDbRepositories(
    dbClient as Parameters<typeof createDbRepositories>[0]
  ) as unknown as DbRepositoriesForManifestRotation;

const normalizeComparableJson = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(item => normalizeComparableJson(item));
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, normalizeComparableJson(entry)])
    );
  }

  return value;
};

const areManifestKeysEquivalent = ({left, right}: {left: unknown; right: unknown}) =>
  JSON.stringify(normalizeComparableJson(left)) === JSON.stringify(normalizeComparableJson(right));

const toAdminSessionPrincipal = ({principal}: {principal: AdminPrincipal}): OpenApiAdminSessionPrincipal =>
  OpenApiAdminSessionPrincipalSchema.parse({
    subject: principal.subject,
    issuer: principal.issuer,
    email: principal.email,
    ...(principal.name ? {name: principal.name} : {}),
    roles: principal.roles,
    tenant_ids: principal.tenantIds ?? []
  });

const buildDeterministicAdminAccessRequestId = ({issuer, subject}: {issuer: string; subject: string}) => {
  const digest = createHash('sha256').update(`${issuer}:${subject}`, 'utf8').digest('hex');
  return `aar_${digest.slice(0, 24)}`;
};

const assertOwnerForAdminUserManagement = ({actor, operation}: {actor: AdminPrincipal; operation: string}) => {
  if (!actor.roles.includes('owner')) {
    throw forbidden('admin_forbidden', `Only owner role can ${operation}`);
  }
};

export class DependencyBridge {
  private readonly auditService;

  public constructor(
    private readonly dependencies: {
      repository: ControlPlaneRepository;
      authenticator: AdminAuthenticator;
      certificateIssuer: CertificateIssuer;
      externalCaEnrollmentProvider?: ExternalCaEnrollmentProvider;
      processInfrastructure?: ProcessInfrastructure;
      manifestKeyEncryption?: {
        key: Buffer;
        keyId: string;
      };
    }
  ) {
    const store: AuditStoreAdapter = {
      appendAuditEvent: ({event}) => this.dependencies.repository.appendAuditEvent({event}),
      queryAuditEvents: ({filter}) =>
        this.dependencies.repository.listAuditEvents({
          filter: {
            ...(filter.time_min ? {timeMin: filter.time_min} : {}),
            ...(filter.time_max ? {timeMax: filter.time_max} : {}),
            ...(filter.tenant_id ? {tenantId: filter.tenant_id} : {}),
            ...(filter.workload_id ? {workloadId: filter.workload_id} : {}),
            ...(filter.integration_id ? {integrationId: filter.integration_id} : {}),
            ...(filter.action_group ? {actionGroup: filter.action_group} : {}),
            ...(filter.decision ? {decision: filter.decision} : {})
          }
        })
    };

    this.auditService = createAuditService({store});
  }

  public listRequiredDependencies() {
    return [...REQUIRED_DEPENDENCIES];
  }

  public getMtlsCaPemFromAuthPackage() {
    // Resolved from the configured certificate issuer profile.
    return this.dependencies.certificateIssuer.mtlsCaPem;
  }

  public async ensureEnrollmentModeSupported_INCOMPLETE({
    enrollmentMode,
    tenantId,
    workloadName
  }: {
    enrollmentMode: 'broker_ca' | 'external_ca';
    tenantId: string;
    workloadName: string;
  }): Promise<{mtlsCaPem?: string; enrollmentReference?: string}> {
    if (enrollmentMode !== 'external_ca') {
      return {};
    }

    const externalCaEnrollmentResult = await issueExternalCaEnrollment({
      input: {
        tenantId,
        workloadName
      },
      provider: this.dependencies.externalCaEnrollmentProvider
    });
    if (!externalCaEnrollmentResult.ok) {
      throw mapExternalCaEnrollmentError(externalCaEnrollmentResult.error);
    }

    return {
      mtlsCaPem: externalCaEnrollmentResult.value.mtlsCaPem,
      ...(externalCaEnrollmentResult.value.enrollmentReference
        ? {enrollmentReference: externalCaEnrollmentResult.value.enrollmentReference}
        : {})
    };
  }

  public async authenticateAdminPrincipal({
    authorizationHeader
  }: {
    authorizationHeader: string | undefined;
  }): Promise<AdminPrincipal> {
    // Authenticated by local static/OIDC admin authenticator configuration.
    return this.dependencies.authenticator.authenticate(authorizationHeader);
  }

  public async resolveAdminIdentityFromToken({principal}: {principal: AdminPrincipal}): Promise<AdminPrincipal> {
    if (principal.authContext.mode === 'static') {
      return principal;
    }

    const identity = await this.dependencies.repository.findAdminIdentityByIssuerSubject({
      issuer: principal.issuer,
      subject: principal.subject
    });

    if (identity) {
      if (identity.status === 'disabled') {
        throw forbidden('admin_identity_disabled', 'Admin identity is disabled');
      }

      if (identity.status === 'pending') {
        throw unauthorized('admin_access_request_pending', 'Admin access request is pending approval');
      }

      return {
        ...principal,
        roles: identity.roles,
        tenantIds: identity.tenant_ids
      };
    }

    return this.evaluateSignupPolicy({principal});
  }

  public async evaluateSignupPolicy({principal}: {principal: AdminPrincipal}): Promise<AdminPrincipal> {
    if (principal.authContext.mode === 'static') {
      return principal;
    }

    const policy = await this.dependencies.repository.getAdminSignupPolicy();
    if (policy.require_verified_email && principal.emailVerified !== true) {
      throw unauthorized('admin_signup_email_unverified', 'Admin sign-in requires a verified email address');
    }

    const emailDomain = principal.email.toLowerCase().split('@')[1] ?? '';
    if (
      Array.isArray(policy.allowed_email_domains) &&
      policy.allowed_email_domains.length > 0 &&
      !policy.allowed_email_domains.map(domain => domain.toLowerCase()).includes(emailDomain)
    ) {
      throw forbidden('admin_signup_domain_blocked', 'Admin email domain is not allowed');
    }

    if (policy.new_user_mode === 'blocked') {
      const request = await this.createAdminAccessRequest({
        principal,
        reason: 'New user signup is blocked; admin approval is required'
      });
      throw unauthorized(
        'admin_access_request_pending',
        `Admin access request is pending approval (${request.request_id})`
      );
    }

    const sessionPrincipal = toAdminSessionPrincipal({principal});
    try {
      const createdIdentity = await this.dependencies.repository.createAdminIdentity({
        principal: sessionPrincipal,
        status: 'active'
      });

      return {
        ...principal,
        roles: createdIdentity.roles,
        tenantIds: createdIdentity.tenant_ids
      };
    } catch (error) {
      if (!isAppError(error) || error.code !== 'db_conflict') {
        throw error;
      }

      const existingIdentity = await this.dependencies.repository.findAdminIdentityByIssuerSubject({
        issuer: principal.issuer,
        subject: principal.subject
      });
      if (!existingIdentity) {
        throw error;
      }

      if (existingIdentity.status !== 'active') {
        throw unauthorized('admin_access_request_pending', 'Admin identity is not active');
      }

      return {
        ...principal,
        roles: existingIdentity.roles,
        tenantIds: existingIdentity.tenant_ids
      };
    }
  }

  public async createAdminAccessRequest({
    principal,
    reason
  }: {
    principal: AdminPrincipal;
    reason?: string;
  }): Promise<RepositoryAdminAccessRequest> {
    const sessionPrincipal = toAdminSessionPrincipal({principal});
    const requestId = buildDeterministicAdminAccessRequestId({
      issuer: sessionPrincipal.issuer,
      subject: sessionPrincipal.subject
    });

    try {
      return await this.dependencies.repository.createAdminAccessRequest({
        principal: sessionPrincipal,
        requestId,
        ...(reason ? {reason} : {})
      });
    } catch (error) {
      if (!isAppError(error) || error.code !== 'db_conflict') {
        throw error;
      }

      return {
        request_id: requestId,
        issuer: sessionPrincipal.issuer,
        subject: sessionPrincipal.subject,
        email: sessionPrincipal.email,
        ...(sessionPrincipal.name ? {name: sessionPrincipal.name} : {}),
        requested_roles: sessionPrincipal.roles,
        requested_tenant_ids: sessionPrincipal.tenant_ids,
        status: 'pending',
        ...(reason ? {reason} : {}),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
    }
  }

  public async listAdminUsers({
    actor,
    status,
    tenantId,
    role,
    search,
    limit,
    cursor
  }: {
    actor: AdminPrincipal;
    status?: 'active' | 'pending' | 'disabled';
    tenantId?: string;
    role?: OpenApiAdminSessionPrincipal['roles'][number];
    search?: string;
    limit?: number;
    cursor?: string;
  }) {
    assertOwnerForAdminUserManagement({
      actor,
      operation: 'list admin users'
    });
    return this.dependencies.repository.listAdminUsers({
      ...(status ? {status} : {}),
      ...(tenantId ? {tenantId} : {}),
      ...(role ? {role} : {}),
      ...(search ? {search} : {}),
      ...(typeof limit === 'number' ? {limit} : {}),
      ...(cursor ? {cursor} : {})
    });
  }

  public async updateAdminUserRolesAndTenants({
    identityId,
    actor,
    roles,
    tenantIds
  }: {
    identityId: string;
    actor: AdminPrincipal;
    roles?: OpenApiAdminSessionPrincipal['roles'];
    tenantIds?: string[];
  }) {
    assertOwnerForAdminUserManagement({
      actor,
      operation: 'update admin user role bindings'
    });

    if (roles === undefined && tenantIds === undefined) {
      throw badRequest('admin_user_update_invalid', 'At least one of roles or tenant_ids must be provided');
    }

    return this.dependencies.repository.updateAdminUserRolesAndTenants({
      identityId,
      ...(roles ? {roles} : {}),
      ...(tenantIds ? {tenantIds} : {})
    });
  }

  public async setAdminUserStatus({
    identityId,
    actor,
    status
  }: {
    identityId: string;
    actor: AdminPrincipal;
    status: 'active' | 'pending' | 'disabled';
  }) {
    assertOwnerForAdminUserManagement({
      actor,
      operation: 'update admin user status'
    });

    return this.dependencies.repository.setAdminUserStatus({
      identityId,
      status
    });
  }

  public async updateAdminUser({
    identityId,
    actor,
    status,
    roles,
    tenantIds
  }: {
    identityId: string;
    actor: AdminPrincipal;
    status?: 'active' | 'pending' | 'disabled';
    roles?: OpenApiAdminSessionPrincipal['roles'];
    tenantIds?: string[];
  }) {
    assertOwnerForAdminUserManagement({
      actor,
      operation: 'update admin users'
    });

    return this.dependencies.repository.updateAdminUser({
      identityId,
      ...(status !== undefined ? {status} : {}),
      ...(roles !== undefined ? {roles} : {}),
      ...(tenantIds !== undefined ? {tenantIds} : {})
    });
  }

  public async listAdminAccessRequests({
    actor,
    status,
    tenantId,
    role,
    search,
    limit,
    cursor
  }: {
    actor: AdminPrincipal;
    status?: RepositoryAdminAccessRequest['status'];
    tenantId?: string;
    role?: OpenApiAdminSessionPrincipal['roles'][number];
    search?: string;
    limit?: number;
    cursor?: string;
  }) {
    assertOwnerForAdminUserManagement({
      actor,
      operation: 'list admin access requests'
    });

    return this.dependencies.repository.listAdminAccessRequests({
      ...(status ? {status} : {}),
      ...(tenantId ? {tenantId} : {}),
      ...(role ? {role} : {}),
      ...(search ? {search} : {}),
      ...(typeof limit === 'number' ? {limit} : {}),
      ...(cursor ? {cursor} : {})
    });
  }

  public async approveAdminAccessRequestWithOverrides({
    requestId,
    actor,
    roles,
    tenantIds,
    reason
  }: {
    requestId: string;
    actor: AdminPrincipal;
    roles?: OpenApiAdminSessionPrincipal['roles'];
    tenantIds?: string[];
    reason?: string;
  }) {
    assertOwnerForAdminUserManagement({
      actor,
      operation: 'approve admin access requests'
    });

    const transitioned = await this.dependencies.repository.transitionAdminAccessRequestStatus({
      requestId,
      status: 'approved',
      actor: actor.subject,
      ...(reason ? {reason} : {})
    });
    const effectiveRoles = roles ?? transitioned.requested_roles;
    const effectiveTenantIds = tenantIds ?? transitioned.requested_tenant_ids;

    const existingIdentity = await this.dependencies.repository.findAdminIdentityByIssuerSubject({
      issuer: transitioned.issuer,
      subject: transitioned.subject
    });

    if (existingIdentity) {
      if (existingIdentity.status !== 'active') {
        throw conflict(
          'admin_identity_state_invalid',
          'Admin identity is not active and cannot be approved through role upsert'
        );
      }

      await this.dependencies.repository.upsertAdminRoleBindings({
        issuer: transitioned.issuer,
        subject: transitioned.subject,
        roles: effectiveRoles,
        tenantIds: effectiveTenantIds
      });

      return transitioned;
    }

    await this.dependencies.repository.createAdminIdentity({
      status: 'active',
      principal: OpenApiAdminSessionPrincipalSchema.parse({
        subject: transitioned.subject,
        issuer: transitioned.issuer,
        email: transitioned.email,
        ...(transitioned.name ? {name: transitioned.name} : {}),
        roles: effectiveRoles,
        tenant_ids: effectiveTenantIds
      })
    });

    return transitioned;
  }

  public async approveAdminAccessRequest({requestId, actor}: {requestId: string; actor: AdminPrincipal}) {
    return this.approveAdminAccessRequestWithOverrides({
      requestId,
      actor
    });
  }

  public async denyAdminAccessRequest({
    requestId,
    actor,
    reason
  }: {
    requestId: string;
    actor: AdminPrincipal;
    reason: string;
  }) {
    assertOwnerForAdminUserManagement({
      actor,
      operation: 'deny admin access requests'
    });

    return this.dependencies.repository.transitionAdminAccessRequestStatus({
      requestId,
      status: 'denied',
      actor: actor.subject,
      reason
    });
  }

  public async setAdminSignupMode({
    mode,
    actor
  }: {
    mode: 'allowed' | 'blocked';
    actor: AdminPrincipal;
  }): Promise<OpenApiAdminSignupPolicy> {
    return this.dependencies.repository.setAdminSignupPolicy({
      policy: {
        new_user_mode: mode
      },
      actor: actor.subject
    });
  }

  public async validateEnrollmentCsrWithAuthPackage({
    csrPem,
    expectedSanUri,
    requireClientAuthEku
  }: {
    csrPem: string;
    expectedSanUri: string;
    requireClientAuthEku: boolean;
  }) {
    const validationResult = await parseAndValidateCsr({
      csrPem,
      expectedSanUri,
      requireClientAuthEku,
      parseCsr: pem => extractCsrMetadata({csrPem: pem})
    });
    if (!validationResult.ok) {
      const errorCode =
        validationResult.error === 'csr_san_mismatch' || validationResult.error === 'csr_eku_missing'
          ? validationResult.error
          : 'csr_invalid';
      throw mapCsrValidationError(errorCode);
    }
  }

  public async issueWorkloadCertificateWithAuthPackage({
    input
  }: {
    input: IssueCertificateInput;
  }): Promise<IssueCertificateResult> {
    // Delegates to certificate issuer; vault mode is implemented through @broker-interceptor/auth helpers.
    return this.dependencies.certificateIssuer.issue(input);
  }

  public validatePolicyRuleWithPolicyEngine({policy}: {policy: OpenApiPolicyRule}): OpenApiPolicyRule {
    const policyValidationResult = validatePolicyRule({policy});
    if (!policyValidationResult.ok) {
      throw badRequest(policyValidationResult.error.code, policyValidationResult.error.message);
    }

    return policyValidationResult.value;
  }

  public async appendAuditEventWithAuditPackage({event}: {event: OpenApiAuditEvent}): Promise<void> {
    const parsedEvent = OpenApiAuditEventSchema.parse(event);
    const appendResult = await this.auditService.appendAuditEvent({event: parsedEvent});
    if (!appendResult.ok) {
      throw mapAuditErrorCodeToAppError(appendResult.error);
    }
  }

  public async queryAuditEventsWithAuditPackage({query}: {query: AuditEventSearchQuery}): Promise<OpenApiAuditEvent[]> {
    const queryResult = await this.auditService.queryAuditEvents({query});
    if (!queryResult.ok) {
      throw mapAuditErrorCodeToAppError(queryResult.error);
    }

    return queryResult.value.events;
  }

  public persistStateWithDbPackage() {
    if (this.dependencies.processInfrastructure?.enabled) {
      // Control-plane repository now speaks to db directly when infra is enabled.
      void this.dependencies.processInfrastructure;
    }
    return Promise.resolve();
  }

  public persistManifestKeyRotationWithDbPackage_INCOMPLETE({
    activeSigningPrivateKey,
    rotatedManifestKeys,
    etag
  }: {
    activeSigningPrivateKey: ManifestSigningPrivateKey;
    rotatedManifestKeys: OpenApiManifestKeys;
    etag: string;
  }) {
    const infrastructure = this.dependencies.processInfrastructure;
    if (!infrastructure?.enabled) {
      return Promise.resolve();
    }

    const prisma = infrastructure.prisma;
    if (!prisma) {
      throw serviceUnavailable('db_unavailable', 'Database client is unavailable');
    }

    const keyEncryption = this.dependencies.manifestKeyEncryption;
    if (!keyEncryption) {
      throw serviceUnavailable('manifest_key_persist_unavailable', 'Manifest key encryption is not configured');
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const activePublicKey = rotatedManifestKeys.keys.find(key => key.kid === activeSigningPrivateKey.kid);
    if (!activePublicKey) {
      throw badRequest('manifest_key_mismatch', 'Active signing key is missing from rotated manifest keys');
    }

    return infrastructure
      .withTransaction(async transactionClient => {
        const repositories = createDbRepositoriesForManifestRotation(transactionClient);
        const manifestSigningKeyLookupClient = transactionClient as unknown as ManifestSigningKeyLookupClient;
        const existingRecordsRaw = await manifestSigningKeyLookupClient.manifestSigningKey.findMany({
          select: {
            kid: true,
            alg: true,
            publicJwk: true
          }
        });
        const existingRecords = existingRecordsRaw
          .filter(
            (record): record is ExistingManifestSigningKeyRecord =>
              (record.alg === 'EdDSA' || record.alg === 'ES256') && record.publicJwk !== undefined
          )
          .map(record => ({
            kid: record.kid,
            alg: record.alg,
            publicJwk: record.publicJwk
          }));
        const existingRecordByKid = new Map(existingRecords.map(record => [record.kid, record]));
        const desiredKeys = rotatedManifestKeys.keys;
        const retainedKidSet = new Set(desiredKeys.map(key => key.kid));

        for (const key of desiredKeys) {
          const existingRecord = existingRecordByKid.get(key.kid);
          if (existingRecord) {
            if (
              existingRecord.alg !== key.alg ||
              !areManifestKeysEquivalent({
                left: existingRecord.publicJwk,
                right: key
              })
            ) {
              throw conflict(
                'manifest_key_conflict',
                `Persisted manifest key ${key.kid} does not match rotated key material`
              );
            }
            continue;
          }

          const privateKeyRef =
            key.kid === activeSigningPrivateKey.kid
              ? await buildManifestSigningPrivateKeyRef({
                  signingKey: activeSigningPrivateKey,
                  key: keyEncryption.key,
                  keyId: keyEncryption.keyId
                })
              : `external://unavailable/manifest/${key.kid}`;

          await repositories.secretRepository.createManifestSigningKeyRecord(
            {
              kid: key.kid,
              alg: key.alg,
              public_jwk: key,
              private_key_ref: privateKeyRef,
              created_at: nowIso
            },
            {transaction_client: transactionClient}
          );
          existingRecordByKid.set(key.kid, {
            kid: key.kid,
            alg: key.alg,
            publicJwk: key
          });
        }

        await repositories.secretRepository.setActiveManifestSigningKey(
          {
            kid: activeSigningPrivateKey.kid,
            activated_at: nowIso
          },
          {transaction_client: transactionClient}
        );

        const allKeys = await manifestSigningKeyLookupClient.manifestSigningKey.findMany({
          select: {
            kid: true,
            status: true
          }
        });
        const retiredKidUpdates: string[] = [];
        const revokedKidUpdates: string[] = [];

        for (const record of allKeys) {
          if (record.kid === activeSigningPrivateKey.kid) {
            continue;
          }

          const targetStatus = retainedKidSet.has(record.kid) ? 'retired' : 'revoked';
          if (record.status === targetStatus) {
            continue;
          }

          if (record.status === 'revoked' && targetStatus === 'retired') {
            throw conflict(
              'manifest_key_state_transition_invalid',
              `Persisted manifest key ${record.kid} cannot transition from revoked to retired`
            );
          }

          if (targetStatus === 'retired') {
            retiredKidUpdates.push(record.kid);
            continue;
          }

          revokedKidUpdates.push(record.kid);
        }

        if (retiredKidUpdates.length > 0) {
          // Deviation note: @broker-interceptor/db currently exposes only single-key transition methods.
          // Bulk update is kept local here to reduce transaction time; switch to a db-package batch
          // transition contract once available to centralize transition guardrails in one place.
          await manifestSigningKeyLookupClient.manifestSigningKey.updateMany({
            where: {
              kid: {
                in: retiredKidUpdates
              }
            },
            data: {
              status: 'retired',
              retiredAt: now
            }
          });
        }

        if (revokedKidUpdates.length > 0) {
          await manifestSigningKeyLookupClient.manifestSigningKey.updateMany({
            where: {
              kid: {
                in: revokedKidUpdates
              }
            },
            data: {
              status: 'revoked',
              revokedAt: now
            }
          });
        }

        await repositories.secretRepository.persistManifestKeysetMetadata(
          {
            etag,
            generated_at: nowIso,
            max_age_seconds: DEFAULT_MANIFEST_KEYSET_MAX_AGE_SECONDS
          },
          {transaction_client: transactionClient}
        );
      })
      .catch(mapDbRepositoryError);
  }

  public async rotateManifestSigningKeysWithCryptoPackage_INCOMPLETE({
    signingAlgorithm = 'EdDSA',
    retainPreviousKeyCount = 1,
    newKeyId
  }: {
    signingAlgorithm?: 'EdDSA' | 'ES256';
    retainPreviousKeyCount?: number;
    newKeyId?: string;
  } = {}) {
    const currentManifestKeys = (await this.dependencies.repository.getManifestKeys()).payload;
    const rotationResult = await rotateManifestSigningKeys({
      current_manifest_keys: currentManifestKeys,
      signing_alg: signingAlgorithm,
      ...(newKeyId ? {new_kid: newKeyId} : {}),
      retain_previous_key_count: retainPreviousKeyCount
    });
    if (!rotationResult.ok) {
      throw mapManifestKeyRotationError(rotationResult.error);
    }

    await this.persistManifestKeyRotationWithDbPackage_INCOMPLETE({
      activeSigningPrivateKey: rotationResult.value.active_signing_private_key,
      rotatedManifestKeys: rotationResult.value.rotated_manifest_keys,
      etag: rotationResult.value.etag
    });

    return {
      activeSigningPrivateKey: rotationResult.value.active_signing_private_key,
      rotatedManifestKeys: rotationResult.value.rotated_manifest_keys,
      etag: rotationResult.value.etag
    };
  }
}
