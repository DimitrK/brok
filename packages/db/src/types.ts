export type CursorPaginationInput = {
  cursor?: string
  limit?: number
}

export type CursorPage<T> = {
  items: T[]
  next_cursor?: string
}

export type RepositoryOperationContext = {
  transaction_client?: unknown
  clients?: {
    postgres?: unknown
    redis?: unknown
  }
}

type DbMethod<TResult> = (args: Record<string, unknown>) => Promise<TResult>

export type TenantRow = {
  tenantId: string
  name: string
  createdAt: Date
}

export type HumanUserRoleRow = {
  role: string
}

export type HumanUserRow = {
  userId: string
  tenantId: string
  email: string
  enabled: boolean
  displayName: string | null
  oidcSubject: string | null
  oidcIssuer: string | null
  createdAt: Date
}

export type HumanUserRowWithRoles = HumanUserRow & {
  roles: HumanUserRoleRow[]
}

export type AdminSignupPolicyRow = {
  id: string
  newUserMode: 'allowed' | 'blocked'
  requireVerifiedEmail: boolean
  allowedEmailDomains: string[]
  updatedBy: string
  updatedAt: Date
}

export type AdminIdentityRoleBindingRow = {
  role: 'owner' | 'admin' | 'auditor' | 'operator'
}

export type AdminIdentityTenantScopeRow = {
  tenantId: string
}

export type AdminIdentityRow = {
  identityId: string
  issuer: string
  subject: string
  email: string
  name: string | null
  status: 'active' | 'pending' | 'disabled'
  createdAt: Date
  updatedAt: Date
}

export type AdminIdentityRowWithBindings = AdminIdentityRow & {
  roleBindings: AdminIdentityRoleBindingRow[]
  tenantScopes: AdminIdentityTenantScopeRow[]
}

export type AdminAccessRequestRow = {
  requestId: string
  issuer: string
  subject: string
  email: string
  name: string | null
  requestedRoles: Array<'owner' | 'admin' | 'auditor' | 'operator'>
  requestedTenantIds: string[]
  status: 'pending' | 'approved' | 'denied' | 'canceled'
  requestReason: string | null
  decisionReason: string | null
  decidedBy: string | null
  decidedAt: Date | null
  createdAt: Date
  updatedAt: Date
}

export type WorkloadRow = {
  workloadId: string
  tenantId: string
  name: string
  mtlsSanUri: string
  enabled: boolean
  ipAllowlist: string[]
  createdAt: Date
}

export type EnrollmentTokenRow = {
  tokenHash: string
  workloadId: string
  tenantId: string
  expiresAt: Date
  usedAt: Date | null
  createdAt: Date
}

export type WorkloadSessionRow = {
  sessionId: string
  workloadId: string
  tenantId: string
  certFingerprint256: string
  tokenHash: string
  dpopJkt: string | null
  scopes: unknown
  expiresAt: Date
}

export type IntegrationRow = {
  integrationId: string
  tenantId: string
  provider: string
  name: string
  templateId: string
  templateVersion: number | null
  enabled: boolean
  secretRef: string | null
  secretVersion: number | null
  lastRotatedAt: Date | null
}

export type SecretRow = {
  secretRef: string
  tenantId: string
  integrationId: string
  type: 'api_key' | 'oauth_refresh_token'
  activeVersion: number
}

export type SecretVersionRow = {
  secretRef: string
  version: number
  keyId: string
  contentEncryptionAlg: string
  keyEncryptionAlg: string
  wrappedDataKeyB64: string
  ivB64: string
  ciphertextB64: string
  authTagB64: string
  aadB64: string | null
  createdAt: Date
}

export type SecretVersionRowWithSecret = SecretVersionRow & {
  secret: {
    tenantId: string
    integrationId: string
    type: 'api_key' | 'oauth_refresh_token'
  }
}

export type ManifestSigningKeyRow = {
  kid: string
  alg: 'EdDSA' | 'ES256'
  publicJwk: unknown
  privateKeyRef: string
  status: 'active' | 'retired' | 'revoked'
  createdAt: Date
  activatedAt: Date | null
  retiredAt: Date | null
  revokedAt: Date | null
}

export type ManifestKeysetMetadataRow = {
  keysetName: string
  etag: string
  generatedAt: Date
  maxAgeSeconds: number
  createdAt: Date
  updatedAt: Date
}

export type CryptoVerificationDefaultsRow = {
  tenantId: string
  requireTemporalValidity: boolean
  maxClockSkewSeconds: number
  createdAt: Date
  updatedAt: Date
}

export type TemplateVersionRow = {
  templateId: string
  version: number
  provider: string
  status: 'active' | 'disabled'
  templateJson: unknown
}

export type PolicyRuleRow = {
  policyJson: unknown
  enabled: boolean
}

export type ApprovalRequestRow = {
  approvalJson: unknown
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'executed' | 'canceled'
}

export type AuditEventRow = {
  eventJson: unknown
  eventId: string
  timestamp: Date
  tenantId: string
}

export type SsrfGuardDecisionRow = {
  eventId: string
  timestamp: Date
  tenantId: string
  workloadId: string
  integrationId: string
  templateId: string
  templateVersion: number
  destinationHost: string
  destinationPort: number
  resolvedIps: string[]
  decision: 'allowed' | 'denied' | 'approval_required' | 'throttled'
  reasonCode: string
  correlationId: string
}

export type TemplateInvalidationOutboxRow = {
  tenantId: string
  templateId: string
  version: number
  updatedAtSignal: Date
  payloadJson: unknown
  status: 'pending' | 'delivered' | 'failed'
  attempts: number
  deliveredAt: Date | null
  lastError: string | null
}

export type AuditRedactionProfileRow = {
  tenantId: string
  profileId: string
  profileJson: unknown
}

export type DatabaseClient = {
  adminSignupPolicy: {
    findUnique: DbMethod<AdminSignupPolicyRow | null>
    upsert: DbMethod<AdminSignupPolicyRow>
  }
  adminIdentity: {
    create: DbMethod<AdminIdentityRowWithBindings>
    findUnique: DbMethod<AdminIdentityRowWithBindings | null>
    findMany: DbMethod<AdminIdentityRowWithBindings[]>
    count: DbMethod<number>
    update: DbMethod<AdminIdentityRowWithBindings>
  }
  adminAccessRequest: {
    create: DbMethod<AdminAccessRequestRow>
    findUnique: DbMethod<AdminAccessRequestRow | null>
    findMany: DbMethod<AdminAccessRequestRow[]>
    update: DbMethod<AdminAccessRequestRow>
    updateMany: DbMethod<{count: number}>
  }
  tenant: {
    create: DbMethod<TenantRow>
    findUnique: DbMethod<TenantRow | null>
    findMany: DbMethod<TenantRow[]>
  }
  humanUser: {
    create: DbMethod<HumanUserRowWithRoles>
    findUnique: DbMethod<HumanUserRowWithRoles | null>
    findMany: DbMethod<HumanUserRowWithRoles[]>
    update: DbMethod<HumanUserRowWithRoles>
  }
  workload: {
    create: DbMethod<WorkloadRow>
    findUnique: DbMethod<WorkloadRow | null>
    findMany: DbMethod<WorkloadRow[]>
    findFirst: DbMethod<WorkloadRow | null>
    update: DbMethod<WorkloadRow>
  }
  enrollmentToken: {
    create: DbMethod<EnrollmentTokenRow>
    findUnique: DbMethod<EnrollmentTokenRow | null>
    updateMany: DbMethod<{count: number}>
  }
  workloadSession: {
    upsert: DbMethod<WorkloadSessionRow>
    findFirst: DbMethod<WorkloadSessionRow | null>
    update: DbMethod<WorkloadSessionRow>
    deleteMany: DbMethod<{count: number}>
  }
  integration: {
    create: DbMethod<IntegrationRow>
    findFirst: DbMethod<IntegrationRow | null>
    findMany: DbMethod<IntegrationRow[]>
    update: DbMethod<IntegrationRow>
  }
  secret: {
    findUnique: DbMethod<SecretRow | null>
    create: DbMethod<SecretRow>
    update: DbMethod<SecretRow>
  }
  secretVersion: {
    findFirst: DbMethod<SecretVersionRow | null>
    create: DbMethod<SecretVersionRowWithSecret>
    findUnique: DbMethod<SecretVersionRowWithSecret | null>
    findMany: DbMethod<SecretVersionRowWithSecret[]>
  }
  manifestSigningKey: {
    findFirst: DbMethod<ManifestSigningKeyRow | null>
    findMany: DbMethod<ManifestSigningKeyRow[]>
    findUnique: DbMethod<ManifestSigningKeyRow | null>
    create: DbMethod<ManifestSigningKeyRow>
    update: DbMethod<ManifestSigningKeyRow>
  }
  manifestKeysetMetadata: {
    findUnique: DbMethod<ManifestKeysetMetadataRow | null>
    upsert: DbMethod<ManifestKeysetMetadataRow>
  }
  cryptoVerificationDefaults: {
    findUnique: DbMethod<CryptoVerificationDefaultsRow | null>
    upsert: DbMethod<CryptoVerificationDefaultsRow>
  }
  templateVersion: {
    findMany: DbMethod<TemplateVersionRow[]>
    create: DbMethod<TemplateVersionRow>
    findUnique: DbMethod<TemplateVersionRow | null>
    findFirst: DbMethod<TemplateVersionRow | null>
  }
  policyRule: {
    create: DbMethod<PolicyRuleRow>
    findUnique: DbMethod<PolicyRuleRow | null>
    update: DbMethod<PolicyRuleRow>
    findMany: DbMethod<PolicyRuleRow[]>
  }
  approvalRequest: {
    create: DbMethod<ApprovalRequestRow>
    findUnique: DbMethod<ApprovalRequestRow | null>
    findMany: DbMethod<ApprovalRequestRow[]>
    update: DbMethod<ApprovalRequestRow>
    findFirst: DbMethod<ApprovalRequestRow | null>
  }
  auditEvent: {
    create: DbMethod<AuditEventRow>
    findMany: DbMethod<AuditEventRow[]>
  }
  ssrfGuardDecision: {
    upsert: DbMethod<SsrfGuardDecisionRow>
    findUnique: DbMethod<SsrfGuardDecisionRow | null>
  }
  templateInvalidationOutbox: {
    upsert: DbMethod<TemplateInvalidationOutboxRow>
  }
  auditRedactionProfile: {
    findUnique: DbMethod<AuditRedactionProfileRow | null>
    create: DbMethod<AuditRedactionProfileRow>
    upsert: DbMethod<AuditRedactionProfileRow>
  }
  $transaction?: <T>(operation: (transactionClient: DatabaseClient) => Promise<T>) => Promise<T>
}
