import {isIP} from 'node:net';

import {
  ApprovalRequestSchema,
  CanonicalRequestDescriptorSchema,
  OpenApiAdminAccessRequestListResponseSchema,
  OpenApiAdminAccessRequestSchema,
  OpenApiAdminAccessRequestStatusSchema,
  OpenApiAdminSessionPrincipalSchema,
  OpenApiAdminSignupPolicySchema,
  OpenApiAdminSignupPolicyUpdateRequestSchema,
  OpenApiAdminUserListResponseSchema,
  OpenApiAdminUserSchema,
  OpenApiAdminUserStatusSchema,
  OpenApiAdminUserUpdateRequestSchema,
  OpenApiManifestKeysSchema,
  OpenApiAuditEventSchema,
  OpenApiIntegrationSchema,
  OpenApiIntegrationUpdateRequestSchema,
  OpenApiIntegrationWriteSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateSchema,
  OpenApiTenantCreateRequestSchema,
  OpenApiTenantSummarySchema,
  OpenApiWorkloadCreateRequestSchema,
  OpenApiWorkloadSchema,
  OpenApiWorkloadUpdateRequestSchema,
  PolicyConstraintsSchema,
  SecretMaterialSchema
} from '@broker-interceptor/schemas';
import {z} from 'zod';

export const UserRoleSchema = z.enum(['owner', 'admin', 'auditor', 'operator']);
export type UserRole = z.infer<typeof UserRoleSchema>;

export const HumanUserSchema = z
  .object({
    user_id: z.string().min(1),
    tenant_id: z.string().min(1),
    email: z.string().email(),
    roles: z.array(UserRoleSchema).min(1),
    enabled: z.boolean(),
    display_name: z.string().min(1).optional(),
    oidc_subject: z.string().min(1).optional(),
    oidc_issuer: z.string().min(1).optional(),
    created_at: z.iso.datetime({offset: true})
  })
  .strict();
export type HumanUser = z.infer<typeof HumanUserSchema>;

export const CreateHumanUserInputSchema = z
  .object({
    user_id: z.string().min(1).optional(),
    tenant_id: z.string().min(1),
    email: z.string().email(),
    roles: z.array(UserRoleSchema).min(1),
    enabled: z.boolean().optional(),
    display_name: z.string().min(1).optional(),
    oidc_subject: z.string().min(1).optional(),
    oidc_issuer: z.string().min(1).optional()
  })
  .strict();
export type CreateHumanUserInput = z.infer<typeof CreateHumanUserInputSchema>;

export const UpdateHumanUserRolesInputSchema = z
  .object({
    user_id: z.string().min(1),
    roles: z.array(UserRoleSchema).min(1)
  })
  .strict();
export type UpdateHumanUserRolesInput = z.infer<typeof UpdateHumanUserRolesInputSchema>;

export const AdminSignupPolicySchema = OpenApiAdminSignupPolicySchema;
export type AdminSignupPolicy = z.infer<typeof AdminSignupPolicySchema>;

export const SetAdminSignupPolicyInputSchema = z
  .object({
    policy: OpenApiAdminSignupPolicyUpdateRequestSchema,
    actor: z.string().min(1),
    updated_at: z.iso.datetime({offset: true}).optional()
  })
  .strict();
export type SetAdminSignupPolicyInput = z.infer<typeof SetAdminSignupPolicyInputSchema>;

export const AdminIdentityStatusSchema = OpenApiAdminUserStatusSchema;
export type AdminIdentityStatus = z.infer<typeof AdminIdentityStatusSchema>;

export const AdminIdentitySchema = OpenApiAdminUserSchema;
export type AdminIdentity = z.infer<typeof AdminIdentitySchema>;

export const AdminIdentityListResponseSchema = OpenApiAdminUserListResponseSchema;
export type AdminIdentityListResponse = z.infer<typeof AdminIdentityListResponseSchema>;

export const FindAdminIdentityByIssuerSubjectInputSchema = z
  .object({
    issuer: OpenApiAdminSessionPrincipalSchema.shape.issuer,
    subject: OpenApiAdminSessionPrincipalSchema.shape.subject
  })
  .strict();
export type FindAdminIdentityByIssuerSubjectInput = z.infer<typeof FindAdminIdentityByIssuerSubjectInputSchema>;

export const CreateAdminIdentityInputSchema = z
  .object({
    identity_id: z.string().min(1).optional(),
    principal: OpenApiAdminSessionPrincipalSchema,
    status: AdminIdentityStatusSchema.optional()
  })
  .strict();
export type CreateAdminIdentityInput = z.infer<typeof CreateAdminIdentityInputSchema>;

export const GetAdminIdentityByIdInputSchema = z
  .object({
    identity_id: z.string().min(1)
  })
  .strict();
export type GetAdminIdentityByIdInput = z.infer<typeof GetAdminIdentityByIdInputSchema>;

const AdminQuerySearchSchema = z
  .string()
  .transform(value => value.trim())
  .pipe(z.string().min(1));

export const ListAdminIdentitiesInputSchema = z
  .object({
    status: AdminIdentityStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: UserRoleSchema.optional(),
    search: AdminQuerySearchSchema.optional(),
    limit: z.number().int().gte(1).lte(100).default(50),
    cursor: z.string().min(1).optional()
  })
  .strict();
export type ListAdminIdentitiesInput = z.infer<typeof ListAdminIdentitiesInputSchema>;

export const UpdateAdminIdentityStatusInputSchema = z
  .object({
    identity_id: z.string().min(1),
    status: AdminIdentityStatusSchema
  })
  .strict();
export type UpdateAdminIdentityStatusInput = z.infer<typeof UpdateAdminIdentityStatusInputSchema>;

const AdminIdentityBindingsPatchSchema = OpenApiAdminUserUpdateRequestSchema.pick({
  roles: true,
  tenant_ids: true
}).refine(
  value => value.roles !== undefined || value.tenant_ids !== undefined,
  'At least one of roles or tenant_ids must be provided'
);

export const UpdateAdminIdentityBindingsInputSchema = z
  .object({
    identity_id: z.string().min(1),
    patch: AdminIdentityBindingsPatchSchema
  })
  .strict();
export type UpdateAdminIdentityBindingsInput = z.infer<typeof UpdateAdminIdentityBindingsInputSchema>;

export const AdminAccessRequestStatusSchema = OpenApiAdminAccessRequestStatusSchema;
export type AdminAccessRequestStatus = z.infer<typeof AdminAccessRequestStatusSchema>;

export const AdminAccessRequestSchema = OpenApiAdminAccessRequestSchema;
export type AdminAccessRequest = z.infer<typeof AdminAccessRequestSchema>;

export const AdminAccessRequestListResponseSchema = OpenApiAdminAccessRequestListResponseSchema;
export type AdminAccessRequestListResponse = z.infer<typeof AdminAccessRequestListResponseSchema>;

export const CreateAdminAccessRequestInputSchema = z
  .object({
    request_id: z.string().min(1).optional(),
    principal: OpenApiAdminSessionPrincipalSchema,
    reason: z.string().min(1).optional()
  })
  .strict();
export type CreateAdminAccessRequestInput = z.infer<typeof CreateAdminAccessRequestInputSchema>;

export const TransitionAdminAccessRequestStatusInputSchema = z
  .object({
    request_id: z.string().min(1),
    status: z.enum(['approved', 'denied', 'canceled']),
    actor: z.string().min(1),
    reason: z.string().min(1).optional(),
    decided_at: z.iso.datetime({offset: true}).optional()
  })
  .strict();
export type TransitionAdminAccessRequestStatusInput = z.infer<typeof TransitionAdminAccessRequestStatusInputSchema>;

export const ListAdminAccessRequestsInputSchema = z
  .object({
    status: AdminAccessRequestStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: UserRoleSchema.optional(),
    search: AdminQuerySearchSchema.optional(),
    limit: z.number().int().gte(1).lte(100).default(50),
    cursor: z.string().min(1).optional()
  })
  .strict();
export type ListAdminAccessRequestsInput = z.infer<typeof ListAdminAccessRequestsInputSchema>;

export const UpsertAdminRoleBindingsInputSchema = z
  .object({
    issuer: OpenApiAdminSessionPrincipalSchema.shape.issuer,
    subject: OpenApiAdminSessionPrincipalSchema.shape.subject,
    roles: z.array(UserRoleSchema).min(1),
    tenant_ids: z.array(z.string().min(1)).optional()
  })
  .strict();
export type UpsertAdminRoleBindingsInput = z.infer<typeof UpsertAdminRoleBindingsInputSchema>;

export const SessionRecordSchema = z
  .object({
    sessionId: z.string().uuid(),
    workloadId: z.string().min(1),
    tenantId: z.string().min(1),
    certFingerprint256: z.string().min(1),
    tokenHash: z.string().regex(/^[a-f0-9]{64}$/u),
    expiresAt: z.iso.datetime({offset: true}),
    dpopKeyThumbprint: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/u)
      .optional(),
    scopes: z.array(z.string()).optional()
  })
  .strict();
export type SessionRecord = z.infer<typeof SessionRecordSchema>;

export const SessionLookupInputSchema = z
  .object({
    token_hash: z.string().regex(/^[a-f0-9]{64}$/u)
  })
  .strict();
export type SessionLookupInput = z.infer<typeof SessionLookupInputSchema>;

export const EnrollmentTokenRecordSchema = z
  .object({
    token_hash: z.string().regex(/^[a-f0-9]{64}$/u),
    workload_id: z.string().min(1),
    tenant_id: z.string().min(1),
    expires_at: z.iso.datetime({offset: true}),
    used_at: z.iso.datetime({offset: true}).optional(),
    created_at: z.iso.datetime({offset: true})
  })
  .strict();
export type EnrollmentTokenRecord = z.infer<typeof EnrollmentTokenRecordSchema>;

export const IssueEnrollmentTokenInputSchema = z
  .object({
    token_hash: z.string().regex(/^[a-f0-9]{64}$/u),
    workload_id: z.string().min(1),
    tenant_id: z.string().min(1),
    expires_at: z.iso.datetime({offset: true}),
    created_at: z.iso.datetime({offset: true}).optional()
  })
  .strict();
export type IssueEnrollmentTokenInput = z.infer<typeof IssueEnrollmentTokenInputSchema>;

export const ConsumeEnrollmentTokenInputSchema = z
  .object({
    token_hash: z.string().regex(/^[a-f0-9]{64}$/u),
    workload_id: z.string().min(1).optional(),
    now: z.iso.datetime({offset: true})
  })
  .strict();
export type ConsumeEnrollmentTokenInput = z.infer<typeof ConsumeEnrollmentTokenInputSchema>;

export const SecretEnvelopeSchema = z
  .object({
    key_id: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9._:-]+$/u),
    content_encryption_alg: z.literal('A256GCM'),
    key_encryption_alg: z.string().min(1),
    wrapped_data_key_b64: z.string().min(1),
    iv_b64: z.string().min(1),
    ciphertext_b64: z.string().min(1),
    auth_tag_b64: z.string().min(1),
    aad_b64: z.string().min(1).optional()
  })
  .strict();
export type SecretEnvelope = z.infer<typeof SecretEnvelopeSchema>;

export const CreateSecretEnvelopeVersionInputSchema = z
  .object({
    secret_ref: z.string().min(1),
    tenant_id: z.string().min(1),
    integration_id: z.string().min(1),
    secret_type: SecretMaterialSchema.shape.type,
    envelope: SecretEnvelopeSchema,
    created_at: z.iso.datetime({offset: true}).optional()
  })
  .strict();
export type CreateSecretEnvelopeVersionInput = z.infer<typeof CreateSecretEnvelopeVersionInputSchema>;

export const GetSecretEnvelopeInputSchema = z
  .object({
    secret_ref: z.string().min(1),
    version: z.number().int().gte(1).optional()
  })
  .strict();
export type GetSecretEnvelopeInput = z.infer<typeof GetSecretEnvelopeInputSchema>;

export const SetActiveSecretEnvelopeVersionInputSchema = z
  .object({
    secret_ref: z.string().min(1),
    version: z.number().int().gte(1)
  })
  .strict();
export type SetActiveSecretEnvelopeVersionInput = z.infer<typeof SetActiveSecretEnvelopeVersionInputSchema>;

export const SecretEnvelopeVersionSchema = z
  .object({
    secret_ref: z.string().min(1),
    tenant_id: z.string().min(1),
    integration_id: z.string().min(1),
    secret_type: SecretMaterialSchema.shape.type,
    version: z.number().int().gte(1),
    envelope: SecretEnvelopeSchema,
    created_at: z.iso.datetime({offset: true})
  })
  .strict();
export type SecretEnvelopeVersion = z.infer<typeof SecretEnvelopeVersionSchema>;

export const ManifestSigningAlgorithmSchema = z.enum(['EdDSA', 'ES256']);
export type ManifestSigningAlgorithm = z.infer<typeof ManifestSigningAlgorithmSchema>;

const ManifestVerificationKeySchema = z.unknown().transform((value, context) => {
  const parsed = OpenApiManifestKeysSchema.safeParse({
    keys: [value]
  });

  if (!parsed.success) {
    context.addIssue({
      code: 'custom',
      message: 'Invalid manifest verification key'
    });
    return z.NEVER;
  }

  return parsed.data.keys[0];
});

export const CreateManifestSigningKeyRecordInputSchema = z
  .object({
    kid: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9._:-]+$/u),
    alg: ManifestSigningAlgorithmSchema,
    public_jwk: ManifestVerificationKeySchema,
    private_key_ref: z.string().min(1),
    created_at: z.iso.datetime({offset: true})
  })
  .strict();
export type CreateManifestSigningKeyRecordInput = z.infer<typeof CreateManifestSigningKeyRecordInputSchema>;

export const ManifestSigningKeyRecordSchema = z
  .object({
    kid: z.string().min(1),
    alg: ManifestSigningAlgorithmSchema,
    public_jwk: ManifestVerificationKeySchema,
    private_key_ref: z.string().min(1),
    status: z.enum(['active', 'retired', 'revoked']),
    created_at: z.iso.datetime({offset: true}),
    activated_at: z.iso.datetime({offset: true}).optional(),
    retired_at: z.iso.datetime({offset: true}).optional(),
    revoked_at: z.iso.datetime({offset: true}).optional()
  })
  .strict();
export type ManifestSigningKeyRecord = z.infer<typeof ManifestSigningKeyRecordSchema>;

export const ManifestSigningKeyStatusSchema = z.enum(['active', 'retired', 'revoked']);
export type ManifestSigningKeyStatus = z.infer<typeof ManifestSigningKeyStatusSchema>;

export const SetActiveManifestSigningKeyInputSchema = z
  .object({
    kid: z.string().min(1),
    activated_at: z.iso.datetime({offset: true})
  })
  .strict();
export type SetActiveManifestSigningKeyInput = z.infer<typeof SetActiveManifestSigningKeyInputSchema>;

export const RetireManifestSigningKeyInputSchema = z
  .object({
    kid: z.string().min(1),
    retired_at: z.iso.datetime({offset: true})
  })
  .strict();
export type RetireManifestSigningKeyInput = z.infer<typeof RetireManifestSigningKeyInputSchema>;

export const RevokeManifestSigningKeyInputSchema = z
  .object({
    kid: z.string().min(1),
    revoked_at: z.iso.datetime({offset: true})
  })
  .strict();
export type RevokeManifestSigningKeyInput = z.infer<typeof RevokeManifestSigningKeyInputSchema>;

export const TransitionManifestSigningKeyStatusInputSchema = z
  .object({
    kid: z.string().min(1),
    status: z.enum(['retired', 'revoked']),
    at: z.iso.datetime({offset: true})
  })
  .strict();
export type TransitionManifestSigningKeyStatusInput = z.infer<
  typeof TransitionManifestSigningKeyStatusInputSchema
>;

export const PersistManifestKeysetMetadataInputSchema = z
  .object({
    etag: z.string().regex(/^W\/".+"$/u),
    generated_at: z.iso.datetime({offset: true}),
    max_age_seconds: z.number().int().gte(30).lte(300)
  })
  .strict();
export type PersistManifestKeysetMetadataInput = z.infer<typeof PersistManifestKeysetMetadataInputSchema>;

export const ManifestVerificationKeysetWithEtagSchema = z
  .object({
    manifest_keys: OpenApiManifestKeysSchema,
    etag: PersistManifestKeysetMetadataInputSchema.shape.etag,
    generated_at: z.iso.datetime({offset: true}),
    max_age_seconds: PersistManifestKeysetMetadataInputSchema.shape.max_age_seconds
  })
  .strict();
export type ManifestVerificationKeysetWithEtag = z.infer<typeof ManifestVerificationKeysetWithEtagSchema>;

export const CryptoVerificationDefaultsSchema = z
  .object({
    tenant_id: z.string().min(1),
    require_temporal_validity: z.boolean().default(true),
    max_clock_skew_seconds: z.number().int().gte(0).lte(300).default(0)
  })
  .strict();
export type CryptoVerificationDefaults = z.infer<typeof CryptoVerificationDefaultsSchema>;

export const GetCryptoVerificationDefaultsByTenantInputSchema = z
  .object({
    tenant_id: z.string().min(1)
  })
  .strict();
export type GetCryptoVerificationDefaultsByTenantInput = z.infer<
  typeof GetCryptoVerificationDefaultsByTenantInputSchema
>;

export const UpsertCryptoVerificationDefaultsInputSchema = z
  .object({
    tenant_id: z.string().min(1),
    require_temporal_validity: z.boolean(),
    max_clock_skew_seconds: z.number().int().gte(0).lte(300)
  })
  .strict();
export type UpsertCryptoVerificationDefaultsInput = z.infer<typeof UpsertCryptoVerificationDefaultsInputSchema>;

export const ApprovalDecisionModeSchema = z.enum(['once', 'rule']);
export type ApprovalDecisionMode = z.infer<typeof ApprovalDecisionModeSchema>;

export const ApprovalStatusSchema = ApprovalRequestSchema.shape.status;
export type ApprovalStatus = z.infer<typeof ApprovalStatusSchema>;

export const ApprovalTransitionInputSchema = z
  .object({
    approval_id: z.string().min(1),
    status: ApprovalStatusSchema,
    decided_at: z.iso.datetime({offset: true}).optional()
  })
  .strict();
export type ApprovalTransitionInput = z.infer<typeof ApprovalTransitionInputSchema>;

export const PolicyInvalidationEventSchema = z
  .object({
    tenant_id: z.string().min(1),
    entity_type: z.enum(['policy_rule', 'template_binding', 'template_version']),
    entity_id: z.string().min(1),
    updated_at: z.iso.datetime({offset: true})
  })
  .strict();
export type PolicyInvalidationEvent = z.infer<typeof PolicyInvalidationEventSchema>;

export const AuditQueryFilterSchema = z
  .object({
    time_min: z.iso.datetime({offset: true}).optional(),
    time_max: z.iso.datetime({offset: true}).optional(),
    tenant_id: z.string().min(1).optional(),
    workload_id: z.string().min(1).optional(),
    integration_id: z.string().min(1).optional(),
    action_group: z.string().min(1).optional(),
    decision: z.enum(['allowed', 'denied', 'approval_required', 'throttled']).optional(),
    limit: z.number().int().gte(1).lte(200).optional(),
    cursor: z.string().min(1).optional()
  })
  .strict();
export type AuditQueryFilter = z.infer<typeof AuditQueryFilterSchema>;

export const SsrfGuardErrorCodeSchema = z.enum([
  'invalid_input',
  'request_url_invalid',
  'request_url_userinfo_forbidden',
  'request_url_fragment_forbidden',
  'request_scheme_not_allowed',
  'request_host_not_allowed',
  'request_port_not_allowed',
  'request_ip_literal_forbidden',
  'template_host_invalid',
  'dns_resolution_required',
  'dns_resolution_failed',
  'dns_resolution_empty',
  'resolved_ip_invalid',
  'resolved_ip_denied_private_range',
  'resolved_ip_denied_loopback',
  'resolved_ip_denied_link_local',
  'resolved_ip_denied_metadata_range',
  'redirect_denied'
]);
export type SsrfGuardErrorCode = z.infer<typeof SsrfGuardErrorCodeSchema>;

const SsrfGuardIpLiteralSchema = z.string().trim().refine(value => isIP(value) > 0, {
  message: 'Invalid IP literal'
});

export const SsrfGuardDecisionProjectionSchema = z
  .object({
    event_id: z.string().min(1),
    timestamp: z.iso.datetime({offset: true}),
    tenant_id: z.string().min(1),
    workload_id: z.string().min(1),
    integration_id: z.string().min(1),
    template_id: z.string().min(1),
    template_version: z.number().int().gte(1),
    destination_host: z.string().min(1),
    destination_port: z.number().int().min(1).max(65_535),
    resolved_ips: z.array(SsrfGuardIpLiteralSchema).min(1).max(32),
    decision: z.enum(['allowed', 'denied']),
    reason_code: SsrfGuardErrorCodeSchema,
    correlation_id: z.string().min(1)
  })
  .strict();
export type SsrfGuardDecisionProjection = z.infer<typeof SsrfGuardDecisionProjectionSchema>;

export const AppendSsrfGuardDecisionProjectionInputSchema = z
  .object({
    projection: SsrfGuardDecisionProjectionSchema
  })
  .strict();
export type AppendSsrfGuardDecisionProjectionInput = z.infer<typeof AppendSsrfGuardDecisionProjectionInputSchema>;

export const TemplateInvalidationSignalSchema = z
  .object({
    template_id: z.string().min(1),
    version: z.number().int().gte(1),
    tenant_id: z.string().min(1),
    updated_at: z.iso.datetime({offset: true})
  })
  .strict();
export type TemplateInvalidationSignal = z.infer<typeof TemplateInvalidationSignalSchema>;

export const PersistTemplateInvalidationOutboxInputSchema = z
  .object({
    signal: TemplateInvalidationSignalSchema
  })
  .strict();
export type PersistTemplateInvalidationOutboxInput = z.infer<typeof PersistTemplateInvalidationOutboxInputSchema>;

export const RedactionActionSchema = z.enum(['keep', 'mask', 'hash', 'drop']);
export type RedactionAction = z.infer<typeof RedactionActionSchema>;

const RedactionRegexPatternSchema = z
  .string()
  .min(1)
  .refine(pattern => {
    try {
      // eslint-disable-next-line security/detect-non-literal-regexp -- Pattern is validated at runtime and constrained to redaction rule matching.
      new RegExp(pattern, 'iu');
      return true;
    } catch {
      return false;
    }
  }, 'Invalid regex pattern');

export const AuditRedactionRulesSchema = z
  .object({
    message_action: RedactionActionSchema,
    metadata_default_action: RedactionActionSchema,
    metadata_key_actions: z.record(z.string(), RedactionActionSchema),
    metadata_allow_keys: z.array(z.string()),
    sensitive_key_patterns: z.array(RedactionRegexPatternSchema).min(1),
    canonical_header_value_action: RedactionActionSchema,
    policy_identifier_action: RedactionActionSchema,
    max_depth: z.number().int().gte(1).lte(8),
    max_collection_size: z.number().int().gte(1).lte(500),
    max_string_length: z.number().int().gte(64).lte(4096),
    hash_salt: z.string().optional()
  })
  .strict();
export type AuditRedactionRules = z.infer<typeof AuditRedactionRulesSchema>;

export const AuditRedactionProfileSchema = z
  .object({
    tenant_id: z.string().min(1),
    profile_id: z.string().min(1),
    rules: AuditRedactionRulesSchema
  })
  .strict();
export type AuditRedactionProfile = z.infer<typeof AuditRedactionProfileSchema>;

export const GetAuditRedactionProfileByTenantInputSchema = z
  .object({
    tenant_id: z.string().min(1)
  })
  .strict();
export type GetAuditRedactionProfileByTenantInput = z.infer<typeof GetAuditRedactionProfileByTenantInputSchema>;

export const UpsertAuditRedactionProfileInputSchema = z
  .object({
    profile: AuditRedactionProfileSchema
  })
  .strict();
export type UpsertAuditRedactionProfileInput = z.infer<typeof UpsertAuditRedactionProfileInputSchema>;

export type TenantCreateRequest = z.infer<typeof OpenApiTenantCreateRequestSchema>;
export type TenantSummary = z.infer<typeof OpenApiTenantSummarySchema>;
export type WorkloadCreateRequest = z.infer<typeof OpenApiWorkloadCreateRequestSchema>;
export type WorkloadUpdateRequest = z.infer<typeof OpenApiWorkloadUpdateRequestSchema>;
export type Workload = z.infer<typeof OpenApiWorkloadSchema>;
export type IntegrationWrite = z.infer<typeof OpenApiIntegrationWriteSchema>;
export type IntegrationUpdateRequest = z.infer<typeof OpenApiIntegrationUpdateRequestSchema>;
export type Integration = z.infer<typeof OpenApiIntegrationSchema>;
export type Template = z.infer<typeof OpenApiTemplateSchema>;
export type PolicyRule = z.infer<typeof OpenApiPolicyRuleSchema>;
export type PolicyConstraints = z.infer<typeof PolicyConstraintsSchema>;
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;
export type AuditEvent = z.infer<typeof OpenApiAuditEventSchema>;
export type CanonicalRequestDescriptor = z.infer<typeof CanonicalRequestDescriptorSchema>;
export type ManifestKeys = z.infer<typeof OpenApiManifestKeysSchema>;

export {
  ApprovalRequestSchema,
  CanonicalRequestDescriptorSchema,
  OpenApiAuditEventSchema,
  OpenApiIntegrationSchema,
  OpenApiIntegrationUpdateRequestSchema,
  OpenApiIntegrationWriteSchema,
  OpenApiManifestKeysSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateSchema,
  OpenApiTenantCreateRequestSchema,
  OpenApiTenantSummarySchema,
  OpenApiWorkloadCreateRequestSchema,
  OpenApiWorkloadSchema,
  OpenApiWorkloadUpdateRequestSchema,
  PolicyConstraintsSchema,
  SecretMaterialSchema
};
