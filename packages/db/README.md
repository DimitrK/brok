# @broker-interceptor/db

## Overview

`@broker-interceptor/db` is the persistence module for broker-interceptor domain data in Postgres. It provides Prisma
schema/migrations plus repository classes for:

- Tenant
- AdminSignupPolicy
- AdminIdentity
- AdminAccessRequest
- User
- Workload
- EnrollmentToken
- Session
- Integration
- Secret
- ManifestSigningKey
- ManifestKeysetMetadata
- Template
- PolicyRule
- ApprovalRequest
- AuditEvent

All DTO validation follows `packages/schemas/openapi.yaml` via `@broker-interceptor/schemas` exports.

## Code Space Boundaries

- Implementation code changes stay inside `packages/db`.
- Cross-code-space communication is done only through Markdown files under `external_feedback/...`.
- This package must not initialize its own Postgres or Redis clients. App layers own client lifecycle and pass clients
  in as dependencies.

## Public Interface

Top-level exports are defined in `packages/db/src/index.ts`.

Main composition entrypoint:

- `createDbRepositories(dbClient)` from `packages/db/src/module.ts`
- `runInTransaction(dbClient, operation, context?)` from `packages/db/src/module.ts`

Expected client shape is documented by `DatabaseClient` in `packages/db/src/types.ts`.

## Repository Surface

### TenantRepository

- `create`
- `getById`
- `list`

### AdminAuthRepository

- `getAdminSignupPolicy`
- `setAdminSignupPolicy`
- `listAdminIdentities`
- `getAdminIdentityById`
- `findAdminIdentityByIssuerSubject`
- `createAdminIdentity`
- `updateAdminIdentityStatus`
- `updateAdminIdentityBindings`
- `createAdminAccessRequest`
- `listAdminAccessRequests`
- `transitionAdminAccessRequestStatus`
- `upsertAdminRoleBindings`

### UserRepository

- `create`
- `getById`
- `listByTenant`
- `updateRoles`

### WorkloadRepository

- `create`
- `getById`
- `getBySanUri`
- `listByTenant`
- `update`
- `resolveTenantByWorkload`

### EnrollmentTokenRepository

- `issueEnrollmentToken`
- `consumeEnrollmentTokenOnce`

### SessionRepository

- `upsertSession`
- `getSessionByTokenHash`
- `revokeSessionById`
- `deleteExpiredSessions`

### IntegrationRepository

- `create`
- `getById`
- `listByTenant`
- `update`
- `bindSecret`
- `getIntegrationTemplateBindingByTenantAndId`
- `getIntegrationTemplateForPolicyEvaluation`
- `getIntegrationTemplateForExecute`
  - execute lookup now returns explicit execution gating metadata:
    - `executable` (`boolean`)
    - `execution_status` (`executable | workload_disabled | integration_disabled`)
  - supports optional `transaction_client` context pass-through

### SecretRepository

- `createSecretEnvelopeVersion`
- `getActiveSecretEnvelope`
- `getSecretEnvelopeVersion`
- `setActiveSecretEnvelopeVersion`
- `listSecretEnvelopeVersions`
- `getActiveManifestSigningKeyRecord`
- `listManifestVerificationKeysWithEtag`
- `createManifestSigningKeyRecord`
- `setActiveManifestSigningKey`
- `retireManifestSigningKey`
- `revokeManifestSigningKey`
- `transitionManifestSigningKeyStatus`
- `persistManifestKeysetMetadata`
- `getCryptoVerificationDefaultsByTenant`
- `upsertCryptoVerificationDefaults`

### TemplateRepository

- `createTemplateVersionImmutable`
- `getTemplateByIdVersion`
- `getTemplateByTenantTemplateIdVersion`
- `getLatestTemplateByTenantTemplateId`
- `listTemplateVersionsByTenantAndTemplateId`
- `listLatestTemplatesByTenant`
- `persistTemplateInvalidationOutbox`

### PolicyRuleRepository

- `createPolicyRule`
- `getPolicyRuleById`
- `disablePolicyRule`
- `listPolicyRulesForDescriptorScope`

### ApprovalRequestRepository

- `create`
- `createApprovalRequestFromCanonicalDescriptor`
- `getById`
- `list`
- `transitionApprovalStatus`
- `findOpenApprovalByCanonicalDescriptor`

### AuditEventRepository

- `appendAuditEvent`
- `appendPolicyDecisionAuditEvent`
- `appendSsrfGuardDecisionProjection`
- `queryAuditEvents`
- `getAuditRedactionProfileByTenant`
- `upsertAuditRedactionProfile`

### Redis Adapters (Auth hot path)

Factories in `packages/db/src/redis/authRedisAdapters.ts` provide Redis-backed adapters compatible with
`@broker-interceptor/auth` storage contracts:

- `createAuthRedisStores({ keyPrefix?, now?, enrollmentConsumeLockSeconds? })`
  - `sessionStore.upsertSession`
  - `sessionStore.getSessionByTokenHash`
  - `sessionStore.revokeSessionById`
  - `enrollmentTokenStore.issueEnrollmentToken`
  - `enrollmentTokenStore.consumeEnrollmentTokenByHash`
  - `replayStore.reserveDpopJti`
- `createAuthWorkloadStoreAdapter({ dbClient })`
  - `workloadStore.getWorkloadBySanUri`

Redis key prefix defaults to `broker:auth:` and can be overridden via `keyPrefix`.

### Redis Adapters (Policy engine)

Factories in `packages/db/src/redis/policyEngineRedisAdapters.ts` provide Redis-backed rate-limit enforcement:

- `createPolicyEngineRedisRateLimitStore({ keyPrefix? })`
  - `checkAndConsumePolicyRateLimit`

Redis key prefix defaults to `broker:pe:` and rate-limit keys are stored as `rl:v1:<key>`.

Factories in `packages/db/src/redis/policyEngineInvalidationRedisAdapters.ts` provide Redis-backed invalidation:

- `createPolicyEngineRedisInvalidationBus({ keyPrefix? })`
  - `publishPolicyEngineInvalidation`
  - `subscribePolicyEngineInvalidation`

Redis key prefix defaults to `broker:pe:` and invalidation is published on `invalidation:v1`.
`subscribePolicyEngineInvalidation` returns a synchronous unsubscribe callback for fail-closed bridge parity.

### Redis Adapters (Crypto)

Factories in `packages/db/src/redis/cryptoRedisAdapters.ts` provide Redis-backed manifest rotation lock coordination:

- `createCryptoRedisRotationLockAdapter({ keyPrefix? })`
  - `acquireCryptoRotationLock`
  - `releaseCryptoRotationLock`

Redis key prefix defaults to `broker:crypto:` and lock keys are stored as `rotation-lock:v1:<lock_name>`.

### Redis Adapters (Canonicalizer)

Factories in `packages/db/src/redis/canonicalizerRedisAdapters.ts` provide Redis-backed caches for canonicalizer:

- `createCanonicalizerRedisCacheStore({ keyPrefix?, templateCacheTtlSeconds? })`
  - `getTemplateCache`
  - `setTemplateCache`
  - `getApprovalOnceCache`
  - `setApprovalOnceCache`
  - `incrementRateLimitCounter`

Redis key prefix defaults to `broker:canon:` and includes:

- `template:<tenant_id>:<template_id>:<version>` for template cache
- `approval:once:<tenant_id>:<workload_id>:<integration_id>:<descriptor_hash>` for approval dedupe
- `rl:<tenant_id>:<workload_id>:<integration_id>:<action_group>:<method>:<host>` for rate limits

### Redis Adapters (Audit)

Factories in `packages/db/src/redis/auditRedisAdapters.ts` provide Redis-backed audit query cache helpers:

- `createAuditRedisCacheAdapter({ redisClient, keyPrefix?, cacheTtlSeconds?, ttlJitterSeconds?, scanCount? })`
  - `getJson`
  - `setJson`
  - `deleteByPrefix`
  - `buildAuditQueryCacheKey`
  - `getAuditQueryCachePrefixForTenant`
  - `getCachedAuditQuery`
  - `setCachedAuditQuery`
  - `getOrSetAuditQuery`
  - `invalidateAuditQueryCacheByTenant`

Audit cache keys default to:

- `audit:<tenant_id>:query:<hash>` for cached queries

Use `ttlJitterSeconds` to add cache expiration jitter and reduce stampedes.

### Redis Adapters (Forwarder)

Factories in `packages/db/src/redis/forwarderRedisAdapters.ts` provide Redis-backed idempotency and lock helpers:

- `createForwarderRedisAdapter({ keyPrefix?, now? })`
  - `acquireForwarderExecutionLock`
  - `releaseForwarderExecutionLock`
  - `createForwarderIdempotencyRecord`
  - `getForwarderIdempotencyRecord`
  - `completeForwarderIdempotencyRecord`
  - `failForwarderIdempotencyRecord`

Forwarder Redis keys default to:

- `lock:<tenant_id>:<workload_id>:<integration_id>:<action_group>:<idempotency_key>` for execution locks
- `idem:<tenant_id>:<workload_id>:<integration_id>:<action_group>:<idempotency_key>` for idempotency records

Idempotency TTLs are derived from `expires_at` and must be between 60 seconds and 24 hours. Lock TTLs are bounded to
`1000..60000` ms and require owner-token match on release.

### Redis Adapters (SSRF Guard)

Factories in `packages/db/src/redis/ssrfGuardRedisAdapters.ts` provide Redis-backed DNS cache, rebinding telemetry, and
template invalidation signaling:

- `createSsrfGuardRedisAdapter({ keyPrefix?, dnsHistoryTtlSeconds?, dnsHistoryMaxEntries? })`
  - `readDnsResolutionCache`
  - `upsertDnsResolutionCache` (atomic CAS; returns `applied | skipped_stale`)
  - `appendDnsRebindingObservation`
  - `readDnsRebindingObservationHistory`
  - `publishTemplateInvalidationSignal`
  - `subscribeTemplateInvalidationSignal`

Redis key prefix defaults to `broker:ssrf:` and uses:

- `dns:v1:<normalized_host>` for DNS cache entries
- `dns-history:v1:<normalized_host>` for rebinding history
- `invalidation:v1` channel for template invalidation fan-out

### Utilities

`packages/db/src/utils.ts` provides shared normalization/validation helpers and now exposes Zod schemas with
`z.infer`-based types for:

- trimmed/non-empty strings
- unique normalized string lists
- IP/CIDR allowlists
- normalized HTTP methods
- exact-host normalization
- base64 payload validation
- cursor pair decoding/validation

## Data Model and Migration Artifacts

- Prisma schema: `packages/db/prisma/schema.prisma`
- Migrations are intentionally cleared during early development. Generate them when the DB is ready:
  - `prisma migrate dev --name init`

## Security and Storage Rules Alignment

- Input validation is schema-driven (Zod/OpenAPI-derived DTOs).
- Repository methods reject empty identifiers and invalid enum/state transitions.
- Secret writes are transaction-guarded and require `dbClient.$transaction`.
- Cursor pagination for audit events is deterministic (`timestamp DESC, eventId DESC`).
- Execute/template reads support optional transaction-client pass-through with boundary validation.
- Canonicalizer-facing template list, approval dedupe/create, and audit append paths accept optional transaction-context pass-through for shared app-owned transaction boundaries.
- Policy-engine-facing policy/template/audit paths accept explicit `input.context.transaction_client` pass-through.
- Template by-version reads exclude inactive template versions (`status != active`).
- SSRF storage contracts include idempotent `appendSsrfGuardDecisionProjection` writes and durable
  `persistTemplateInvalidationOutbox` writes with transaction-client pass-through support.
- Audit redaction profile repository methods support optional `db_context.transaction_client` pass-through with boundary
  validation.
- Manifest-key repository read and keyset-metadata write methods support optional transaction-context pass-through and
  fail closed when metadata/keys are missing.
- Manifest lifecycle includes explicit retire/revoke wrappers and Redis rotation locks with ownership-verified release.
- Per-tenant crypto verification defaults enforce bounded skew (`0..300`) and default fail-closed values (`require_temporal_validity=true`, `max_clock_skew_seconds=0`).
- `runInTransaction` avoids nested transaction creation when a valid `transaction_client` is supplied.
- No package-level connection pooling or client lifecycle management exists in this package.

## Build, Lint, Test

From repository root:

- `pnpm --filter @broker-interceptor/db build`
- `pnpm --filter @broker-interceptor/db lint`
- `pnpm --filter @broker-interceptor/db test`
- `pnpm --filter @broker-interceptor/db test:coverage`

Dedicated utility tests live in:

- `packages/db/src/__tests__/utils.test.ts`

## Environment and Runtime Requirements

- Runtime dependency injection requires an app-managed Prisma-compatible DB client.
- `DATABASE_URL` is required by Prisma generation scripts (the package script provides a local default if unset).

## Pending Feedback

Last checked: 2026-02-20.

None awaiting external-team response.

## External Feedback Status (Processed Incoming)

Responses have been posted under `packages/db/external_feedback/broker-interceptor/*/*_response.md` for:

- `audit`
- `auth`
- `broker-api`
- `broker-admin-api`
- `canonicalizer`
- `crypto`
- `forwarder`
- `policy-engine`
- `ssrf-guard`

Forwarder contract validation was re-checked on 2026-02-13 against
`packages/forwarder/external_feedback/broker-interceptor/db/repository_injection_requirements_response.md`.

Open incoming threads currently being processed:

- none
