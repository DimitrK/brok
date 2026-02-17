# External Feedback Tracker (`broker-api`)

Last reviewed: 2026-02-13 (auth API rename migrated; SSRF bridge moved to db-native projection/outbox hooks)
Owner: `apps/broker-api`

## Purpose
Track every `_INCOMPLETE` dependency method request issued by `broker-api`, and make it easy to revisit package-team
responses when they arrive.

## Tracking Rules
- Source of truth request file: `missing_methods.md`
- Expected response file per package: `missing_methods_reply.md` or `missing_methods_response.md` (same folder)
- `Status` values:
  - `pending`: no reply file yet
  - `reply_received`: reply file exists and needs review/reconciliation
  - `closed`: response reviewed and integration work completed in `broker-api`

## Requests

### `packages/audit`
- Request file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/external_feedback/broker-interceptor/broker-api/missing_methods.md`
- Reply file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
- Status: `reply_received`
- Reply last seen:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
- Review note:
  - Reply reviewed. Methods are present but intentionally `_INCOMPLETE` pending `@broker-interceptor/db` adapters.
  - Keep as `reply_received` until concrete store integrations are wired.
- Requested `_INCOMPLETE` methods:
  - `appendAuditEventInPostgres_INCOMPLETE`
  - `queryAuditEventsFromPostgres_INCOMPLETE`
  - `getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE`
  - `readAuditQueryCacheFromRedis_INCOMPLETE`
  - `writeAuditQueryCacheToRedis_INCOMPLETE`
  - `invalidateAuditQueryCacheByTenantFromRedis_INCOMPLETE`
  - `createPersistentAuditStore_INCOMPLETE`
  - `createAuditRedactionProfileResolverFromDb_INCOMPLETE`

### `packages/auth`
- Request file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/auth/external_feedback/broker-interceptor/broker-api/missing_methods.md`
- Reply file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/auth/external_feedback/broker-interceptor/broker-api/missing_methods_reply.md`
- Status: `reply_received`
- Reply last seen:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/auth/external_feedback/broker-interceptor/broker-api/missing_methods_reply.md`
- Review note:
  - Reply reviewed. Broker-api now wires auth storage scope with app-owned clients/repositories for active data-plane paths:
    `persistSessionRecord_INCOMPLETE`, `getSessionRecordByTokenHash_INCOMPLETE`,
    `createDpopReplayJtiStore_INCOMPLETE` (+ workload adapter wiring for `loadWorkloadRecordBySanUri_INCOMPLETE`).
  - Keep as `reply_received` until enrollment token storage methods are needed by broker-api runtime.
- Requested `_INCOMPLETE` methods:
  - `createDpopReplayJtiStore_INCOMPLETE`
  - `persistSessionRecord_INCOMPLETE`
  - `getSessionRecordByTokenHash_INCOMPLETE`
  - `loadWorkloadRecordBySanUri_INCOMPLETE`
  - `issueEnrollmentTokenRecord_INCOMPLETE`
  - `consumeEnrollmentTokenRecordByHash_INCOMPLETE`

### `packages/crypto`
- Request file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/external_feedback/broker-interceptor/broker-api/missing_methods.md`
- Reply file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/external_feedback/broker-interceptor/broker-api/missing_methods_reply.md`
- Status: `closed`
- Reply last seen:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/crypto/external_feedback/broker-interceptor/broker-api/missing_methods_reply.md`
- Review note:
  - Reply reviewed and fully integrated in broker-api via `createCryptoStorageService_INCOMPLETE` with app-owned
    DB/Redis dependencies and shared transaction context propagation.
  - Closed by broker-api wiring for `private_key_ref`-based private signing key resolution and
    `rotateManifestSigningKeysWithStore_INCOMPLETE` orchestration (rotation lock + transactional state updates).
- Requested `_INCOMPLETE` methods:
  - `createManifestSigningKeyRecord_INCOMPLETE`
  - `getActiveManifestSigningKeyRecord_INCOMPLETE`
  - `setActiveManifestSigningKey_INCOMPLETE`
  - `listManifestVerificationKeysWithEtag_INCOMPLETE`
  - `persistManifestKeysetMetadata_INCOMPLETE`
  - `acquireCryptoRotationLock_INCOMPLETE`
  - `releaseCryptoRotationLock_INCOMPLETE`
  - `rotateManifestSigningKeysWithStore_INCOMPLETE`
  - `createSecretEnvelopeVersion_INCOMPLETE`
  - `getActiveSecretEnvelope_INCOMPLETE`
  - `getSecretEnvelopeVersion_INCOMPLETE`
  - `setActiveSecretEnvelopeVersion_INCOMPLETE`

### `packages/forwarder`
- Request file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/forwarder/external_feedback/broker-interceptor/broker-api/missing_methods.md`
- Reply file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/forwarder/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
- Status: `reply_received`
- Reply last seen:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/forwarder/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
- Review note:
  - Reply reviewed. Bridge contracts are now wired in broker-api runtime for lock + idempotency execution paths:
    `acquire/release/create/get/complete/fail`.
  - Keep as `reply_received` for deferred forwarder persistence methods (host cooldown/circuit/inflight/snapshot paths).
  - 2026-02-13 follow-up: db-side implementations for deferred methods requested in
    `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/external_feedback/broker-interceptor/broker-api/missing_methods.md`.
- Requested `_INCOMPLETE` methods:
  - `listRequiredDependencies_INCOMPLETE`
  - `acquireForwarderExecutionLock_INCOMPLETE`
  - `releaseForwarderExecutionLock_INCOMPLETE`
  - `createForwarderIdempotencyRecord_INCOMPLETE`
  - `getForwarderIdempotencyRecord_INCOMPLETE`
  - `completeForwarderIdempotencyRecord_INCOMPLETE`
  - `failForwarderIdempotencyRecord_INCOMPLETE`
  - `incrementForwarderHostFailureCounter_INCOMPLETE`
  - `getForwarderHostCircuitState_INCOMPLETE`
  - `createForwarderInflightExecutionMarker_INCOMPLETE`
  - `deleteForwarderInflightExecutionMarker_INCOMPLETE`
  - `setForwarderHostCooldownState_INCOMPLETE`
  - `getForwarderHostCooldownState_INCOMPLETE`
  - `insertForwarderIdempotencyConflict_INCOMPLETE`
  - `insertForwarderExecutionSnapshot_INCOMPLETE`
  - `queryForwarderExecutionSnapshots_INCOMPLETE`

### `packages/policy-engine`
- Request file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/policy-engine/external_feedback/broker-interceptor/broker-api/missing_methods.md`
- Reply file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/policy-engine/external_feedback/broker-interceptor/broker-api/missing_methods_reply.md`
- Status: `reply_received`
- Reply last seen:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/policy-engine/external_feedback/broker-interceptor/broker-api/missing_methods_reply.md`
- Review note:
  - Reply reviewed. Bridge methods exist as `_INCOMPLETE` placeholders with fail-closed semantics.
  - Keep as `reply_received` until `@broker-interceptor/db` provides concrete backing repositories.
- Requested `_INCOMPLETE` methods:
  - `listPolicyRulesForDescriptorScope_INCOMPLETE`
  - `getIntegrationTemplateForPolicyEvaluation_INCOMPLETE`
  - `checkAndConsumePolicyRateLimit_INCOMPLETE`
  - `appendPolicyDecisionAuditEvent_INCOMPLETE`
  - `publishPolicyEngineInvalidation_INCOMPLETE`
  - `subscribePolicyEngineInvalidation_INCOMPLETE`

### `packages/ssrf-guard`
- Request file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/ssrf-guard/external_feedback/broker-interceptor/broker-api/missing_methods.md`
- Reply file:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/ssrf-guard/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
- Status: `reply_received`
- Reply last seen:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/ssrf-guard/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
- Review note:
  - Reply reviewed. Broker-api now wires the bridge in runtime and repository with db-native template loading:
    `getIntegrationTemplateForExecute`,
    `readDnsResolutionCache`,
    `upsertDnsResolutionCache`,
    `appendDnsRebindingObservation`,
    `appendSsrfGuardDecisionProjection`,
    `persistTemplateInvalidationOutbox`,
    `publishTemplateInvalidationSignal`.
  - Local wrapper duplication for template load mapping has been removed from broker-api;
    `SsrfGuardStorageBridge` now handles executable/not_found semantics via native db repository contract.
  - Keep as `reply_received` until `@broker-interceptor/db` ships dedicated CAS DNS contracts for shared redis adapter parity.
- Requested `_INCOMPLETE` methods:
  - `listRequiredDependencies_INCOMPLETE`
  - `loadActiveTemplateForExecuteFromDb_INCOMPLETE`
  - `persistActiveTemplateForExecuteInDbMock_INCOMPLETE`
  - `readDnsResolutionCacheFromRedis_INCOMPLETE`
  - `writeDnsResolutionCacheToRedisMock_INCOMPLETE`
  - `appendDnsRebindingObservationToRedisMock_INCOMPLETE`
  - `appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE`
  - `publishTemplateInvalidationSignalToRedisMock_INCOMPLETE`

## Quick Check
- Run:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/scripts/check-external-feedback.sh`

## Notes
- `@broker-interceptor/db` persistent-store method details are intentionally out of scope in this tracker phase,
  except for explicitly tracked blocking asks under:
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/external_feedback/broker-interceptor/broker-api/missing_methods.md`.
