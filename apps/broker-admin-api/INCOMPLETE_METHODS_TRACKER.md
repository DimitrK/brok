# Incomplete Methods Tracker (`broker-admin-api`)

Purpose: keep a single ledger of all `_INCOMPLETE` local methods and all upstream methods previously requested via
`external_feedback`, so responses can be revisited and wired quickly.

Last reviewed: 2026-02-14 (OAuth admin-auth wiring validated; no new blockers)

## Local `_INCOMPLETE` Methods (Current)

| Local Method                                            | File                                            | Dependency Owner                                        | Upstream Requirement                                    | Status | Next Revisit Trigger                            |
| ------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------- | ------ | ----------------------------------------------- |
| `ensureEnrollmentModeSupported_INCOMPLETE`              | `apps/broker-admin-api/src/dependencyBridge.ts` | `@broker-interceptor/auth` + external CA provider       | External CA runtime provider wiring (`issueEnrollment`) | Open   | External CA provider implementation/reply lands |
| `persistManifestKeyRotationWithDbPackage_INCOMPLETE`    | `apps/broker-admin-api/src/dependencyBridge.ts` | `@broker-interceptor/db`                                | Manifest key rotation persistence contract              | Wired  | Update method name when stable                  |
| `rotateManifestSigningKeysWithCryptoPackage_INCOMPLETE` | `apps/broker-admin-api/src/dependencyBridge.ts` | `@broker-interceptor/crypto` + `@broker-interceptor/db` | Crypto rotation + DB persistence are now wired          | Wired  | Update method name when stable                  |

## Infrastructure Readiness

- Process-scoped Prisma/Redis initialization is wired in `apps/broker-admin-api/src/infrastructure.ts`.
- Infrastructure dependencies are passed through `apps/broker-admin-api/src/app.ts` into:
- `ControlPlaneRepository` (`processInfrastructure`)
- `DependencyBridge` (`processInfrastructure`)
- Core db persistence now includes enrollment token durability and manifest key rotation writes.

## Upstream Method Request Ledger (History)

| Requested Upstream Method                                                       | Request File                                                                                      | Reply File                                                                                              | Current Integration Status                                                                                                  |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `@broker-interceptor/auth/issueExternalCaEnrollment_INCOMPLETE`                 | `packages/auth/external_feedback/broker-interceptor/broker-admin-api/missing_methods.md`          | `packages/auth/external_feedback/broker-interceptor/broker-admin-api/missing_methods_reply.md`          | Package method delivered and wired; local runtime provider wiring still open via `ensureEnrollmentModeSupported_INCOMPLETE` |
| `@broker-interceptor/policy-engine/validatePolicyRule_INCOMPLETE`               | `packages/policy-engine/external_feedback/broker-interceptor/broker-admin-api/missing_methods.md` | `packages/policy-engine/external_feedback/broker-interceptor/broker-admin-api/missing_methods_reply.md` | Delivered and wired (`validatePolicyRuleWithPolicyEngine`)                                                                  |
| `@broker-interceptor/policy-engine/derivePolicyFromApprovalDecision_INCOMPLETE` | `packages/policy-engine/external_feedback/broker-interceptor/broker-admin-api/missing_methods.md` | `packages/policy-engine/external_feedback/broker-interceptor/broker-admin-api/missing_methods_reply.md` | Delivered and wired (`repository.decideApproval`)                                                                           |
| `@broker-interceptor/crypto/rotateManifestSigningKeys_INCOMPLETE`               | `packages/crypto/external_feedback/broker-interceptor/broker-admin-api/missing_methods.md`        | `packages/crypto/external_feedback/broker-interceptor/broker-admin-api/missing_methods_reply.md`        | Delivered and wired end-to-end (rotation + DB persistence path active in admin-api)                                       |
| `@broker-interceptor/db/persistManifestKeyRotation_INCOMPLETE`                  | `packages/db/external_feedback/broker-interceptor/broker-admin-api/missing_store_data.md`         | `packages/db/external_feedback/broker-interceptor/broker-admin-api/missing_store_data_response.md`      | Reply delivered; wiring complete                                                                                            |

## Feedback Liveness Status

- Incoming requests in `apps/broker-admin-api/external_feedback`: none.
- Outgoing request pending response: none.

## Feedback Decision Notes

- `packages/crypto` also suggested optional adoption of `createCryptoStorageService_INCOMPLETE` and transaction-context threading helpers.
- Current admin-api implementation already satisfies app-owned lifecycle + explicit transaction propagation requirements via:
  - `apps/broker-admin-api/src/infrastructure.ts`
  - `apps/broker-admin-api/src/dependencyBridge.ts`
  - `apps/broker-admin-api/src/repository.ts`
- Decision: keep current wiring for now and revisit crypto storage-service abstraction only if cross-package standardization mandates it.
- `packages/auth` storage bridge updates were reviewed and wired in admin-api enrollment-token cache paths through
  `createAuthStorageScope` scoped methods in
  `apps/broker-admin-api/src/repository.ts`.

## Revisit Workflow

1. Check for new reply files under `packages/*/external_feedback/broker-interceptor/broker-admin-api/`.
2. Update this tracker row status before wiring code.
3. Keep local DB-dependent methods suffixed with `_INCOMPLETE` until integration is complete.
4. After wiring, run `build`, `lint`, `test`, and `test:coverage` for `@broker-interceptor/broker-admin-api`.
