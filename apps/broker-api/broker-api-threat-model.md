# broker-api Threat Model (Targeted Review of Recent Consultant Changes)

## Scope

- **In scope:** `apps/broker-api/src/config.ts`, `apps/broker-api/src/repository.ts`, `apps/broker-api/src/server.ts`,
  and touched tests under `apps/broker-api/src/__tests__`.
- **Runtime focus only:** Data-plane session/execute/manifest flow and shared-infrastructure secret/key handling.
- **Out of scope:** CI/tooling, frontend/admin UX, non-runtime docs.

## Repository-grounded system model

- Data-plane entrypoints: `POST /v1/session`, `POST /v1/execute`, `GET /v1/workloads/{id}/manifest`,
  `GET /v1/keys/manifest` in `apps/broker-api/src/server.ts`.
- Runtime state and policy/template/session interfaces in `apps/broker-api/src/repository.ts`.
- Shared infra wiring (Prisma + Redis + db repositories) in `apps/broker-api/src/infrastructure.ts`.
- Secret envelope cryptography primitives from `packages/crypto/src/envelope.ts` and DB envelope persistence in
  `packages/db/src/repositories/secretRepository.ts`.

## Trust boundaries

1. **Workload -> broker-api (mTLS boundary)**
   - Protocol: HTTPS/mTLS.
   - Controls: workload cert/SAN checks, optional source IP allowlist, session token binding, optional DPoP.
2. **broker-api -> Redis/Postgres (shared infra boundary)**
   - Protocol: DB/Redis client connections.
   - Controls: repository adapters, transaction wrapper, redis key-prefix isolation.
3. **broker-api -> upstream providers (execute forwarding boundary)**
   - Protocol: HTTPS fetch with strict template/policy/SSRF gates.
   - Controls: canonicalization, policy decisioning, SSRF guard, forwarding limits.

## High-value assets

- Integration secrets (encrypted envelopes + decrypted material in memory).
- Session tokens and DPoP replay state.
- Manifest signing private keys and verification keyset metadata.
- Immutable audit events and policy decisions.

## Attacker capabilities (calibrated)

- Can send malicious workload requests (including malformed body/headers) if workload host is compromised.
- Can attempt replay/token misuse and SSRF-style destination abuse.
- Cannot directly read broker-api memory without host compromise.
- Cannot decrypt secret envelopes without valid key material in KMS/key config.

## Threats as abuse paths

| ID  | Abuse path                                                                                                   | Impacted assets                                          | Likelihood | Impact | Priority   | Existing controls                                                | Residual gap                                                                             |
| --- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- | ---------- | ------ | ---------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| T1  | Shared-infra secret retrieval silently falls back to local in-memory headers after decryption/storage errors | Secrets, auth integrity                                  | Medium     | High   | **High**   | Envelope decryption + key management + typed schemas             | Silent fallback could mask storage/decryption failure and weaken fail-closed posture     |
| T2  | Redis `eval` adapter mismatch causes lock/idempotency/rotation scripts to behave incorrectly                 | Idempotency integrity, key-rotation correctness          | Medium     | High   | **High**   | Redis adapters expect strict `eval(script, keys, args)` contract | Runtime cast to incompatible client signature can break critical script semantics        |
| T3  | Missing or unconfigured secret key in production shared-infra mode                                           | Secret confidentiality/integrity and execute reliability | Medium     | High   | **High**   | Secret key env config and envelope schemas                       | Config path previously did not enforce/wire secret key into runtime strongly enough      |
| T4  | Global template resolution dropped in shared manifest rule generation                                        | Policy/template integrity, manifest correctness          | Medium     | Medium | **Medium** | Tenant template lookup                                           | Integrations depending on global templates may be omitted from manifest/routing controls |
| T5  | mTLS-protected public key endpoint implementation drift (unused auth context, low signal bugs)               | Defense-in-depth correctness                             | Low        | Medium | **Low**    | mTLS gate present                                                | Minor implementation errors can hide future auth regression risk                         |

## Prioritized mitigations

### Existing mitigations (kept)

- mTLS + session + optional DPoP gate chain in `server.ts`.
- Zod parsing for request DTOs and persisted state in `server.ts` and `repository.ts`.
- SSRF guard + canonicalization + policy checks before forward execute.

### Implemented refactors in this review

- Restored Redis eval compatibility adapter in `repository.ts` for forwarder/crypto script calls.
- Enforced fail-closed behavior for shared-infrastructure secret retrieval/decryption errors (while preserving
  non-breaking fallback for absent secret bindings).
- Wired secret key parsing into `loadConfig` output and enforced production requirement when shared infrastructure is
  enabled.
- Restored tenant + global template merge for shared manifest rule generation.
- Fixed compile warning and aligned tests with restored runtime contracts.

### Recommended follow-up hardening

1. Add explicit `AppError` reason code for secret decryption/storage failures in execute path (instead of generic
   internal errors).
2. Add dedicated tests for shared-infra secret path when:
   - decryption fails (`expected_aad` mismatch),
   - secret repository throws transport/db errors,
   - integration has stale `secret_ref`.
3. Consider startup-time invariant checks in infra-enabled mode (required repositories present), so request-time paths
   cannot drift into partial wiring.

## Assumptions affecting priority

- Production deployments run with `BROKER_API_INFRA_ENABLED=true` and shared DB/Redis repositories fully wired.
- Integrations requiring protected provider access rely on secret envelope storage (not only state-file headers).
- Workloads are semi-trusted and prompt injection is considered persistent risk.

## Open questions for service owner

1. In production shared-infra mode, should integrations **without** `secret_ref` be hard-denied (strict fail-closed) or
   allowed to proceed with empty injected headers?
2. Are global templates (`tenant_id = global`) a required contract for all tenants in production, or a migration-only
   compatibility path?
3. Should secret retrieval/decryption failures map to a stable public error code (e.g. `integration_secret_unavailable`)
   for operational triage?

## Quality check

- Entrypoints covered: session, execute, manifest, public manifest keys.
- Trust boundaries covered: workload ingress, infra stores, upstream egress.
- Runtime-only focus maintained (no CI/dev tooling mixing).
- Assumptions and unresolved questions are explicit.
