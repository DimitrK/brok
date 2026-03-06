# Playbook: Adding a New Credential Type

This playbook documents the extension pattern introduced by the staged AWS SigV4 / S3 work, using:

- `docs/RPODUCT_SPECIFICATION.md`
- `README.md`
- `docs/AWS S3 key material support plan.md`
- staged changes outside `packages/backup-workload/`

It is intended for future credential types such as additional signing schemes, custom header credentials, or structured provider secrets that cannot be represented safely as a single bearer token.

## Core Design Model

The staged S3 work shows that a new credential type is not a single change. It crosses five layers:

1. Contract layer
   - Define a typed secret-material variant.
   - Define any typed template/runtime constraints needed to tell broker how to use that secret.
2. Storage layer
   - Preserve a stable secret discriminator for DB and envelope metadata.
   - Encrypt the full structured secret DTO, not an ad hoc string encoding.
3. Control-plane layer
   - Accept and validate the new credential shape at the admin API boundary.
   - Provide explicit admin-web authoring flows for the new secret and any runtime constraints.
4. Data-plane layer
   - Decrypt the secret and translate it into exact upstream auth behavior for the matched request.
   - Fail closed when required signing/auth inputs are missing.
5. Observability and operator layer
   - Summarize the credential type safely in audit.
   - Redact all raw secret fields in logs.
   - Update docs and examples so operators never fall back to raw JSON stuffing.

The durable abstraction is:

- `SecretMaterial` is the canonical credential payload.
- `SecretMaterialType` is the storage discriminator.
- template path-group constraints describe runtime auth behavior separately from secret storage.
- broker data plane owns the final translation from typed secret + matched path group + request to injected upstream headers.

## What Was Generic vs S3-Specific

### Generic patterns introduced by the staged work

- `packages/schemas` now treats secret material as a discriminated union.
- `packages/crypto` now encrypts the full secret DTO JSON and still decrypts legacy string envelopes for older simple secret types.
- `packages/db` stores only the secret type discriminator plus the opaque encrypted envelope.
- `apps/broker-admin-api` persists `payload.secret_material.type` and never exposes secret values in read APIs.
- `apps/admin-web` uses small helper adapters instead of inline branching for secret creation and template constraint creation.
- `apps/broker-api/src/repository.ts` now has a single seam, `buildExecuteRequestHeadersShared(...)`, for credential-aware request auth injection.
- `packages/audit` and `packages/logging` were extended so operators get safe summaries, not raw secret fields.

### S3-specific pieces

- `aws_sigv4` as a secret-material variant.
- `constraints.upstream_auth = { type: "aws_sigv4", service: "s3", region? }`.
- the SigV4 signer in `apps/broker-api/src/upstreamAuth.ts`.
- S3 bucket-root list presets and authoring helpers in admin-web.
- S3-specific verification and compatibility tests.

Future credential types should reuse the generic pattern and add only the minimum provider-specific runtime logic.

## File Map

Use this map when planning the work.

### Contracts

- `packages/schemas/openapi.yaml`
- `packages/schemas/secret-material-type.schema.json`
- `packages/schemas/secret-material.schema.json`
- `packages/schemas/integration-write.schema.json`
- `packages/schemas/template-path-group-constraints.schema.json`
- `packages/schemas/src/generated/schemas.ts`

### Control plane and storage

- `apps/broker-admin-api/src/repository.ts`
- `apps/broker-admin-api/src/crypto.ts`
- `apps/broker-admin-api/src/nest/controllers/integrationsController.ts`
- `apps/broker-admin-api/src/nest/controllers/templatesController.ts`
- `packages/crypto/src/contracts.ts`
- `packages/crypto/src/envelope.ts`
- `packages/db/prisma/schema.prisma`
- `packages/db/prisma/migrations/*`
- `packages/db/src/contracts.ts`
- `packages/db/src/repositories/secretRepository.ts`

### Data plane and routing

- `apps/broker-api/src/repository.ts`
- `apps/broker-api/src/upstreamAuth.ts`
- `apps/broker-api/src/http/routes/executeRoute.ts`
- `packages/forwarder/src/forward.ts`
- `packages/interceptor-node/src/integration-selection.ts`
- `packages/interceptor-node/src/match-patterns.ts`
- `packages/interceptor-node/src/broker-client.ts`

### UI and observability

- `apps/admin-web/src/features/integrations/integrationSecretMaterial.ts`
- `apps/admin-web/src/features/integrations/IntegrationsPanel.tsx`
- `apps/admin-web/src/features/templates/templateS3Auth.ts`
- `apps/admin-web/src/features/templates/TemplatesPanel.tsx`
- `packages/audit/src/integration.ts`
- `packages/audit/src/redaction.ts`
- `packages/logging/src/redaction.ts`

## Decision Tree

Before editing anything, classify the new credential type:

### Case A: secret shape changes, but runtime auth is still plain bearer

Example: a renamed or structured bearer-like secret that still becomes `Authorization: Bearer ...`.

Required changes:

- contract union
- storage discriminator support
- encryption/decryption round-trip
- admin API validation
- admin-web authoring
- audit summary
- log redaction
- docs/tests

Likely not required:

- template constraints
- new upstream auth builder logic
- forwarder fidelity changes
- interceptor routing changes

### Case B: runtime auth behavior changes per request

Examples:

- SigV4-style signing
- multiple injected headers
- query-string signing
- request-body digests
- auth behavior selected per path group

Required changes:

- everything from Case A
- typed template/runtime constraints
- data-plane auth builder changes
- forwarder/header-fidelity review
- canonicalization/policy/matching review
- extra docs and operator guidance

## Step-by-Step Playbook

### 1. Define the credential contract first

Start in `packages/schemas`.

Add:

- a new discriminator in `secret-material-type.schema.json`
- a new discriminated-union member in `secret-material.schema.json`
- the write-side variant in `integration-write.schema.json`
- matching OpenAPI definitions in `openapi.yaml`

Rules:

- Do not overload `api_key` with embedded JSON.
- Do not treat the new credential as an untyped blob at the public boundary.
- Keep the secret DTO strict and bounded with explicit field limits.
- Regenerate `packages/schemas/src/generated/schemas.ts` and add schema tests.

If the new credential needs runtime execution semantics, also extend `template-path-group-constraints.schema.json` with a typed discriminated union member instead of leaving loose `constraints` blobs.

### 2. Keep secret storage opaque and discriminator-driven

Update the storage-facing discriminator path:

- `packages/crypto/src/contracts.ts`
- `packages/db/src/contracts.ts`
- `packages/db/src/types.ts`
- `packages/db/prisma/schema.prisma`
- Prisma SQL migration if the secret discriminator is stored in a Postgres enum

The current system stores:

- the secret type discriminator in DB metadata
- the encrypted envelope as opaque ciphertext

It does not store structured credential subfields relationally. Keep that property unless there is a strong query or policy requirement.

### 3. Extend envelope handling without breaking older secrets

Update `packages/crypto/src/envelope.ts`.

Current reusable pattern:

- encrypt the full `SecretMaterial` DTO as JSON
- on decrypt, try to parse full JSON back into `SecretMaterial`
- keep legacy fallback parsing only for older simple secret types that were previously stored as raw strings

Requirements:

- AAD must still bind `tenant_id`, `integration_id`, and `secret_type`.
- decrypted secret type must match the envelope metadata discriminator.
- malformed secret payloads must fail closed.

This is the mechanism that made `aws_sigv4` possible without redesigning the envelope format again.

### 4. Wire the control plane through broker-admin-api

Update the integration create path in `apps/broker-admin-api`, and any future secret-rotation/update path if that API is introduced later.

Required work:

- accept the new schema-derived DTO via controller parsing
- encrypt the secret through `apps/broker-admin-api/src/crypto.ts`
- store `payload.secret_material.type` in secret metadata
- bind `secret_ref` and `secret_version` exactly as existing integrations do

Rules:

- do not expose secret material in any read/list API
- do not bypass schema parsing with hand-rolled DTOs
- do not add silent fallback behavior for malformed credential types

If the new credential type needs template-level execution hints, make template validation reject malformed constraint shapes at the same time.

### 5. Add explicit admin-web authoring

Do not force operators to paste JSON into a generic field.

Follow the adapter pattern from:

- `apps/admin-web/src/features/integrations/integrationSecretMaterial.ts`
- `apps/admin-web/src/features/templates/templateS3Auth.ts`

Required work:

- add explicit fields for the new secret type
- add a helper that builds schema-valid secret material
- add template helper logic if runtime constraints are needed
- update the relevant panels and tests

If the new credential type requires common path groups or operator hints, add a small preset/helper rather than documenting the behavior only in prose.

### 6. Add data-plane auth translation in one place

The main seam is:

- `apps/broker-api/src/repository.ts` -> `buildExecuteRequestHeadersShared(...)`

That method should:

- fetch and decrypt the secret
- validate the decrypted shape
- delegate request auth generation

The current auth-generation seam is:

- `apps/broker-api/src/upstreamAuth.ts`

For future credential types, add logic there or, preferably, evolve it into a strategy registry keyed by runtime constraint type.

Every runtime-auth credential type must explicitly define:

- which template constraint activates it
- which secret fields are required
- which request fields are part of signing or auth generation
- precedence rules between secret values, template overrides, and request-derived values
- exact fail-closed conditions

Note:

- the current implementation still serializes structured secrets to strings/JSON before auth generation and reparses them in `upstreamAuth.ts`
- if more credential types are added, replace this with typed `SecretMaterial` strategy inputs

### 7. Review forwarder and request-shape fidelity

Any credential type that signs requests or depends on header/query fidelity must review:

- `packages/forwarder/src/forward.ts`
- `packages/interceptor-node/src/broker-client.ts`

The S3 change had to preserve header tuples instead of rebuilding a `Headers` object because coalescing/deduplication can break signed requests.

For future credential types, verify:

- exact header filtering rules
- duplicate-header behavior
- `Host` header handling
- query-string preservation
- body hashing/canonicalization behavior

If auth correctness depends on request shape, treat forwarder fidelity as part of the credential feature, not as a separate concern.

### 8. Review matching, policy, and SSRF implications

New credential types often change which requests must be routed through broker.

Review:

- `packages/interceptor-node/src/integration-selection.ts`
- `packages/interceptor-node/src/match-patterns.ts`
- `packages/policy-engine/src/classification.ts`
- `packages/canonicalizer/*`
- `packages/ssrf-guard/*`

Questions to answer:

- can more than one integration match the same URL family?
- do workloads need deterministic `integrationOverrides`?
- do new path patterns require safe-glob or regex support?
- do hosts remain exact-allowlist-only?
- do signed requests rely on exact root paths, encoded object keys, or unusual query params?

Do not assume a new credential type is only a storage problem. It can change routing ambiguity, policy evaluation, and SSRF boundary rules.

### 9. Extend audit and logging safely

Add non-secret summaries in `packages/audit/src/integration.ts`.

Good summary fields:

- credential type
- feature flags such as “has session token”
- non-secret region or audience-like values when operationally useful

Do not emit:

- raw key ids if they are sensitive in your threat model
- client secrets
- signing secrets
- refresh tokens
- raw session tokens

Then extend:

- `packages/audit/src/redaction.ts`
- `packages/logging/src/redaction.ts`

so accidental inclusion of raw fields is still masked.

### 10. Update operator docs and examples

Update at minimum:

- root `README.md`
- `apps/broker-admin-api/README.md` if control-plane behavior changed
- `apps/broker-api/README.md` if runtime auth behavior changed
- `apps/admin-web/README.md` if authoring flows changed
- package READMEs for `schemas`, `crypto`, `db`, `audit`, or interceptors when their public guidance changed

Operator docs must show the typed contract, not internal implementation details.

### 11. Build the test matrix before calling the work done

Minimum required coverage:

- schema tests for valid and invalid credential DTOs
- crypto tests for round-trip encryption/decryption
- legacy compatibility tests if older envelopes exist
- DB repository tests for secret type persistence
- admin-api tests for create/update validation and storage wiring
- admin-web tests for secret-material builders and template helper logic
- broker-api tests for request auth generation and fail-closed behavior
- forwarder tests if request signing depends on header/query fidelity
- matcher/canonicalizer/policy/ssrf tests if request classification changed
- audit/logging tests that prove secrets are not exposed

If the credential type is for a workload with unusual request shapes, add a focused compatibility verifier similar to the staged eBPF helper, but keep it workload-specific instead of polluting the core abstraction.

## Recommended Reusable Abstractions for the Next Credential Types

The staged changes make these abstractions explicit enough to standardize:

### 1. Secret-type registry

Create a small registry keyed by `SecretMaterial["type"]` that owns:

- schema fragments
- admin-web field metadata
- audit-safe summary extraction
- log redaction keys

Today this logic is spread across unions, UI helpers, and audit `switch` statements.

### 2. Runtime-auth strategy registry

Create a registry keyed by typed template constraint, for example `constraints.upstream_auth.type`.

Each strategy should own:

- runtime constraint parser
- typed secret parser
- request auth/header generation
- fail-closed errors
- optional precedence rules and docs text

Today this logic is centralized in `apps/broker-api/src/upstreamAuth.ts`, but it is still S3-specific.

### 3. Constraint helper adapters

Follow the `templateS3Auth.ts` pattern, but make it generic:

- parse existing constraints into draft state
- build constraints from draft state
- optionally expose common presets

This avoids burying provider-specific logic inside large React components.

### 4. Safe audit summary adapter

Define one summary adapter per secret type. It should return only operationally useful, non-secret metadata.

The current `packages/audit/src/integration.ts` `switch` is the right conceptual seam, but it will become repetitive if more types arrive.

## Current Rough Edges to Keep in Mind

- `template-path-group-constraints.schema.json` is still effectively S3-specific, not a broad upstream-auth framework.
- `integration-write.schema.json` and `secret-material.schema.json` both need updates for new secret types, so drift is possible.
- Postgres enum migration is easy to miss even though envelope payloads are opaque.
- `PATCH /v1/integrations/{id}` does not currently rotate secret material; secret updates are a separate capability.
- `apps/broker-api/src/upstreamAuth.ts` reparses structured secrets from JSON strings instead of consuming typed secret objects directly.
- any auth type that signs headers or query params must re-check forwarder fidelity and interceptor request serialization.

## Definition of Done

A new credential type is only complete when all of the following are true:

- the public contract accepts the new typed secret shape
- encrypted storage round-trips it without leaking fields
- admin APIs and admin-web can author it without raw JSON hacks
- broker-api can translate it into correct upstream auth behavior
- request forwarding preserves whatever exact request shape the auth scheme depends on
- audit and logs expose only safe summaries
- docs and examples show the typed, supported operator workflow
- end-to-end tests prove valid flows and fail-closed behavior

If one of those is missing, the feature is partial even if the secret can technically be stored.
