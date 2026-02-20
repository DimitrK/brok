# broker-admin-api

Control-plane API for the broker platform.  
This service manages tenants, workloads, enrollments, templates, integrations, policies, approvals, audit queries, and
manifest key distribution.

## Architecture

- Runtime: Node.js + TypeScript
- Framework: NestJS on Express (`@nestjs/platform-express`)
- Security middleware: Helmet
- Process infrastructure: single Prisma client + single Redis client initialized once per process and passed through app
  dependencies
- API contracts: OpenAPI-derived DTO/zod schemas from `@broker-interceptor/schemas`

## Purpose

`broker-admin-api` is the administrative boundary of the system:

- Handles human/admin authenticated operations (not workload mTLS data-plane execution).
- Enforces RBAC and tenant scoping for all control-plane actions.
- Stores provider secrets in encrypted form and never returns secret material in read APIs.
- Emits append-only audit events for sensitive admin actions and policy changes.
- Validates all API inputs/outputs with OpenAPI-derived DTO schemas from `@broker-interceptor/schemas`.

## How To Run

From repository root:

```bash
pnpm --filter @broker-interceptor/broker-admin-api run build
pnpm --filter @broker-interceptor/broker-admin-api run dev
```

Default bind:

- `BROKER_ADMIN_API_HOST=0.0.0.0`
- `BROKER_ADMIN_API_PORT=8080`

Health endpoint:

- `GET /healthz`

Infrastructure env requirements when enabled:

- `BROKER_ADMIN_API_INFRA_ENABLED=true`
- `BROKER_ADMIN_API_DATABASE_URL=postgresql://...`
- `BROKER_ADMIN_API_REDIS_URL=redis://...`
- `BROKER_ADMIN_API_REDIS_CONNECT_TIMEOUT_MS` (optional)
- `BROKER_ADMIN_API_REDIS_KEY_PREFIX` (optional)
- `BROKER_ADMIN_API_CORS_ALLOWED_ORIGINS` (optional, comma-separated; defaults to `http://localhost:4173` outside production and empty in production)

Logging env:

- `BROKER_ADMIN_API_LOG_LEVEL`: `debug|info|warn|error|fatal|silent` (default `info`, default `silent` in `test`)
- `BROKER_ADMIN_API_LOG_REDACT_EXTRA_KEYS`: optional comma-separated additional sensitive key names to redact in log metadata

Logging behavior:

- structured JSON logs on stdout/stderr
- request lifecycle emits `request.received`, `request.completed`, and rejection/failure events
- auth decision failures are logged with stable `reason_code` and correlation context
- logger failures are non-blocking and never fail request handling

Vault issuer hardening env (vault mode only):

- `BROKER_ADMIN_API_VAULT_REQUEST_TIMEOUT_MS` (optional, default `5000`)

## Key Endpoints

- `POST /v1/tenants`
- `GET /v1/tenants`
- `POST /v1/tenants/{tenantId}/workloads`
- `GET /v1/tenants/{tenantId}/workloads`
- `POST /v1/workloads/{workloadId}/enroll`
- `PATCH /v1/workloads/{workloadId}`
- `POST /v1/tenants/{tenantId}/integrations`
- `GET /v1/tenants/{tenantId}/integrations`
- `PATCH /v1/integrations/{integrationId}`
- `POST /v1/templates`
- `GET /v1/templates`
- `GET /v1/templates/{templateId}/versions/{version}`
- `POST /v1/policies`
- `GET /v1/policies`
- `DELETE /v1/policies/{policyId}`
- `GET /v1/approvals`
- `POST /v1/approvals/{approvalId}/approve`
- `POST /v1/approvals/{approvalId}/deny`
- `GET /v1/audit/events`
- `GET /v1/keys/manifest`
- `GET /v1/admin/auth/providers`
- `POST /v1/admin/auth/oauth/start`
- `POST /v1/admin/auth/oauth/callback`
- `GET /v1/admin/auth/session`
- `GET /v1/admin/auth/signup-policy`
- `PATCH /v1/admin/auth/signup-policy`

All request/response contracts are defined in:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/schemas/openapi.yaml`

## Auth Modes

Supported modes:

- `static` bearer token auth
- `oidc` bearer token verification (issuer/audience/JWKS)

For local development, `static` mode is the easiest:

- `BROKER_ADMIN_API_AUTH_MODE=static`
- `BROKER_ADMIN_API_STATIC_TOKENS_JSON='[{"token":"...","subject":"...","roles":["owner"]}]'`

OIDC mode controls:

- `BROKER_ADMIN_API_AUTH_MODE=oidc`
- `BROKER_ADMIN_API_OIDC_ISSUER=https://...`
- `BROKER_ADMIN_API_OIDC_AUDIENCE=...`
- `BROKER_ADMIN_API_OIDC_JWKS_URI=https://.../.well-known/jwks.json`
- `BROKER_ADMIN_API_OIDC_CLIENT_ID=...` (required for interactive OAuth login)
- `BROKER_ADMIN_API_OIDC_CLIENT_SECRET=...` (optional, required by some providers)
- `BROKER_ADMIN_API_OIDC_AUTHORIZATION_URL=https://.../authorize` (optional, defaults from issuer)
- `BROKER_ADMIN_API_OIDC_TOKEN_URL=https://.../oauth/token` (optional, defaults from issuer)
- `BROKER_ADMIN_API_OIDC_SCOPE` (optional, default `openid profile email`)
- `BROKER_ADMIN_API_OAUTH_STATE_TTL_SECONDS` (optional, default `600`)
- `BROKER_ADMIN_API_OIDC_GOOGLE_CONNECTION` (optional provider hint; defaults to `google-oauth2` for Auth0 issuers)
- `BROKER_ADMIN_API_OIDC_GITHUB_CONNECTION` (optional provider hint; defaults to `github` for Auth0 issuers)
- `BROKER_ADMIN_API_OIDC_EMAIL_CLAIM` (optional, default `email`)
- `BROKER_ADMIN_API_OIDC_NAME_CLAIM` (optional, default `name`)

Interactive OAuth behavior:

- `POST /v1/admin/auth/oauth/start` builds an authorization URL with PKCE and includes the configured
  `BROKER_ADMIN_API_OIDC_AUDIENCE`.
- `POST /v1/admin/auth/oauth/callback` exchanges the code and uses OAuth `access_token` as `session_id` for admin API
  bearer auth (while validating nonce against `id_token` when present).

## Security Notes

- Fail-closed boundary validation with `zod`.
- No secret payloads exposed in read/list endpoints.
- Strict structured error responses with correlation IDs.
- Audit events are append-only from API perspective.
- Tenant scope checks are enforced before state mutation on approval actions.
- Vault signing calls deny redirects and enforce request timeouts to avoid credential leakage and hung upstream
  dependencies.
- Vault mode enforces `https` Vault addresses in production configuration.
- Invalid request URLs (including malformed Host header combinations) are rejected with deterministic 400 responses.
- Manifest key rotation fails closed if persisted key material for an existing `kid` does not match the rotated keyset.

## Dependency Integration Status

Infrastructure lifecycle (wired):

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/infrastructure.ts`
  initializes Prisma/Redis once per process.
- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/app.ts` wires that
  infrastructure into repository/dependency bridge and closes clients on shutdown.
- Transaction boundary hand-off is available via `processInfrastructure.withTransaction(...)` for package-level wiring.

Wired in this app:

1. `@broker-interceptor/audit`

- `appendAuditEvent` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` ->
  `appendAuditEventWithAuditPackage`
- `queryAuditEvents` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` ->
  `queryAuditEventsWithAuditPackage`

2. `@broker-interceptor/auth`

- `parseAndValidateCsr` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` ->
  `validateEnrollmentCsrWithAuthPackage`
- `signCsrWithVault` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/certificateIssuer.ts`
  -> `issueVaultCertificate`
- `issueExternalCaEnrollment` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` ->
  `ensureEnrollmentModeSupported_INCOMPLETE`
- `createAuthStorageScope` wired for enrollment-token cache bridge via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/repository.ts` ->
  `authEnrollmentTokenStorageScope` (`issueEnrollmentTokenRecord` and
  `consumeEnrollmentTokenRecordByHash`)

3. `@broker-interceptor/policy-engine`

- `validatePolicyRule` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` ->
  `validatePolicyRuleWithPolicyEngine`
- `derivePolicyFromApprovalDecision` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/repository.ts` ->
  `decideApproval`

4. `@broker-interceptor/crypto`

- `encryptSecretMaterial` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/crypto.ts` ->
  `encryptSecretMaterialWithCryptoPackage`
- `decryptSecretMaterial` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/crypto.ts` ->
  `decryptSecretMaterialWithCryptoPackage`
- `computeManifestKeysEtag` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/crypto.ts` ->
  `computeManifestKeysWeakEtagWithCryptoPackage`
- `rotateManifestSigningKeys` wired via
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` ->
  `rotateManifestSigningKeysWithCryptoPackage_INCOMPLETE` (rotation + persistence wired; rename pending)

Pending in this app:

1. `external-ca-provider`

- runtime enrollment provider wiring for `external_ca` workload enrollment mode

## Pending Feedback

Last checked: 2026-02-13

- No pending external feedback for this app.

Resolved feedback already reviewed and integrated:

- `packages/auth/external_feedback/broker-interceptor/broker-admin-api/missing_methods_reply.md`
- `packages/crypto/external_feedback/broker-interceptor/broker-admin-api/missing_methods_reply.md`
- `packages/crypto/external_feedback/broker-interceptor/broker-admin-api/missing_methods_response.md`
- `packages/policy-engine/external_feedback/broker-interceptor/broker-admin-api/missing_methods_reply.md`

Crypto feedback decision:

- `rotateManifestSigningKeys` is already wired and active in admin-api.
- Suggested optional crypto storage-service abstraction (`createCryptoStorageService_INCOMPLETE`) is deferred for now;
  current admin-api wiring already enforces app-owned client lifecycle and explicit transaction boundaries.

## Pending Package/Method Wiring Matrix

The following upstream methods are still pending and are tracked with `_INCOMPLETE` naming.  
Each line maps `package/method_name_INCOMPLETE` to the local method that will consume it.

1. `external-ca-provider/issueEnrollment_INCOMPLETE` ->
   `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts`
   `ensureEnrollmentModeSupported_INCOMPLETE`

## `_INCOMPLETE` Methods

- `ensureEnrollmentModeSupported_INCOMPLETE` (pending)
- `persistManifestKeyRotationWithDbPackage_INCOMPLETE` (wired; rename pending)
- `rotateManifestSigningKeysWithCryptoPackage_INCOMPLETE` (wired; rename pending)

Detailed tracking ledger:

- `apps/broker-admin-api/INCOMPLETE_METHODS_TRACKER.md`

## Tests

Run:

```bash
pnpm --filter @broker-interceptor/broker-admin-api run test
pnpm --filter @broker-interceptor/broker-admin-api run test:coverage
```

TCP integration tests are explicit opt-in:

```bash
BROKER_ADMIN_API_RUN_TCP_INTEGRATION=1 pnpm --filter @broker-interceptor/broker-admin-api run test
```

Coverage target for implemented methods: `>= 85%`.

Latest coverage run (2026-02-15):

- Statements: `85.11%`
- Functions: `93.42%`
