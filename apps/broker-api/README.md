# `@broker-interceptor/broker-api`

Data-plane service for protected outbound provider execution.

## What this app does

`broker-api` enforces the data-plane security chain:

1. mTLS workload identity verification (+ optional workload IP allowlist)
2. Session token issuance and binding (`POST /v1/session`)
3. Optional DPoP binding and replay protectio
4. Execute pipeline (`POST /v1/execute`)
5. Canonicalization + classification + policy decision + approvals
6. SSRF protections + redirect deny + safe forwarding
7. Audit emission for session/execute/manifest/policy decisions
8. Signed manifest distribution (`GET /v1/workloads/{id}/manifest`)

The service is implemented with NestJS on Express and uses a single-process Prisma client and Redis client whe
infrastructure mode is enabled.

## Architecture (runtime)

- Framework: NestJS (`@nestjs/platform-express`) with Express adapter
- Validation: zod schemas sourced from `@broker-interceptor/schemas`
- Persistence/runtime state:
  - In-memory + optional state file (`BROKER_API_STATE_PATH`), always validated
  - Shared infra mode: PostgreSQL (Prisma) + Redis initialized once per process
  - Shared crypto metadata wiring: `@broker-interceptor/crypto` storage factory backed by `@broker-interceptor/db`
    `secretRepository` + Redis rotation-lock adapter
  - Prisma schema source-of-truth: `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/prisma/schema.prisma`
- Security controls:
  - Strict mTLS gate for data-plane endpoints
  - Session token hash lookup/binding to cert thumbprint
  - DPoP proof verification for bound sessions or tenant/workload required DPoP
  - SSRF guard with DNS resolution and denylisted IP ranges
  - Redirect deny policy in execute path
  - Response buffering (no streaming)

## Endpoints

All endpoint DTOs are defined by `packages/schemas/openapi.yaml`.

### `GET /healthz`

- Purpose: liveness/health check
- Auth: none
- Response: `{ "status": "ok" }`

### `POST /v1/session`

- Purpose: issue short-lived session token bound to mTLS identity
- Auth: mTLS required
- Optional header: `DPoP: <proof-jwt>`
- Request body schema: `SessionRequest`
- Response body schema: `SessionResponse`

### `POST /v1/execute`

- Purpose: execute protected-provider call through broker enforcement chai
- Auth: mTLS + `Authorization: Bearer <session_token>`
- Optional/required header: `DPoP` (required when session is DPoP-bound or policy mandates DPoP)
- Request body schema: `ExecuteRequest`
- Response body schema: one of:
  - `ExecuteResponseExecuted` (`status: "executed"`)
  - `ExecuteResponseApprovalRequired` (`status: "approval_required"`)

### `GET /v1/workloads/{workloadId}/manifest`

- Purpose: issue signed short-lived manifest for workload interceptor
- Auth: mTLS + bearer session with `manifest.read` scope
- Response body schema: `Manifest`

## Environment variables

### Core

- `NODE_ENV`: `development|test|production`
- `BROKER_API_HOST`: bind host (default `0.0.0.0`)
- `BROKER_API_PORT`: bind port (default `8081`)
- `BROKER_API_PUBLIC_BASE_URL`: canonical public URL used for DPoP `htu` checks
- `BROKER_API_MAX_BODY_BYTES`: ingress JSON body limit
- `BROKER_API_EXPECTED_SAN_URI_PREFIX`: optional SAN URI prefix check
- `BROKER_API_CORS_ALLOWED_ORIGINS`: comma-separated allowed origins (defaults to `http://localhost:4173` outside production; defaults to empty in production)

### Logging

- `BROKER_API_LOG_LEVEL`: `debug|info|warn|error|fatal|silent` (default `info`, default `silent` in `test`)
- `BROKER_API_LOG_REDACT_EXTRA_KEYS`: optional comma-separated additional sensitive key names to redact in log metadata

Logging behavior:
- structured JSON logs on stdout/stderr
- request lifecycle logs include `correlation_id` and generated `request_id`
- top-level envelope is stable (`ts`, `level`, `service`, `env`, `event`, `component`, correlation/request ids)
- logger failures are non-blocking and never fail request handling

### TLS / mTLS listener

- `BROKER_API_TLS_ENABLED`: enable HTTPS listener for broker-api
- `BROKER_API_TLS_KEY_PATH`: server private key path (PEM)
- `BROKER_API_TLS_CERT_PATH`: server certificate path (PEM)
- `BROKER_API_TLS_CLIENT_CA_PATH`: CA bundle used to validate client workload certificates (PEM)
- `BROKER_API_TLS_REQUIRE_CLIENT_CERT`: request/require client certificates in TLS handshake
- `BROKER_API_TLS_REJECT_UNAUTHORIZED_CLIENT_CERT`: reject unauthorized client certificates at TLS layer

Default behavior:
- `development`: TLS enabled is supported with client-cert verification disabled unless explicitly enabled.
- `production`/`test`: client-cert verification defaults to enabled when TLS is enabled.

### Security + policy timing

- `BROKER_API_SESSION_DEFAULT_TTL_SECONDS`
- `BROKER_API_APPROVAL_TTL_SECONDS`
- `BROKER_API_MANIFEST_TTL_SECONDS` (must be between `30` and `300`)
- `BROKER_API_DPOP_MAX_SKEW_SECONDS`
- `BROKER_API_DNS_TIMEOUT_MS`

### Forwarder controls

- `BROKER_API_FORWARDER_TOTAL_TIMEOUT_MS`
- `BROKER_API_FORWARDER_MAX_REQUEST_BODY_BYTES`
- `BROKER_API_FORWARDER_MAX_RESPONSE_BYTES`

### State loading

- `BROKER_API_STATE_PATH`: persisted local state file
- `BROKER_API_INITIAL_STATE_JSON`: inline initial state JSON

Production requires at least one of `BROKER_API_STATE_PATH` or `BROKER_API_INITIAL_STATE_JSON`.

### Shared infrastructure mode

- `BROKER_API_INFRA_ENABLED`: `true|false` (defaults to enabled outside `test`)
- `BROKER_API_DATABASE_URL`: PostgreSQL connection URL (required when infra enabled)
- `BROKER_API_REDIS_URL`: Redis connection URL (required when infra enabled)
- `BROKER_API_REDIS_CONNECT_TIMEOUT_MS`
- `BROKER_API_REDIS_KEY_PREFIX`

### Secret decryption (integration secrets)
- `BROKER_API_SECRET_KEY_B64`: Base64-encoded 32-byte AES key for decrypting integration secrets (required in production)
- `BROKER_API_SECRET_KEY_ID`: Key identifier for the active encryption key (default: `v1`)

The broker-api retrieves encrypted integration secrets from the database at runtime and decrypts them using the configured key. If no key is configured, it falls back to in-memory state (`integration_secret_headers` in the state file).

**Key generation example:**
```bash
# Generate a 32-byte key and encode as base64
openssl rand -32 | base64
```

**Note:** The same key must be configured in broker-admin-api (as `BROKER_ADMIN_API_SECRET_KEY_B64`) for secrets to be decryptable after being encrypted by the control plane.

### Security behavior
- **Production (infrastructure enabled):** If `BROKER_API_SECRET_KEY_B64` is not configured, the service will fail closed and throw an error when attempting to decrypt integration secrets. This prevents silent fallback to in-memory secrets in production.
- **Development/Test:** If no secret key is configured, a random key is generated automatically for convenience. The service falls back to in-memory state for secrets if shared infrastructure repositories are not available.
- **Shutdown:** During graceful shutdown, the secret key buffer is zeroized (filled with zeros) to minimize in-memory exposure of cryptographic material.

## How to start the server

From repo root:

```bash
pnpm --filter @broker-interceptor/broker-api build
pnpm --filter @broker-interceptor/broker-api dev
```

`dev` runs `node dist/index.js`.

## Local Docker TLS (HTTPS)

`docker-compose` local (`--profile apps`) now prepares broker-api certs automatically via `broker-api-certs`
and starts `broker-api` over HTTPS.

Start local app services:

```bash
docker compose --profile apps up --build broker-api
```

Certificates are generated into `apps/broker-api/certs` and mounted read-only into the container at
`/run/certs/broker-api`.

Manual certificate rotation options:

```bash
# Force rotate now
./apps/broker-api/scripts/generate-dev-mtls-certs.sh --force

# Or force rotate via compose init service
BROKER_API_CERTS_FORCE_ROTATE=true docker compose --profile apps up --build broker-api-certs
```

Automatic refresh behavior:
- Cert generation script is idempotent.
- Existing certs are reused unless they are missing or expiring within the renewal window
  (`--renew-before-days`, default `30`).

## Production TLS/mTLS

Use `docker-compose.production.yml` with mounted certificate material and strict mTLS:

- `BROKER_API_TLS_ENABLED=true`
- `BROKER_API_TLS_REQUIRE_CLIENT_CERT=true`
- `BROKER_API_TLS_REJECT_UNAUTHORIZED_CLIENT_CERT=true`
- `BROKER_API_TLS_CERTS_DIR` mounted to `/run/certs/broker-api`

Expected cert files in `BROKER_API_TLS_CERTS_DIR`:
- `server.key`
- `server.crt`
- `ca.crt`
- `healthcheck-client.key`
- `healthcheck-client.crt`

## Test and coverage

From repo root:

```bash
pnpm --filter @broker-interceptor/broker-api lint
pnpm --filter @broker-interceptor/broker-api test
pnpm --filter @broker-interceptor/broker-api test:coverage
```

Current line coverage target is expected to remain above 85%.

## Pending feedback

- `packages/audit`
  - Status: reply received, pending integration closure.
  - Reply: `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
  - Note: DB-backed persistent audit wiring is now enabled in broker-api when infrastructure mode is enabled; remaining `_INCOMPLETE` items are redaction/cache contract finalization.
- `packages/auth`
  - Status: reply received, pending integration closure.
  - Note: broker-api now wires auth storage scope with app-owned clients/repositories for session persistence/lookup and DPoP replay reservation.
    Enrollment token storage methods remain pending until broker-api introduces enrollment-token runtime flows.
- `packages/crypto`
  - Status: closed.
  - Note: broker-api now wires crypto storage through app-owned DB/Redis clients, enforces active-key consistency,
    resolves signing keys via `private_key_ref`, and orchestrates shared key rotation with Redis lock + transaction.
- `packages/forwarder`
  - Status: reply received, pending integration closure.
  - Reply: `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/forwarder/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
  - Note: execute runtime now wires lock + idempotency persistence (`acquire/release/create/get/complete/fail`) through
    app-owned Redis and the forwarder DB bridge. Deferred host-cooldown/circuit/inflight/snapshot methods remain pending.
- `packages/policy-engine`
  - Status: reply received, pending integration closure.
  - Note: DB bridge methods exist and broker-api now consumes DB-backed descriptor-scope policy reads when infrastructure mode is enabled.
- `packages/ssrf-guard`
  - Status: reply received, pending integration closure.
  - Reply: `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/ssrf-guard/external_feedback/broker-interceptor/broker-api/missing_methods_response.md`
  - Note: broker-api now wires SSRF storage bridge in runtime for DB-backed execute-template loading through native
    `getIntegrationTemplateForExecute` plus Redis-backed DNS cache,
    rebinding observations, SSRF decision projection outbox persistence, and template invalidation publish/outbox.
    Remaining closure items depend on `@broker-interceptor/db` native contracts (CAS DNS semantics + dedicated Postgres projection tables).
- `packages/db` (incoming request handled)
  - Request received: `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/external_feedback/broker-interceptor/db/schema_consolidation_confirmation.md`
  - Response posted: `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/external_feedback/broker-interceptor/db/schema_consolidation_confirmation_response.md`
  - Decision: use shared DB schema as source of truth; keep DPoP replay and rate-limit counters Redis-backed.
