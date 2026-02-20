### Backend-First Logging Infrastructure via `packages/logging`

### Summary
Build a shared logging module at `/Users/dimitriskyriazopoulos/Development/brok/packages/logging` and integrate it first into `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api` and `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api`.  
This gives immediate production-grade structured logs, correlation propagation, redaction guarantees, and reason-code alignment without changing public API behavior.

### Architecture Decision
- Chosen boundary: new shared package `@broker-interceptor/logging` in `/Users/dimitriskyriazopoulos/Development/brok/packages/logging`.
- Reason: app-local logging would duplicate redaction/context logic and drift quickly across code spaces.
- Current repo reality: both APIs are custom Node handlers wrapped by Nest (`/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/server.ts`, `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/server.ts`), so lifecycle logging must be implemented in handler flow, not Nest interceptors/filters.

### Scope (This Implementation)
- In scope:
- Shared structured logger contract + implementation.
- Async request context (`correlation_id`, `request_id`, scoped identifiers) with `AsyncLocalStorage`.
- Redaction-first logging wrappers.
- Request lifecycle + stage logs in `broker-api`.
- Request lifecycle + auth/audit-failure logs in `broker-admin-api`.
- Runtime path lint guard against direct `console.*` usage in these two apps.
- Out of scope for this slice:
- Full package-level instrumentation across `auth/policy-engine/ssrf-guard/forwarder/audit/db`.
- W3C Trace Context propagation.
- Log backend/vendor integration (stdout only, collector external).

### Important Interface Changes

#### New shared package API
- Add package: `/Users/dimitriskyriazopoulos/Development/brok/packages/logging`.
- Exports:
- `LogLevelSchema` and `type LogLevel`.
- `LogContextSchema` and `type LogContext`.
- `LogEventInputSchema` and `type LogEventInput`.
- `createStructuredLogger(options)`.
- `createNoopLogger()`.
- `runWithLogContext(context, fn)`, `getLogContext()`, `setLogContextFields(partial)`.
- `sanitizeForLog(value)` and default sensitive key policy.

#### New config/env interfaces
- `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/config.ts`:
- `BROKER_API_LOG_LEVEL` (`debug|info|warn|error|fatal|silent`, default `info`, `silent` in test).
- `BROKER_API_LOG_REDACT_EXTRA_KEYS` (comma-separated optional).
- `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/config.ts`:
- `BROKER_ADMIN_API_LOG_LEVEL` (`debug|info|warn|error|fatal|silent`, default `info`, `silent` in test).
- `BROKER_ADMIN_API_LOG_REDACT_EXTRA_KEYS` (comma-separated optional).

#### Schema contract additions
- Add `/Users/dimitriskyriazopoulos/Development/brok/packages/schemas/log-event.schema.json`.
- Export generated zod schema/type through `/Users/dimitriskyriazopoulos/Development/brok/packages/schemas/src/generated/schemas.ts` and `/Users/dimitriskyriazopoulos/Development/brok/packages/schemas/src/index.ts`.
- No OpenAPI route contract changes.

### Logging Envelope (Locked)
Top-level fields:
- `ts`, `level`, `service`, `env`, `event`, `component`, `correlation_id`, `request_id`.
Optional top-level fields:
- `tenant_id`, `workload_id`, `integration_id`, `reason_code`, `duration_ms`, `status_code`, `route`, `method`.
All other details go in `metadata`.

### Implementation Plan by Code Space

#### 1) `/Users/dimitriskyriazopoulos/Development/brok/packages/logging`
- Create logger core with non-throwing emit path.
- Implement ALS context utilities.
- Implement redaction policy:
- Always redact keys matching token/secret/auth/cookie/dpop/private-key/ciphertext/auth-tag families.
- Never log raw request or response body by default.
- Add unit tests for:
- redaction.
- context isolation across concurrent async operations.
- non-blocking logger behavior if writer throws.
- log envelope shape validation.

#### 2) `/Users/dimitriskyriazopoulos/Development/brok/packages/schemas`
- Add `log-event.schema.json`.
- Regenerate schemas.
- Add minimal tests/validation usage in logging package tests.

#### 3) `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api`
- Wire logger instance in `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/app.ts`.
- Pass logger via Nest tokens/module factory in `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/nest/brokerApiNestModule.ts` and tokens file.
- In `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/server.ts`:
- Create request context at ingress (`correlation_id` from existing extractor + generated `request_id`).
- Emit `request.received` and `request.completed` once per request with duration and final status.
- Emit stage logs for session/execute/manifest flow and denials with stable `reason_code`.
- Replace `reportPersistenceWarning` `process.emitWarning` path with structured logger `warn`.
- In `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/repository.ts`:
- Replace `process.emitWarning` paths with injected logger calls.
- Preserve fail-closed behavior when secret infrastructure is required.
- In `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/index.ts`:
- Replace startup `console.error` with logger-backed fatal/error output.

#### 4) `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api`
- Wire logger in `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/app.ts`.
- Pass logger via `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/nest/adminApiNestModule.ts` and tokens.
- In `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/server.ts`:
- Add request lifecycle logs (`request.received`, `request.completed`, `request.rejected`).
- Replace `appendAuditEventNonBlocking` fallback `console.error` with structured logger.
- Log auth decision failures with `reason_code` and correlation context.
- In `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/repository.ts`:
- Replace enrollment token cache `console.warn` with logger warning (sanitized).
- In `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/index.ts`:
- Replace startup `console.error` with logger-backed fatal/error output.

#### 5) Lint guardrail
- Update `/Users/dimitriskyriazopoulos/Development/brok/packages/eslint-config/eslint.config.js` with path-scoped rule for runtime app source:
- Disallow direct `console.*` in `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api/src/**` and `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api/src/**`.
- Exclude tests.
- Keep `packages/interceptor-node` console migration for later slice.

### Test Cases and Scenarios

#### Unit tests
- Logging package:
- redact sensitive keys and nested fields.
- preserve allowed metadata.
- enforce envelope schema.
- ALS context propagation and isolation under parallel promises.
- Config parsing:
- invalid log level rejected.
- defaults applied by env.

#### Integration tests
- `broker-api`:
- `POST /v1/session`, `POST /v1/execute`, `GET /v1/workloads/{id}/manifest` emit start/end logs with same `correlation_id`.
- denial branches emit `reason_code`.
- `broker-admin-api`:
- auth-protected route success/failure emits lifecycle logs.
- non-blocking audit append failure emits `audit_emit_failed` log with correlation.

#### Security tests
- Assert logs never contain:
- authorization headers, DPoP values, API keys, secret envelopes, decrypted secret values.
- Fuzz redaction key matching with mixed-case and nested structures.

#### Regression checks
- Existing API responses unchanged.
- Existing audit event behavior unchanged.
- lint/typecheck/test pass for touched packages/apps.

### Rollout and Operationalization
- Default stdout JSON logs.
- Default test env level `silent` to avoid test noise.
- Production default `info`, debug opt-in via env.
- No request-path failures caused by logger failures.
- Correlation key remains `x-correlation-id` in responses and logs.

### Collaboration Workflow (Cross-Code-Space)
- Primary touched code spaces:
- `/Users/dimitriskyriazopoulos/Development/brok/packages/logging`
- `/Users/dimitriskyriazopoulos/Development/brok/packages/schemas`
- `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-api`
- `/Users/dimitriskyriazopoulos/Development/brok/apps/broker-admin-api`
- No external feedback request files are required for this slice unless blocked by ownership constraints discovered during implementation.
- README updates will be made in each touched code space to document logging behavior, env vars, and operational notes.

### Explicit Assumptions and Defaults
- Trace context (`traceparent`) is deferred to a later RFC.
- Retention and backend shipping policy remain platform-level; app responsibility is structured stdout only.
- This first delivery is backend-first; package-level instrumentation for `auth/policy-engine/ssrf-guard/forwarder/audit/db` and interceptor-node contract alignment is the next planned slice.
- No OpenAPI response shape changes are introduced in this logging slice.
