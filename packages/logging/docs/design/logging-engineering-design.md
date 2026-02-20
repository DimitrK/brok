# Cross-Codespace Logging Engineering Design (NestJS + Express)

Status: Proposed  
Owner: `apps/broker-api` (data-plane ingress)  
Applies to: `apps/broker-api`, `apps/broker-admin-api`, `packages/auth`, `packages/policy-engine`, `packages/ssrf-guard`, `packages/forwarder`, `packages/audit`, `packages/db`, `packages/interceptor-node`, `packages/schemas`

## 1. Why this exists

`broker-api` currently propagates `correlation_id` for API responses and audit events, but does not emit an operational structured log stream for request lifecycle, errors, and internal stage timings.  
This document defines a production logging mechanism that is consistent across code-spaces while preserving current audit guarantees.

References:
- `apps/broker-api/README.md`
- `apps/broker-api/broker-api-threat-model.md`
- `docs/TASKS_BACKLOG.md` ("Secrets never appear in logs")

## 2. Scope and principles

### In scope

- Structured application logs (JSON) for control-plane and data-plane services.
- Correlation context propagation across app and package boundaries.
- Redaction and safe defaults that prevent secret/token leakage.
- Stage-level logging for data-plane enforcement chain.
- Consistent reason-code logging aligned with API error codes.

### Out of scope

- Replacing immutable audit events with logs.
- Vendor-specific log backend lock-in.
- Full distributed tracing implementation (can be layered later).

### Hard principles

1. Audit is compliance/forensics truth; logs are operational telemetry.
2. All untrusted and sensitive payloads are redacted by default.
3. Every denial/error path logs a stable `reason_code`.
4. Correlation context is mandatory for all request-scoped logs.
5. Log write failures must never break request processing.

## 3. Target outcomes

1. Operators can reconstruct request path by `correlation_id` without reading raw payloads.
2. Security incidents can map API error reason codes to structured logs and audit records.
3. Logs are schema-governed and queryable across code-spaces.
4. Logging overhead is bounded and measurable.

## 4. Architecture overview

### 4.1 Data flow

1. Ingress middleware extracts/creates `correlation_id`.
2. Context is bound to `AsyncLocalStorage` for request lifecycle.
3. Request start/end logs are emitted centrally.
4. Domain stage logs are emitted from service/package boundaries.
5. Logs are written to stdout in JSON (single-line per event).
6. Runtime log collector ships stdout to centralized storage.

### 4.2 Separation from audit

- `packages/audit`: keeps append-only immutable security events.
- Logging layer: emits high-cardinality operational events (latency, retries, dependency errors, lock conflicts, cache hits/misses).
- Shared key for correlation: `correlation_id` present in both streams.

## 5. Log event contract

## 5.1 Canonical envelope

All log lines use this JSON envelope:

```json
{
  "ts": "2026-02-20T01:23:45.123Z",
  "level": "info",
  "service": "broker-api",
  "env": "production",
  "event": "request.completed",
  "message": "execute request completed",
  "correlation_id": "corr_...",
  "request_id": "req_...",
  "tenant_id": "t_1",
  "workload_id": "w_1",
  "integration_id": "i_1",
  "component": "server.execute",
  "reason_code": null,
  "duration_ms": 42,
  "metadata": {}
}
```

Required keys: `ts`, `level`, `service`, `event`, `correlation_id`, `component`.  
Recommended keys: `tenant_id`, `workload_id`, `integration_id`, `reason_code`, `duration_ms`.

## 5.2 Log levels

- `debug`: development diagnostics only; disabled in production by default.
- `info`: lifecycle and success outcomes.
- `warn`: recoverable anomalies, retries, fallback prevented, policy denials.
- `error`: failed operations or unexpected faults.
- `fatal`: process-level termination path.

## 5.3 Event namespace

Use `<domain>.<action>[.<outcome>]` naming:

- `request.received`
- `request.completed`
- `request.rejected`
- `auth.mtls.verified`
- `auth.mtls.denied`
- `auth.session.verified`
- `auth.session.denied`
- `auth.dpop.verified`
- `auth.dpop.denied`
- `policy.decision`
- `ssrf.check.allowed`
- `ssrf.check.denied`
- `forwarder.execute.success`
- `forwarder.execute.failure`
- `manifest.issued`
- `dependency.redis.error`
- `dependency.postgres.error`

## 5.4 Reason code alignment

- `reason_code` must reuse API/AppError codes when available (`dpop_missing`, `session_scope_missing`, `integration_secret_unavailable`, etc).
- For internal dependency errors, use stable prefixes (`redis_*`, `postgres_*`, `crypto_*`).

## 6. Redaction and data handling

## 6.1 Never log list

Never log raw values for:

- `Authorization`, `DPoP`, cookies, session tokens, API keys.
- Secret envelopes, decrypted secret material, private keys.
- Request/response bodies in data-plane execute path.
- Full client certificates or fingerprint-adjacent sensitive fields beyond already-approved identifiers.

## 6.2 Redaction strategy

- Structured key-based redaction at logger boundary:
  - redact keys matching `*token*`, `*secret*`, `authorization`, `cookie`, `dpop`, `private_key`, `ciphertext*`, `auth_tag*`.
- Header logging policy:
  - log only header names and count by default.
  - values logged only for explicit allowlist (`content-type`, `accept`) in debug mode outside production.

## 6.3 Payload policy

- Request/response payloads are excluded by default.
- Optional debug capture requires all:
  1. non-production env,
  2. explicit feature flag,
  3. size cap,
  4. redaction pass.

## 7. Correlation context propagation

## 7.1 Ingress rules

- Source: incoming `x-correlation-id` when valid; otherwise generate UUID.
- Returned: always echo `x-correlation-id` in response.
- Stored in ALS context and used by all logging calls.

## 7.2 Cross-component propagation

- Internal package APIs accept optional `context` object containing `correlation_id`.
- Outbound HTTP requests include `x-correlation-id` when safe.
- Audit append calls include same `correlation_id`.

## 7.3 Context keys

Request context object:

- `correlation_id`
- `request_id`
- `route`
- `method`
- `tenant_id` (if resolved)
- `workload_id` (if resolved)
- `integration_id` (if resolved)

## 8. NestJS + Express integration design

## 8.1 Runtime components

1. **Logger provider** (singleton): structured JSON logger implementation.
2. **Correlation middleware** (Express): create/bind context before routing.
3. **Request logging interceptor** (Nest): emit `request.received` and `request.completed`.
4. **Exception filter hook**: emit `request.rejected` with `reason_code` and status.
5. **Package logger adapter**: thin interface for shared packages to avoid direct framework dependency.

## 8.2 Preferred stack

- Logger engine: `pino`-style structured logger (fast JSON emission).
- Context propagation: `AsyncLocalStorage`.
- Keep output to stdout; no direct vendor SDK in app runtime path.

## 9. Cross-codespace ownership and responsibilities

### `apps/broker-api`

- Own ingress context creation and request lifecycle logs.
- Emit stage logs for session/execute/manifest chain.
- Ensure every denial path logs `reason_code`.

### `apps/broker-admin-api`

- Reuse shared logger contract and correlation middleware.
- Log OIDC/session/RBAC decisions with redacted identity metadata.

### `packages/auth`

- Emit verification outcome logs via injected logger interface.
- Include DPoP replay/store outcomes without JWT content.

### `packages/policy-engine`

- Log deterministic decision summary (`decision`, `rule_id`, `action_group`, `reason_code`).
- No raw request body logging.

### `packages/ssrf-guard`

- Log destination normalization, cache hit/miss, decision code.
- Never log sensitive headers or payloads.

### `packages/forwarder`

- Log upstream execution metadata (`host`, `method`, `status_code`, `duration_ms`, body bytes count only).
- Log proxy-safety rejections and redirect denials.

### `packages/audit`

- Keep audit semantics unchanged.
- Add optional helper to emit log mirror for audit write failures and latency.

### `packages/db`

- Provide optional query timing hooks for warn/error logs on slow/failing operations.
- Avoid raw SQL or sensitive bind parameter logs.

### `packages/interceptor-node`

- Align client-side log fields (`correlation_id`, `integration_id`, `event`) with backend contract for end-to-end debugging.

### `packages/schemas`

- Add optional `log-event.schema.json` and generated TS type for envelope contract.
- Keep audit schema separate.

## 10. Performance and reliability requirements

1. Median added latency per request from logging path: <= 1 ms.
2. p99 added latency from logging path: <= 5 ms.
3. Log emission must be non-blocking for request completion.
4. Log throughput controls:
   - deduplicate noisy warnings,
   - rate-limit repeated identical error events.
5. Memory bounds: avoid unbounded buffering in app process.

## 11. Operational model

## 11.1 Transport

- Default: stdout JSON from each service.
- Collector (outside app): Fluent Bit / OpenTelemetry Collector / platform equivalent.

## 11.2 Retention and access

- Retention by environment (e.g. prod 30-90 days for ops logs).
- Access control by role; data-plane logs treated as sensitive operational data.

## 11.3 Alerting examples

- High rate of `auth.dpop.denied` by tenant/workload.
- Spike in `ssrf.check.denied` reason code families.
- Repeated `integration_secret_unavailable` in execute path.
- `audit_write_failed` warnings/errors.

## 12. Rollout plan

### Phase 0: Contract and scaffolding

- Finalize event envelope schema and reason-code policy.
- Add shared logger interface package and basic no-op adapter for tests.

Acceptance:
- All services compile against shared logger interface.

### Phase 1: broker-api ingress + lifecycle

- Add correlation middleware + ALS context.
- Add request lifecycle interceptor/filter logs.
- Add structured logs for execute/session/manifest stage boundaries.

Acceptance:
- Every `POST /v1/session`, `POST /v1/execute`, `GET /v1/workloads/{id}/manifest` has start/end logs with same `correlation_id`.

### Phase 2: package-level stage instrumentation

- Add package adapters and stage logs in auth/policy/ssrf/forwarder.
- Enforce redaction and reason-code mapping.

Acceptance:
- Pipeline stage failures always include stable `reason_code` in logs.

### Phase 3: admin-api + interceptor alignment

- Apply same envelope to admin service.
- Align interceptor-node log keys for cross-system debugging.

Acceptance:
- End-to-end flow can be traced by `correlation_id` across interceptor and broker services.

### Phase 4: hardening and SLOs

- Add log-volume controls and performance checks.
- Add dashboards/alerts on key denial and dependency-failure events.

Acceptance:
- Logging overhead SLOs met; no sensitive data leakage in sampling review.

## 13. Test and verification strategy

1. Unit tests:
- envelope schema validation,
- redaction behavior,
- reason-code mapping.

2. Integration tests:
- correlation propagation through full request path,
- log presence for success/deny/error branches.

3. Security tests:
- assert secrets/tokens do not appear in emitted logs,
- fuzz test redaction key matching.

4. Load tests:
- compare latency with and without logging enabled.

## 14. Risks and mitigations

1. Risk: log schema drift across code-spaces.  
Mitigation: central schema in `packages/schemas` + lint/test gate.

2. Risk: accidental secret leakage via ad hoc logging.  
Mitigation: mandatory logger wrapper + lint rule banning direct `console.*` in runtime paths.

3. Risk: noisy logs reduce signal quality.  
Mitigation: strict event taxonomy + rate-limited repeated warnings.

4. Risk: coupling logging to request success.  
Mitigation: non-blocking logger writes and error swallowing in logger transport layer.

## 15. Open decisions to resolve before implementation

1. Shared package name for observability utilities (`packages/observability` vs `packages/logging`).
2. Exact set of fields promoted to top-level envelope vs nested `metadata`.
3. Production log retention and PII policy by environment.
4. Whether to add optional W3C Trace Context now or in a later tracing RFC.

## 16. Definition of done

This design is considered delivered when:

1. The shared logging contract is merged and referenced by broker services.
2. `broker-api` emits structured correlation-aware lifecycle and stage logs.
3. Reason codes are aligned with API errors and audit events.
4. Redaction tests prove no secret/token leakage.
5. Operational dashboards can pivot by `correlation_id`, `tenant_id`, `workload_id`, and `reason_code`.
