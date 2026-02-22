# `packages/db` Ticket: SSRF Decision Projection Persistence Returns `unexpected_error`

Date: 2026-02-20  
Owner reporting: `apps/broker-api` (data plane)  
Target owner: `packages/db`

## Problem Statement

During successful `POST /v1/execute` flows, SSRF decision projection persistence intermittently fails in DB repository wiring:

- Broker request still completes with `200`
- SSRF projection append emits warning:
  - `event=repository.persistence.warning`
  - `stage=ssrf_decision_projection_allowed`
  - `reason_code=DbRepositoryError`
  - `metadata.error_code=unexpected_error`

Security enforcement remains correct; durability of SSRF decision telemetry is degraded.

## Production-Like Evidence (Captured Log)

```json
{"ts":"2026-02-20T23:25:23.876Z","level":"warn","service":"broker-api","env":"development","event":"repository.persistence.warning","component":"repository.persistence","message":"Non-blocking persistence operation failed (ssrf_decision_projection_allowed)","correlation_id":"6990db11-ec04-494f-9fd2-6e6cb548c792","request_id":"3170f65d-7ede-444c-bb1e-6ffd3dc5f0d5","tenant_id":"t_71c9bcbf9476495c844658bf1b4c686d","workload_id":"w_92f9f2dc4b3f4e10a026a4e7063b3850","integration_id":"int_c31a3116ae854b1db295ef15518bcb16","reason_code":"DbRepositoryError","route":"/v1/execute","method":"POST","metadata":{"warning_code":"BROKER_API_PERSISTENCE_WARNING","stage":"ssrf_decision_projection_allowed","error_name":"DbRepositoryError","error_code":"unexpected_error","error_message":"Unexpected database error","diagnostic_probe":"insert_succeeded_rollback_forced"}}
```

## Key Diagnostic Finding

`diagnostic_probe=insert_succeeded_rollback_forced` proved:

1. Same projection payload can be inserted directly through Prisma (rollback transaction).
2. DB schema and row-level constraints are valid for this event.
3. Failure is specific to repository operation path in `packages/db`, not the persisted data shape.

## Likely Root Cause

In:

- `packages/db/src/repositories/auditEventRepository.ts`

`appendSsrfGuardDecisionProjection(...)` uses:

- `ssrfGuardDecision.upsert(..., update: {})`

This operation appears to fail under current runtime/client behavior and gets remapped to:

- `DbRepositoryError('unexpected_error', 'Unexpected database error')`

## Requested Change

Replace SSRF projection write logic with a deterministic idempotent flow that avoids empty-update `upsert` behavior:

1. `create` by `event_id`
2. On unique conflict:
   - `findUnique(eventId)`
   - if same payload: return success (idempotent replay)
   - if different payload: throw `DbRepositoryError('conflict', ...)`

## Acceptance Criteria

1. Valid SSRF projection append no longer returns `unexpected_error`.
2. Duplicate same `event_id` + same payload is idempotent success.
3. Duplicate same `event_id` + different payload returns `conflict`.
4. Unit tests added in `packages/db` for all above branches.

## Security/Operational Impact

- No SSRF bypass introduced by this issue.
- Reduced forensics and analytics fidelity while warning is present.
- Should be prioritized due to security telemetry correctness.
