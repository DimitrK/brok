# Pre-Implementation Review: SPA Plan (`apps/admin-web`)

## Reviewed Inputs

- `docs/TASKS_BACKLOG.md`
- `docs/RPODUCT_SPECIFICATION.md`
- `docs/admin-auth.md`
- `docs/TECH_STACK.md`
- `docs/SECURITY_ADVISORY.md`
- `docs/development/common-engineering-rules.md`
- `docs/development/engineering-process.md`
- `docs/development/frontend-engineering-rules.md`
- `docs/development/frontend-react-rules.md`
- `skills/software-engineering-guardrails/SKILL.md`

## Findings

1. Frontend-only boundary: PASS
   - Plan keeps backend service in `apps/broker-admin-api` and treats `apps/admin-web` as SPA client.
2. Contract discipline: PASS
   - Plan enforces OpenAPI-derived DTO/Zod usage from shared schemas.
3. Security posture: PASS
   - Token is memory-only, input/response parsing is strict, and network access is centralized.
4. Scope completeness: PASS
   - Endpoint groups required for control-plane workflows are included.
5. Operational readiness: PASS
   - Lint/test/build gates are defined.

## Risks + Mitigations

1. Risk: contract drift if UI assumes backend shape.
   - Mitigation: runtime schema parsing on every API response and typed request validation.
2. Risk: tenant context mistakes across tabs.
   - Mitigation: shared selected-tenant state and query-key scoping by tenant.
3. Risk: secret/token leakage in browser persistence.
   - Mitigation: keep token in Zustand memory state only.

## Decision

Go.

Plan is implementation-ready and compliant with the code-space constraint.
