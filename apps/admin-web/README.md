# admin-web

Single-page admin console for Broker control-plane operations.

This code space is frontend-only and consumes the existing `apps/broker-admin-api` REST API.

## Stack

- React + TypeScript
- React Router (permalink routes + guarded navigation)
- TanStack Query (server-state fetching/mutations)
- Zustand (session-persisted auth/session state)
- OpenAPI-derived DTO/Zod contracts from `@broker-interceptor/schemas`

## Scope

`admin-web` provides UI workflows for these control-plane endpoint groups:

- tenants
- workloads + enrollment
- integrations
- templates
- policies
- approvals
- audit search
- manifest key inspection

Guided builders are available for integrations, templates, policies, and approval constraints, with preset shortcuts
for common provider and policy setups.

## Routing

Public route:

- `/login`
- `/login/callback`

Protected routes:

- `/tenants`
- `/workloads`
- `/integrations`
- `/templates`
- `/policies`
- `/approvals`
- `/audit`
- `/manifest`

Unknown paths redirect to `/login` (logged out) or `/tenants` (authenticated).

## API Contract Discipline

- Request bodies are validated against OpenAPI-derived schemas before submit.
- Responses are validated against OpenAPI-derived schemas before use.
- No local hand-written API DTO copies.

Contract source of truth:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/schemas/openapi.yaml`

## Run

From repository root:

```bash
pnpm --filter @broker-interceptor/admin-web run dev
```

Build:

```bash
pnpm --filter @broker-interceptor/admin-web run build
```

Test:

```bash
pnpm --filter @broker-interceptor/admin-web run test
```

## Browser QA Runbook

For browser-driven validation (open app, snapshot UI, gather console/network logs, and take screenshots), use:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/admin-web/PLAYWRIGHT_RUNBOOK.md`
- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/admin-web/SMOKE_TEST_REPORT_2026-02-14.md`

Store screenshots and related browser artifacts under:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/output/playwright`

## Environment

- `VITE_BROKER_ADMIN_API_BASE_URL` (optional, default: `http://localhost:8080`)

Admin auth session is stored in browser `sessionStorage` (not `localStorage`) so authenticated users stay signed in on
refresh for the current browser context.

## Admin Authentication UX

- Primary login flow uses OAuth Authorization Code + PKCE against:
  - `GET /v1/admin/auth/providers`
  - `POST /v1/admin/auth/oauth/start`
  - `POST /v1/admin/auth/oauth/callback`
- Callback route is `/login/callback`.
- Session metadata and principal are refreshed through:
  - `GET /v1/admin/auth/session`
- Owner role users can toggle new-user sign-up mode through:
  - `GET /v1/admin/auth/signup-policy`
  - `PATCH /v1/admin/auth/signup-policy`
- Advanced fallback keeps direct bearer token login for static/local environments.

Connection settings are staged in the form and committed only when `Apply connection` is pressed. This updates
auth/base-url state and triggers query invalidation for fresh server data.

## Pending Feedback

Last checked: 2026-02-14

- Target code space: `apps/broker-admin-api`
- Request file:
  `apps/broker-admin-api/external_feedback/broker-interceptor/admin-web/integration_secret_write_transaction_support.md`
- Waiting reason: `POST /v1/tenants/{tenantId}/integrations` returns `503 db_unavailable` for valid secret write payloads,
  blocking the end-to-end integration secret storage flow.
- Additional contract gap for admin-web OAuth UX:
  `submitAccessRequest()` cannot call an API endpoint yet because no OpenAPI path for access request creation is
  currently defined under `/v1/admin/auth/*`.
