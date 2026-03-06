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
Integrations now support typed `aws_sigv4` secret material with dedicated fields for access key id, secret access key,
optional session token, and region.
Template path groups now support typed S3 SigV4 upstream-auth constraints and include a helper preset for bucket-root
list-object coverage used by backup-workload flows.
Audit workflow now supports selecting failing events and drafting template contracts with prefilled traits.
Template editor includes template-level and per-path-group cURL request checks for fast regex/method/host validation.
Audit events list now uses a reusable `VirtualizedInfiniteTable` (12-row viewport, virtualized rows, infinite load on
scroll, end-of-list indicator) plus reusable cursor-page fetch composition (`useCursorInfiniteQuery`) backed by
`/v1/audit/events?limit=&cursor=`.
Primary table-based management panels also use a reusable `MobileEntityList` pattern on small screens, where each row is
presented as a tap target that opens a focused detail view with entry-specific actions/forms.

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

- `packages/schemas/openapi.yaml`

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

- `apps/admin-web/PLAYWRIGHT_RUNBOOK.md`
- `apps/admin-web/SMOKE_TEST_REPORT_2026-02-14.md`

Store screenshots and related browser artifacts under:

- `output/playwright`

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
- Sign-out calls:
  - `POST /v1/admin/auth/logout` and expects `204`; client must discard bearer session credentials immediately.
- Owner role users can toggle new-user sign-up mode through:
  - `GET /v1/admin/auth/signup-policy`
  - `PATCH /v1/admin/auth/signup-policy`
- OAuth access-request-required journey now wires access-request endpoints:
  - `POST /v1/admin/access-requests`
  - `GET /v1/admin/access-requests/{requestId}`
- OAuth callback page attempts request submission when the backend includes an unresolved OAuth session token in callback
  error headers.
- Advanced fallback keeps direct bearer token login for static/local environments.

Connection settings are staged in the form and committed only when `Apply connection` is pressed. This updates
auth/base-url state and triggers query invalidation for fresh server data.

## S3-Compatible Authoring

- Integrations route:
  - choose `secret type = aws_sigv4`
  - provide `access key id`, `secret access key`, optional `session token`, and `region`
- Templates route:
  - path groups can set `upstream auth = aws_sigv4 (S3)`
  - optional SigV4 region override is serialized into template constraints
  - `Add S3 list path group` scaffolds bucket-root list support for `GET /?list-type=2...`
- This UI matches the OpenAPI DTO contract from `packages/schemas/openapi.yaml`; no manual JSON secret payloads are
  required in the browser.

## Pending Feedback

Last checked: 2026-03-02

- None.
