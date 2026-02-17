# Admin Web Productization Review (2026-02-14)

## Summary

`apps/admin-web` was upgraded from prototype-style single-view tooling into a route-based admin console with a dedicated login experience, persistent authenticated session on refresh, and guided form-driven workflows.

## Implemented Changes

1. Authentication and session UX
- Added dedicated admin login route: `/login`.
- Added protected route guard for admin sections.
- Persisted auth session to `sessionStorage` via Zustand `persist` middleware.
- Added explicit `Sign out` action clearing local session state and query cache.

2. Routing and permalinks
- Added React Router route tree with direct permalinks:
  - `/tenants`, `/workloads`, `/integrations`, `/templates`, `/policies`, `/approvals`, `/audit`, `/manifest`.
- Added default redirects:
  - unauthenticated -> `/login`
  - authenticated root/unknown -> `/tenants`.

3. UI productization
- Replaced tab-only shell with sidebar navigation + page-level headers.
- Added polished login card and responsive layout.
- Added favicon and router future flags to eliminate dev-console warnings.

4. Guided form workflows
- Integrations: replaced free-form JSON with provider/name/template/secret typed form + presets.
- Templates: replaced free-form JSON with structured builder + presets.
- Policies: replaced free-form JSON with structured policy builder + presets + conditional rate-limit fields.
- Approvals: replaced free-form JSON constraints with explicit optional constraint fields.

## Contract And Security Review

- OpenAPI DTO discipline preserved: all create/update requests still parse with shared Zod schemas from `@broker-interceptor/schemas` before API calls.
- Auth token storage is not persisted in `localStorage`; session persistence uses `sessionStorage` only.
- Existing fail-closed error handling behavior from API client remains unchanged.

## Verification

Static checks:
- `pnpm --filter @broker-interceptor/admin-web lint`
- `pnpm --filter @broker-interceptor/admin-web test`
- `pnpm --filter @broker-interceptor/admin-web build`

Browser checks (no mocks):
- Verified login flow (`/login` -> `/tenants`) using real token.
- Verified permalink navigation (`/policies`, `/integrations`, `/templates`).
- Verified session survives hard refresh on protected route.
- Verified clean console on fresh login load (no warnings/errors).

## Artifacts

- Screenshot: `output/playwright/admin-web-productized-login.png`
- Screenshot: `output/playwright/admin-web-productized-templates.png`
- Snapshot: `.playwright-cli/page-2026-02-14T15-19-10-753Z.yml`
- Snapshot: `.playwright-cli/page-2026-02-14T15-19-25-075Z.yml`
- Snapshot: `.playwright-cli/page-2026-02-14T15-20-10-851Z.yml`
- Console (clean check): `.playwright-cli/console-2026-02-14T15-22-04-625Z.log`
- Console (clean check): `.playwright-cli/console-2026-02-14T15-22-05-563Z.log`

## Known External Dependency Blocker

Unchanged from prior smoke test:
- Integration creation with valid secret payload is still blocked by backend `503 db_unavailable` in `broker-admin-api`.
- Pending request tracked at:
  - `apps/broker-admin-api/external_feedback/broker-interceptor/admin-web/integration_secret_write_transaction_support.md`
