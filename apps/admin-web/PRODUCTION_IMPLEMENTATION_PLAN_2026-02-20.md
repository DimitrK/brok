# Admin Web Production Implementation Plan and Review (2026-02-20)

## Sources Reviewed

- `docs/TASKS_BACKLOG.md`
- `docs/RPODUCT_SPECIFICATION.md`
- `docs/admin-auth.md`
- `docs/TECH_STACK.md`
- `docs/SECURITY_ADVISORY.md`
- `apps/broker-admin-api/README.md`
- `apps/admin-web/README.md`
- `packages/schemas/openapi.yaml`
- Engineering standards:
  - `docs/development/common-engineering-rules.md`
  - `docs/development/engineering-process.md`
  - `docs/development/frontend-engineering-rules.md`
  - `docs/development/web-app-ui-ux-user-experience-rules.md`

## Analysis Summary

1. Contract-first discipline is already in place (OpenAPI DTO + Zod parsing in API client).
2. Admin auth flow had a production gap:
- `POST /v1/admin/auth/logout` existed in OpenAPI but was not wired in admin-web sign-out behavior.
3. API boundary hardening gap:
- user-supplied API base URLs could fail with runtime URL errors rather than deterministic typed client errors.
4. OAuth callback UX gap:
- signup-blocked flow exposed a `Request access` action that is not contract-backed (no OpenAPI endpoint for request creation).
5. Cross-code-space status drift:
- `apps/admin-web/README.md` pending feedback section did not reflect latest broker-admin-api response status.

## Implementation Plan

1. Add logout endpoint wiring and session invalidation handling in `admin-web`.
2. Harden API base URL boundary handling with stable fail-closed errors.
3. Remove contract-incompatible OAuth callback action and replace with deterministic guidance.
4. Extend tests for new client behavior.
5. Update `apps/admin-web/README.md` pending feedback and API notes.
6. Run lint, tests, and build.

## Implemented Changes

- `apps/admin-web/src/api/client.ts`
  - Added `resolveRequestUrl(...)` with strict URL/protocol validation and stable `invalid_base_url` errors.
  - Added `logoutAdminSession()` for `POST /v1/admin/auth/logout`.

- `apps/admin-web/src/App.tsx`
  - Sign-out now attempts server-side logout before local session purge.
  - Added explicit handling for ignorable logout errors (`401`, legacy `404 route_not_found`).

- `apps/admin-web/src/features/auth/AdminOAuthCallbackPage.tsx`
  - Removed unusable access-request submit action from callback flow.
  - Added explicit messaging for `admin_access_request_pending` and signup-closed states.
  - Clears pending OAuth state on callback failure to avoid stale state reuse.

- `apps/admin-web/src/api/client.test.ts`
  - Added fail-closed test for invalid base URL.
  - Added logout endpoint test (path, method, auth header).

- `apps/admin-web/README.md`
  - Updated contract source/runbook paths to current repository.
  - Documented logout endpoint usage and access-request contract gap.
  - Updated pending feedback status from broker-admin-api responses.

## Verification

Executed from repo root:

1. `pnpm --filter @broker-interceptor/admin-web run lint` -> PASS
2. `pnpm --filter @broker-interceptor/admin-web run test` -> PASS
3. `pnpm --filter @broker-interceptor/admin-web run build` -> PASS

Test summary:

- 3 test files passed
- 17 tests passed

## Review Findings

No blocking defects found in the implemented frontend scope.

Residual external dependencies:

1. Access-request creation remains blocked by missing OpenAPI endpoint contract.
2. Integration secret-write fix from `broker-admin-api` response still requires live end-to-end revalidation from `admin-web` smoke run.
