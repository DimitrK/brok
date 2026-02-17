# User Management Smoke Report (2026-02-15)

## Scope
`apps/admin-web` new `User Management` screen:
- Access onboarding controls moved from connection area.
- Admin user listing and update flow.
- Access request review and resolution flow.
- Mobile navigation/menu access and responsive rendering.

## Environment
- Frontend: `http://localhost:4173`
- API: `http://localhost:8080` (live running service)
- Auth mode used: static owner token (`dev-admin-token-change-in-production`)

## Validation Steps and Results
1. Login and route access
- Opened `/users`, authenticated via advanced token sign-in.
- Result: redirected to authenticated `User Management` route.

2. Access onboarding relocation
- Verified signup policy card is rendered on `User Management` panel.
- Toggled `Allow new users` then restored `Block new users`.
- Result: both PATCH operations returned `200`, mode reflected immediately.

3. User role/scope management
- Opened editor for existing admin identity.
- Added `auditor` role and saved (`PATCH /v1/admin/users/{identityId}` => `200`).
- Reverted to original role set and saved (`200`).
- Result: role changes persisted and reverted correctly.

4. Access request queue
- Opened pending request review and approved it (`POST /v1/admin/access-requests/{requestId}/approve` => `200`).
- Result: pending queue updated; request removed from pending filter.

5. Responsive + side menu access
- Verified mobile viewport (`390x844`) with `Menu` button present.
- Opened and closed sidebar navigation from mobile controls.
- Result: menu actions accessible on small viewport.

## Observations
- Network traces include transient `net::ERR_ABORTED` entries during route/query transitions; corresponding successful retries return `200` and UI state is consistent.
- No browser console errors reported in final pass.

## Artifacts
Screenshots:
- `output/playwright/user-management-desktop-2026-02-15.png`
- `output/playwright/user-management-desktop-final-2026-02-15.png`
- `output/playwright/user-management-mobile-2026-02-15.png`
- `output/playwright/user-management-mobile-final-2026-02-15.png`

Logs:
- `.playwright-cli/network-2026-02-15T12-38-12-601Z.log`
- `.playwright-cli/console-2026-02-15T12-38-12-581Z.log`
