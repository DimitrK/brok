# Admin Web Smoke Test Report (2026-02-14)

## Scope

Live end-to-end smoke test for `apps/admin-web` against the running local `broker-admin-api` instance.

- No request mocking was used.
- Browser automation executed with Playwright CLI wrapper.
- Goal journey: token rotation, tenant setup, secret storage path, policy definition path.

## Environment

- Admin web URL: `http://localhost:4173`
- Admin API URL: `http://localhost:8080`
- Admin auth mode: static bearer token from local `.env`
- Token used: `dev-admin-token-change-in-production`

## Validation Sequence And Results

1. Token rotation behavior
- Applied `wrong-token` and observed live `401` + UI error:
  - `admin_auth_invalid: Bearer token is invalid`
- Applied valid token and confirmed tenant query recovered without reload.
- Result: token apply flow now refreshes queries with the updated token.

2. Tenant setup
- Created tenant `tenant-alpha`.
- API returned `201`, UI selected tenant as active.
- Result: success.

3. Secret storage flow (integration creation)
- First create attempt failed with `404 template_not_found` for `tpl_openai_core_v1`.
- Uploaded template `tpl_openai_core_v1` version `1` in Templates tab (`201`).
- Retried integration create with secret payload:
  - `secret_material.type=api_key`
  - `secret_material.value=sk-live-demo-123`
- API returned `503` with UI error:
  - `db_unavailable: Database client must provide transactional execution for secret version writes`
- Result: blocked by backend dependency/wiring, not by frontend request shape.

4. Policy definition flow
- Created policy for active tenant with:
  - `rule_type=approval_required`
  - `action_group=responses_create`
  - `method=POST`
  - `host=api.openai.com`
- API returned `201`, policy row rendered in table.
- Result: success.

## Artifacts

- Screenshot (policy created): `output/playwright/admin-web-policy-created.png`
- Screenshot (integration secret store failure): `output/playwright/admin-web-integration-secret-store-503.png`
- Network trace: `.playwright-cli/network-2026-02-14T10-47-55-507Z.log`
- Console log: `.playwright-cli/console-2026-02-14T10-47-55-509Z.log`

## Notable Backend Responses Observed

- `401` on invalid admin token (expected).
- `404` on integration create before template creation (expected).
- `503 db_unavailable` on integration create after template exists (unexpected backend limitation).
- `201` on policy create (expected).
