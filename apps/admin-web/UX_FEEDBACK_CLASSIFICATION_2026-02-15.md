# Admin Web UX Feedback Classification (2026-02-15)

## Implemented in `apps/admin-web` (frontend-only)

1. Global layout
- Moved `Broker Admin API Base URL` and session token into a collapsible `Server settings` section at the bottom of the sidebar.
- Moved health display next to the active tenant indicator in the page header.

2. Binary state UX
- Added reusable `ToggleSwitch` component with:
  - muted gray styling for `off`
  - vibrant theme styling for `on`
- Applied toggle switch in workload and integration inline state editing.

3. User Management
- Added `Sign-in` method column (derived from issuer heuristics: `github` / `google` / `local` / `oidc`).
- Kept inline `Edit` action pattern.
- Added pending access-request counter badge on sidebar `User Management` nav item.

4. Workloads
- Converted create workload into CTA-driven flow (`New workload` opens form).
- Replaced textual enabled state with inline toggle switch.
- Row click now selects workload for enrollment flow.
- Enroll section now includes actionable CSR generation instructions with SAN URI and ready-to-run commands.
- Enrollment result already supports certificate and CA chain download actions.

5. Integrations
- Converted create integration into CTA-driven flow (`New integration`).
- Removed standalone edit form.
- Added inline table editing for template assignment and enabled state.
- Create flow uses template dropdown with explicit selection required.

6. Templates
- Converted to list-first UX with `New template` CTA.
- Reused one create/edit-in-place form (edit opens prefilled and publishes next version).

7. Policies
- Converted create policy into CTA-driven flow (`New policy`).
- Tenant field is now a dropdown with friendly name + ID.
- Integration field is now searchable via datalist-backed input with friendly label.
- Removed redundant `Active tenant scope` block from policy panel body.
- Added helper note about action-group value semantics.

## Requires backend API support

1. Workloads deletion
- Requested UX: delete workloads.
- Gap: no workload delete endpoint in current Admin API contract.
- Suggested API addition: `DELETE /v1/workloads/{workloadId}`.

2. Templates disable/delete lifecycle
- Requested UX: disable templates and delete templates.
- Gap: current template contract has no `enabled` state and no delete/update endpoints.
- Suggested API additions:
  - `PATCH /v1/templates/{templateId}` for enable/disable state
  - `DELETE /v1/templates/{templateId}` for archival/deletion policy

3. Integration create uses only enabled templates
- Requested UX: create integration template picker should include only enabled templates.
- Gap: template list does not expose enabled/disabled lifecycle metadata.
- Suggested: expose template status in template DTO/list endpoint.

4. Exact OIDC provider attribution in users list
- Requested UX: precise provider (`github/google`) per user.
- Gap: user DTO currently exposes `issuer` but not normalized provider field.
- Suggested: add `provider` enum to `AdminUser` DTO.

## Partially implemented / constrained by current contracts

1. General “list only + modal/in-place action surfaces”
- Applied to core feedback screens: Workloads, Integrations, Templates, Policies.
- Remaining panels can follow the same pattern in a subsequent UX pass.

2. Searchable dropdown behavior
- Implemented for policy integration selection with datalist.
- Native searchable select behavior is browser-limited; full combobox UX would require a dedicated component.
