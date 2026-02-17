# User Management Delivery Plan (Broker Admin)

Date: 2026-02-15
Owner code space: `apps/admin-web`

## Goal
Add a production-ready user management experience so owner/admin users can:
- Control admin signup policy.
- Manage existing admin identities (status, roles, tenant scopes).
- Review and resolve admin access requests.

## Cross-Codespace Requirements

### 1. `packages/schemas` (contract gate)
Status: Completed by upstream team (required DTOs present).

Required OpenAPI endpoints:
- `GET /v1/admin/users`
- `PATCH /v1/admin/users/{identityId}`
- `GET /v1/admin/access-requests`
- `POST /v1/admin/access-requests/{requestId}/approve`
- `POST /v1/admin/access-requests/{requestId}/deny`

Required DTOs:
- `OpenApiAdminUser`
- `OpenApiAdminUserListResponse`
- `OpenApiAdminUserUpdateRequest`
- `OpenApiAdminAccessRequest`
- `OpenApiAdminAccessRequestListResponse`
- `OpenApiAdminAccessRequestApproveRequest`
- `OpenApiAdminAccessRequestDenyRequest`

### 2. `packages/db`
Status: Assumed completed by upstream team.

Hard invariants expected at repository layer:
- prevent disabling/demoting the last active owner.
- enforce tenant scope validity.
- atomic approve/deny transitions.
- deterministic normalization for role/scope ordering.

### 3. `apps/broker-admin-api`
Status: Assumed completed by upstream team for this UI integration.

Behavior required by UI:
- RBAC guardrails (`owner` full; `admin` tenant-scoped only).
- clear structured validation errors with correlation id.
- idempotent approve/deny responses and conflict signaling.
- audit emission for all mutations.

### 4. `apps/admin-web` (this code space)
Status: Implemented in this deliverable.

Deliverables:
- New routed screen: `User Management`.
- Moved `Access Onboarding` controls from connection strip into `User Management`.
- Added user list filters and identity editor (status/roles/tenant assignments).
- Added access request queue and approve/deny review workflow.
- Added frontend guardrails mirroring backend restrictions (non-owner cannot grant owner or outside tenant scope).
- Responsive behavior for tables/editors on small screens.

## Security and Behavior Rules (UI + API contract)
- Non-owner cannot grant `owner` role.
- Tenant-scoped admin actions are constrained to actor tenant scope in UI.
- Last-owner lockout is proactively guarded in UI and enforced by backend.
- Update operations are explicit replacement sets (`status`, `roles`, `tenant_ids`).
- Error payloads are shown verbatim to operators for corrective action.

## Validation Plan (admin-web)
1. Static verification:
- `pnpm --filter @broker-interceptor/admin-web lint`
- `pnpm --filter @broker-interceptor/admin-web test`
- `pnpm --filter @broker-interceptor/admin-web build`

2. Browser smoke tests against live API:
- login with owner/admin accounts.
- toggle signup mode from User Management panel.
- edit user roles/tenants and confirm persistence.
- approve and deny access requests with validation messages.
- verify responsive behavior (desktop and narrow mobile viewport).

## Non-Goals
- No contract/schema/backend mutations in this code space.
- No endpoint mocking for smoke validation.
