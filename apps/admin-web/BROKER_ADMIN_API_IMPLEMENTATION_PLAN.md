# Admin Web Implementation Plan (`apps/admin-web`)

## 1. Objective

Deliver a production-ready SPA in `apps/admin-web` that consumes the existing broker admin REST API (`apps/broker-admin-api`) without changing other code spaces.

## 2. Constraints

- Code changes only in `apps/admin-web`.
- No backend implementation merge into this code space.
- API interfaces must use DTO/Zod schemas from `@broker-interceptor/schemas` (OpenAPI source).

## 3. Architecture

1. `api/client.ts`
   - Centralized typed REST client.
   - Bearer-token header support.
   - Structured error mapping and correlation propagation.
   - Request/response contract validation using OpenAPI-derived schemas.
2. Zustand store (`store/adminStore.ts`)
   - In-memory token, selected tenant, active tab.
   - No localStorage persistence for sensitive token material.
3. TanStack Query
   - Query/mutation lifecycle for each endpoint group.
   - Explicit query keys and invalidation strategy.
4. Feature modules
   - Tenants
   - Workloads/enrollment
   - Integrations
   - Templates
   - Policies
   - Approvals
   - Audit
   - Manifest keys

## 4. Endpoint Coverage

The SPA consumes these API groups from `broker-admin-api`:

- `POST/GET /v1/tenants`
- `POST/GET /v1/tenants/{tenantId}/workloads`
- `POST /v1/workloads/{workloadId}/enroll`
- `PATCH /v1/workloads/{workloadId}`
- `POST/GET /v1/tenants/{tenantId}/integrations`
- `PATCH /v1/integrations/{integrationId}`
- `POST/GET /v1/templates`
- `GET /v1/templates/{templateId}/versions/{version}`
- `POST/GET /v1/policies`
- `DELETE /v1/policies/{policyId}`
- `GET /v1/approvals`
- `POST /v1/approvals/{approvalId}/approve`
- `POST /v1/approvals/{approvalId}/deny`
- `GET /v1/audit/events`
- `GET /v1/keys/manifest`
- `GET /healthz`

## 5. Security and Quality Requirements

- Fail-closed API boundary parsing with shared schemas.
- Memory-only admin token handling.
- No untrusted HTML rendering.
- Centralized network layer (no scattered ad-hoc fetch usage).
- Structured error surfaces for operator debugging.

## 6. Verification Plan

- `pnpm --filter @broker-interceptor/admin-web run lint`
- `pnpm --filter @broker-interceptor/admin-web run test`
- `pnpm --filter @broker-interceptor/admin-web run build`

## 7. Deliverables

- Vite-based React SPA with modular feature panels.
- REST client + shared query/filter schema helpers.
- Unit tests for API contract enforcement and state behavior.
- Updated `apps/admin-web/README.md` with API usage and pending-feedback status.
