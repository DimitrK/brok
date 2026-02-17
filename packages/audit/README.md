# @broker-interceptor/audit

Audit package for Epic 6.1 and 6.2.

## Short Description

This package handles broker audit concerns end-to-end:

- append-only audit event emission
- tenant-aware redaction before persistence
- OpenAPI-aligned audit search filtering
- structured redacted log payload generation

## Exposed Interface Details

Service:

- `createAuditService(dependencies)`
- `AuditService.appendAuditEvent({event})`
- `AuditService.queryAuditEvents({query})`

Admin auth-policy audit helpers:

- `createAdminAuthPolicyAuditEmitter(audit)`
- `appendAdminLoginSucceededAuditEvent({audit, input, db_context})`
- `appendAdminLoginFailedAuditEvent({audit, input, db_context})`
- `appendAdminSignupModeChangedAuditEvent({audit, input, db_context})`
- `appendAdminAccessRequestCreatedAuditEvent({audit, input, db_context})`
- `appendAdminAccessRequestApprovedAuditEvent({audit, input, db_context})`
- `appendAdminAccessRequestDeniedAuditEvent({audit, input, db_context})`

Store:

- `createInMemoryAuditStore()`
- `createPersistentAuditStore_INCOMPLETE(dependencies)` (app-injected Postgres + optional Redis adapters)

Redaction:

- `createDefaultAuditRedactionProfile({tenant_id})`
- `redactAuditEvent({event, profile})`
- `redactStructuredLogPayload({payload, profile})`
- `toStructuredAuditLogRecord({event, delivery_status})`

Search model:

- `AuditEventSearchQuerySchema`
- `normalizeAuditEventSearchFilter(rawQuery)`
- `buildAuditSearchPredicate(filter)`
- `filterAuditEvents({events, filter})`

Contracts and errors:

- `AuditAppendEventInputSchema`, `AuditAppendEventResultSchema`
- `AuditQueryEventsInputSchema`, `AuditQueryEventsResultSchema`
- `AuditRedactionProfileSchema`
- `auditErrorCodes`

## How To Use

```typescript
import {createAuditService, createInMemoryAuditStore} from '@broker-interceptor/audit'

const audit = createAuditService({
  store: createInMemoryAuditStore(),
  resolveRedactionProfile: async ({tenant_id}) => {
    // Optional: load tenant profile from control-plane storage.
    // Return null to use strict default profile.
    return null
  }
})

const appendResult = await audit.appendAuditEvent({
  event,
  db_context: {transaction_client}
})
if (!appendResult.ok) {
  throw new Error(`${appendResult.error.code}: ${appendResult.error.message}`)
}

const queryResult = await audit.queryAuditEvents({
  query: {
    tenant_id: 't_1',
    decision: 'denied'
  },
  db_context: {transaction_client}
})
if (!queryResult.ok) {
  throw new Error(`${queryResult.error.code}: ${queryResult.error.message}`)
}

const events = queryResult.value.events
```

Admin auth-policy emission example:

```typescript
import {
  createAdminAuthPolicyAuditEmitter,
  createAuditService,
  createPersistentAuditStore_INCOMPLETE
} from '@broker-interceptor/audit'

const auditService = createAuditService({
  store: createPersistentAuditStore_INCOMPLETE({
    postgres_repository,
    redis_cache_repository
  }),
  resolveRedactionProfile: createAuditRedactionProfileResolverFromDb_INCOMPLETE({
    postgres_repository
  })
})

const adminAudit = createAdminAuthPolicyAuditEmitter(auditService)

await adminAudit.appendAdminLoginSucceededAuditEvent({
  input: {
    event_id: 'evt_admin_login_1',
    timestamp: '2026-02-14T12:00:00.000Z',
    tenant_id: 'tenant_1',
    correlation_id: 'corr_admin_1',
    actor_subject: 'sub_admin_1',
    actor_email: 'owner@example.com',
    provider: 'google'
  },
  db_context: {transaction_client}
})
```

## Dependency Injection And Transactions

- This package **does not create Postgres or Redis clients**.
- Apps must create/process-manage clients and pass repository implementations into audit factories.
- For shared cross-package transactions, apps should pass an explicit `db_context` down the call chain.

Current pass-through points:

- `AuditService.appendAuditEvent({event, db_context})`
- `AuditService.queryAuditEvents({query, db_context})`
- `AuditStoreAdapter.appendAuditEvent({event, db_context})`
- `AuditStoreAdapter.queryAuditEvents({filter, db_context})`
- `RedisAuditCacheAdapter.getJson/setJson/deleteByPrefix(..., db_context)`
- `createAuditRedactionProfileResolverFromDb_INCOMPLETE() -> ({tenant_id, db_context})`

## Source Of Truth

This package must use DTO/runtime contracts from:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/schemas/openapi.yaml`
- `@broker-interceptor/schemas`

Do not redefine audit DTOs locally.

## Pending feedback

No active pending feedback requests.

Latest resolved DB response:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/external_feedback/broker-interceptor/audit/archive/missing_store_data_response_1.md`

Phase-2 note:

- Delivery-status lifecycle persistence (`stored|queued|delivered|failed`) is confirmed as phase-2 in DB response and is not blocking current package integration.

## `_INCOMPLETE` Tracking

Current incomplete methods inside this package:

1. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `appendAuditEventInPostgres_INCOMPLETE` (operational via injected adapters; suffix kept for cross-team tracking)
2. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `queryAuditEventsFromPostgres_INCOMPLETE` (operational via injected adapters; suffix kept for cross-team tracking)
3. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `getAuditRedactionProfileByTenantFromPostgres_INCOMPLETE` (operational with DB repository `getAuditRedactionProfileByTenant({tenant_id, db_context?})`)
4. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `readAuditQueryCacheFromRedis_INCOMPLETE` (operational when Redis adapter is injected)
5. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `writeAuditQueryCacheToRedis_INCOMPLETE` (operational when Redis adapter is injected)
6. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `invalidateAuditQueryCacheByTenantFromRedis_INCOMPLETE` (operational when Redis adapter is injected)
7. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `createPersistentAuditStore_INCOMPLETE` (operational; only delivery-status lifecycle remains phase-2)
8. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/audit/src/store.ts` -> `createAuditRedactionProfileResolverFromDb_INCOMPLETE` (operational with DB repository profile methods)

External wiring still pending:

1. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` -> `appendAuditEventWithAuditPackage_INCOMPLETE`
2. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-admin-api/src/dependencyBridge.ts` -> `listRequiredDependencies_INCOMPLETE`
3. `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/src/dependencyBridge.ts` -> `listRequiredDependencies_INCOMPLETE`

## Development

```bash
pnpm --filter @broker-interceptor/audit run lint
pnpm --filter @broker-interceptor/audit run test
pnpm --filter @broker-interceptor/audit run build
```
