# @broker-interceptor/ssrf-guard

Security-focused SSRF guard module for Broker execute pipeline (Epic 4.2, Epic 9.1, Epic 9.3).

## Scope

This package provides:

- Request-time DNS resolution for execute destinations
- Denylist enforcement for resolved IP ranges:
  - private ranges
  - loopback ranges
  - link-local ranges
  - metadata ranges
- Redirect denial guard for upstream 3xx responses in MVP
- Stable fail-closed reason codes for audit and policy wiring

## Source of truth DTOs

All request/template/headers contracts are imported from:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/schemas/openapi.yaml`
- `@broker-interceptor/schemas` exports (`OpenApiExecuteRequest`, `Template`, `OpenApiHeaderList`)

No local OpenAPI DTO re-definition is used.

## Public API

Exports from `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/ssrf-guard/src/index.ts`:

- `guardExecuteRequestDestination`
- `enforceRedirectDenyPolicy`
- `GuardExecuteRequestInputSchema`
- `GuardExecuteRequestOutputSchema`
- `GuardUpstreamResponseInputSchema`
- `DnsResolutionConfigSchema`
- `ssrfGuardErrorCodes`
- `SsrfGuardStorageBridge` (db/redis integration bridge with `_INCOMPLETE` methods)
- `createSsrfGuardStorageBridge_INCOMPLETE` (factory for app-injected repository implementations)

## Security behavior

- URL userinfo and fragments are rejected.
- Scheme/host/port are re-validated against template allowlists.
- IP-literal URLs are denied unless explicitly allowlisted in template `allowed_hosts`.
- DNS resolution is required for non-IP hosts and performed at request time.
- Any resolved destination in denied ranges causes rejection.
- Any redirect status (`300-399`) is rejected by `enforceRedirectDenyPolicy`.

## Usage

```ts
import {
  enforceRedirectDenyPolicy,
  guardExecuteRequestDestination
} from '@broker-interceptor/ssrf-guard';

const destinationCheck = await guardExecuteRequestDestination({
  input: {
    execute_request,
    template
  }
});

if (!destinationCheck.ok) {
  // map destinationCheck.error.code to API/audit reason
}

const redirectCheck = enforceRedirectDenyPolicy({
  input: {
    template,
    upstream_status_code,
    upstream_headers
  }
});

if (!redirectCheck.ok) {
  // reject redirected response
}
```

Storage bridge usage (app-owned clients/repositories, package-owned abstraction):

```ts
import {createSsrfGuardStorageBridge_INCOMPLETE} from '@broker-interceptor/ssrf-guard';

const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
  repositories: {
    getIntegrationTemplateForExecute: ({
      tenant_id,
      workload_id,
      integration_id,
      transaction_client
    }) =>
      appRepositories.integrationRepository.getIntegrationTemplateForExecute({
        tenant_id,
        workload_id,
        integration_id,
        ...(transaction_client !== undefined ? {transaction_client} : {})
      }),
    readDnsResolutionCache: ({normalized_host, context}) =>
      appRepositories.ssrfGuardRedisAdapter.readDnsResolutionCache({
        normalized_host,
        context
      }),
    upsertDnsResolutionCache: ({normalized_host, entry, context}) =>
      appRepositories.ssrfGuardRedisAdapter.upsertDnsResolutionCache({
        normalized_host,
        entry,
        context
      }),
    appendDnsRebindingObservation: ({normalized_host, observation, context}) =>
      appRepositories.ssrfGuardRedisAdapter.appendDnsRebindingObservation({
        normalized_host,
        observation,
        context
      }),
    publishTemplateInvalidationSignal: ({signal, context}) =>
      appRepositories.ssrfGuardRedisAdapter.publishTemplateInvalidationSignal({
        signal,
        context
      })
  },
  clients: {
    redis: appClients.redis
  }
});

const template = await bridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
  scope: {tenant_id, workload_id, integration_id},
  transaction_client: txClient
});
```

## `_INCOMPLETE` Tracking

### In this package

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/ssrf-guard/src/storageBridge.ts` contains db/redis dependent methods intentionally marked as `_INCOMPLETE`:
  - methods are async and support optional transaction pass-through via `transaction_client`
  - `loadActiveTemplateForExecuteFromDb_INCOMPLETE` now supports two wiring modes:
    - app-injected custom method `loadActiveTemplateForExecuteFromDb_INCOMPLETE`
    - direct db repository method `getIntegrationTemplateForExecute` (returns `null` on non-executable status or `not_found`)
  - Redis-backed methods now support direct db adapter wiring modes:
    - `readDnsResolutionCacheFromRedis_INCOMPLETE` -> `readDnsResolutionCache`
    - `writeDnsResolutionCacheToRedisMock_INCOMPLETE` -> `upsertDnsResolutionCache`
    - `appendDnsRebindingObservationToRedisMock_INCOMPLETE` -> `appendDnsRebindingObservation`
    - `publishTemplateInvalidationSignalToRedisMock_INCOMPLETE` -> `publishTemplateInvalidationSignal`
    - optional durable pre-publish hook: `persistTemplateInvalidationOutbox`
  - `listRequiredDependencies_INCOMPLETE`
  - `loadActiveTemplateForExecuteFromDb_INCOMPLETE`
  - `persistActiveTemplateForExecuteInDbMock_INCOMPLETE`
  - `readDnsResolutionCacheFromRedis_INCOMPLETE`
  - `writeDnsResolutionCacheToRedisMock_INCOMPLETE`
  - `appendDnsRebindingObservationToRedisMock_INCOMPLETE`
  - `appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE`
  - `publishTemplateInvalidationSignalToRedisMock_INCOMPLETE`

### External wiring follow-up

- Pending integration location:
  - `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/src/dependencyBridge.ts`
- Existing bridge method to extend with SSRF guard dependency declaration:
  - `listRequiredDependencies_INCOMPLETE`
- Methods expected from this package for broker execute wiring:
  - `guardExecuteRequestDestination`
  - `enforceRedirectDenyPolicy`

## Pending feedback

- Target code space: `@broker-interceptor/db`
  - Request file:
    `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/external_feedback/broker-interceptor/ssrf-guard/missing_store_data.md`
  - Waiting reason: db response received and unblocked template reads plus Redis DNS/rebinding/invalidation adapter wiring; remaining blocker is SSRF decision projection persistence and durable invalidation outbox repository contract.
  - Related `_INCOMPLETE` methods:
    - `listRequiredDependencies_INCOMPLETE`
    - `loadActiveTemplateForExecuteFromDb_INCOMPLETE`
    - `persistActiveTemplateForExecuteInDbMock_INCOMPLETE`
    - `readDnsResolutionCacheFromRedis_INCOMPLETE`
    - `writeDnsResolutionCacheToRedisMock_INCOMPLETE`
    - `appendDnsRebindingObservationToRedisMock_INCOMPLETE`
    - `appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE`
    - `publishTemplateInvalidationSignalToRedisMock_INCOMPLETE`

## Development

```bash
pnpm --filter @broker-interceptor/ssrf-guard run lint
pnpm --filter @broker-interceptor/ssrf-guard run test
pnpm --filter @broker-interceptor/ssrf-guard run test:coverage
pnpm --filter @broker-interceptor/ssrf-guard run build
```
