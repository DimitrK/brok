# @broker-interceptor/forwarder

## What This Package Does

`@broker-interceptor/forwarder` is the Broker execute-path forwarding module (Epic 4.1, 4.3, 4.5).
It receives a validated execute request, applies proxy-safe HTTP controls, forwards upstream, and returns a buffered OpenAPI-compatible response.

## Exposed Interfaces

Main exports are in `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/forwarder/src/index.ts`:

- `forwardExecuteRequest({input, fetchImpl?})`
  - Main forwarding entrypoint.
  - Input is validated by `ForwardExecuteRequestInputSchema`.
  - Output is `ForwarderResult<OpenApiExecuteResponseExecuted>`.

- `stripHopByHopHeaders(rawHeaders)`
  - Strips hop-by-hop headers and headers nominated by `Connection`.
  - Returns `ForwarderResult<OpenApiHeaderList>`.

- `validateRequestFraming({headers, body_byte_length})`
  - Rejects ambiguous/unsafe framing (`Content-Length` and `Transfer-Encoding` issues).
  - Returns `ForwarderResult<{content_length: number | null; has_transfer_encoding: boolean}>`.

- `createForwarderDbDependencyBridge_INCOMPLETE({repositories})`
  - Factory for DB wiring bridge with `_INCOMPLETE` methods for Redis/Postgres-backed forwarder persistence.
  - App injects repository implementations; this package does not create Redis/Postgres connections.
  - Tracks required DB methods and preserves fail-closed input validation for bridge calls.

- Schemas and types:
  - `ForwardExecuteRequestInputSchema`
  - `ForwarderTimeoutsSchema`
  - `ForwarderLimitsSchema`
  - `ForwardExecuteRequestInput`
  - `ForwardExecuteRequestOutput`
  - `forwarderErrorCodes`

## How To Use

```ts
import {forwardExecuteRequest} from '@broker-interceptor/forwarder'

const forwarded = await forwardExecuteRequest({
  input: {
    execute_request,
    template,
    matched_path_group_id: canonicalized.matched_path_group_id,
    injected_headers: [{name: 'authorization', value: `Bearer ${providerCredential}`}],
    response_header_allowlist: ['content-type', 'x-request-id'],
    correlation_id
  }
})

if (!forwarded.ok) {
  // map forwarded.error.code -> API error + audit reason
  return
}

const executed = forwarded.value
// executed.status === 'executed'
// executed.upstream.status_code / headers / body_base64
```

### DB Injection Model (Required)

- `@broker-interceptor/forwarder` never initializes Postgres/Redis clients.
- App processes own lifecycle:
  - create pool/client(s) once per process
  - wire repository implementations in app code
  - pass repositories into forwarder bridge factory
- `_INCOMPLETE` bridge calls support optional transaction pass-through context:
  - `bridge.<method>_INCOMPLETE(input, {transactionClient})`
  - the same transaction client is forwarded to the injected repository method

```ts
import {createForwarderDbDependencyBridge_INCOMPLETE} from '@broker-interceptor/forwarder';

const bridge = createForwarderDbDependencyBridge_INCOMPLETE({
  repositories: {
    acquireForwarderExecutionLock: db.forwarder.acquireForwarderExecutionLock,
    releaseForwarderExecutionLock: db.forwarder.releaseForwarderExecutionLock,
    createForwarderIdempotencyRecord: db.forwarder.createForwarderIdempotencyRecord,
    getForwarderIdempotencyRecord: db.forwarder.getForwarderIdempotencyRecord,
    completeForwarderIdempotencyRecord: db.forwarder.completeForwarderIdempotencyRecord,
    failForwarderIdempotencyRecord: db.forwarder.failForwarderIdempotencyRecord,
    incrementForwarderHostFailureCounter: db.forwarder.incrementForwarderHostFailureCounter,
    getForwarderHostCircuitState: db.forwarder.getForwarderHostCircuitState,
    createForwarderInflightExecutionMarker: db.forwarder.createForwarderInflightExecutionMarker,
    deleteForwarderInflightExecutionMarker: db.forwarder.deleteForwarderInflightExecutionMarker,
    setForwarderHostCooldownState: db.forwarder.setForwarderHostCooldownState,
    getForwarderHostCooldownState: db.forwarder.getForwarderHostCooldownState,
    insertForwarderIdempotencyConflict: db.forwarder.insertForwarderIdempotencyConflict,
    insertForwarderExecutionSnapshot: db.forwarder.insertForwarderExecutionSnapshot,
    queryForwarderExecutionSnapshots: db.forwarder.queryForwarderExecutionSnapshots
  }
});

const tx = await db.beginTransaction();
await bridge.createForwarderIdempotencyRecord_INCOMPLETE(payload, {transactionClient: tx});
```

## Security Behavior

- Strips hop-by-hop and `Connection`-nominated headers.
- Rejects ambiguous request framing.
- Never forwards broker/internal auth headers upstream.
- Re-validates template method/scheme/host/port before dispatch.
- Denies redirects (`3xx`) in MVP.
- Rejects streaming request/response modes in MVP.
- Buffers responses with max-size limits and allowlisted response headers only.

## Source of Truth

Contracts come from:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/schemas/openapi.yaml`
- `@broker-interceptor/schemas`

No local OpenAPI DTO re-definition is used in this package.

## `_INCOMPLETE` Tracking

- `_INCOMPLETE` methods currently exist in:
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/forwarder/src/dbDependencyBridge.ts`

Methods:

- `listRequiredDependencies_INCOMPLETE`
- `acquireForwarderExecutionLock_INCOMPLETE`
- `releaseForwarderExecutionLock_INCOMPLETE`
- `createForwarderIdempotencyRecord_INCOMPLETE`
- `getForwarderIdempotencyRecord_INCOMPLETE`
- `completeForwarderIdempotencyRecord_INCOMPLETE`
- `failForwarderIdempotencyRecord_INCOMPLETE`
- `incrementForwarderHostFailureCounter_INCOMPLETE`
- `getForwarderHostCircuitState_INCOMPLETE`
- `createForwarderInflightExecutionMarker_INCOMPLETE`
- `deleteForwarderInflightExecutionMarker_INCOMPLETE`
- `setForwarderHostCooldownState_INCOMPLETE`
- `getForwarderHostCooldownState_INCOMPLETE`
- `insertForwarderIdempotencyConflict_INCOMPLETE`
- `insertForwarderExecutionSnapshot_INCOMPLETE`
- `queryForwarderExecutionSnapshots_INCOMPLETE`
- External wiring note:
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/src/dependencyBridge.ts`
  still has `listRequiredDependencies_INCOMPLETE`.

## Feedback status

- `packages/db` feedback loop for `missing_store_data.md` is acknowledged and resolved for MVP scope.
- Forwarder sent follow-up confirmation:
  `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/external_feedback/broker-interceptor/forwarder/missing_store_data_followup.md`
- MVP DB dependency scope:
  `acquireForwarderExecutionLock`, `releaseForwarderExecutionLock`,
  `createForwarderIdempotencyRecord`, `getForwarderIdempotencyRecord`,
  `completeForwarderIdempotencyRecord`, `failForwarderIdempotencyRecord`.
- Deferred post-MVP `_INCOMPLETE` methods:
  `incrementForwarderHostFailureCounter_INCOMPLETE`, `getForwarderHostCircuitState_INCOMPLETE`,
  `createForwarderInflightExecutionMarker_INCOMPLETE`, `deleteForwarderInflightExecutionMarker_INCOMPLETE`,
  `setForwarderHostCooldownState_INCOMPLETE`, `getForwarderHostCooldownState_INCOMPLETE`,
  `insertForwarderIdempotencyConflict_INCOMPLETE`, `insertForwarderExecutionSnapshot_INCOMPLETE`,
  `queryForwarderExecutionSnapshots_INCOMPLETE`.
