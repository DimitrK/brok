# @broker-interceptor/interceptor-node

Node.js request interceptor that routes protected outbound HTTP/HTTPS calls through the Broker `/v1/execute` API.

## Features

- Intercepts `http.request`, `https.request`, and `fetch`.
- Supports zero-code preload mode with `--import`.
- Propagates preload and broker env to Node child processes.
- Supports:
  - static session token mode
  - mTLS session auto-acquisition and refresh mode
- Enforces signed manifest validation before applying match rules.
- Provides runtime failure policy controls via `manifestFailurePolicy`.

## Installation

```bash
pnpm add @broker-interceptor/interceptor-node
```

## Requirements

- Node.js 20+.
- Broker endpoints available:
  - `/v1/session` (when using mTLS auto session mode)
  - `/v1/workloads/{workloadId}/manifest`
  - `/v1/keys/manifest`
  - `/v1/execute`

## Quick Start

### Scenario 1: Programmatic + mTLS auto session (recommended)

Use this when you want automatic session acquisition/refresh.

```ts
import {initializeInterceptor, shutdownInterceptor} from '@broker-interceptor/interceptor-node';

const initResult = await initializeInterceptor({
  brokerUrl: 'https://broker.example.com',
  workloadId: 'w_123',
  mtlsCertPath: '/abs/path/workload.crt',
  mtlsKeyPath: '/abs/path/workload.key',
  mtlsCaPath: '/abs/path/ca-chain.pem',
  manifestFailurePolicy: 'use_last_valid'
});

if (!initResult.ok) {
  throw new Error(initResult.error);
}

// app logic...

shutdownInterceptor();
```

### Scenario 2: Programmatic + static session token

Use this when token lifecycle is managed externally.

```ts
import {initializeInterceptor} from '@broker-interceptor/interceptor-node';

const initResult = await initializeInterceptor({
  brokerUrl: 'https://broker.example.com',
  workloadId: 'w_123',
  sessionToken: 'sess_xxx',
  manifestFailurePolicy: 'use_last_valid'
});

if (!initResult.ok) {
  throw new Error(initResult.error);
}
```

### Scenario 2b: Programmatic + explicit integration override

Use this when more than one broker integration can match the same outbound endpoint and the workload must pin a specific `integration_id`.

```ts
import {initializeInterceptor} from '@broker-interceptor/interceptor-node';

const initResult = await initializeInterceptor({
  brokerUrl: 'https://broker.example.com',
  workloadId: 'w_123',
  sessionToken: 'sess_xxx',
  integrationOverrides: [
    {
      integrationId: 'int_backup_primary',
      match: {
        hosts: ['bucket.s3.example.com'],
        path_groups: ['/'],
        schemes: ['https'],
        ports: [443]
      }
    }
  ]
});

if (!initResult.ok) {
  throw new Error(initResult.error);
}
```

Use overrides only for narrow request scopes. If an override matches a request but the current manifest does not authorize that `integration_id` for the same URL, the interceptor fails closed instead of falling back to another integration.

### Scenario 3: Zero-code preload (NODE_OPTIONS)

Use this when you cannot modify app code.

```bash
export BROKER_URL=https://broker.example.com
export BROKER_WORKLOAD_ID=w_123
export BROKER_MTLS_CERT_PATH=/abs/path/workload.crt
export BROKER_MTLS_KEY_PATH=/abs/path/workload.key
export BROKER_MTLS_CA_PATH=/abs/path/ca-chain.pem
export BROKER_MANIFEST_FAILURE_POLICY=use_last_valid

export NODE_OPTIONS="--import=@broker-interceptor/interceptor-node/preload"
node app.js
```

### Scenario 4: Local manifest file

Use this when manifest is distributed out-of-band and you still want signature verification.

```bash
export BROKER_URL=https://broker.example.com
export BROKER_WORKLOAD_ID=w_123
export BROKER_SESSION_TOKEN=sess_xxx
export BROKER_MANIFEST_PATH=/abs/path/manifest.json
export NODE_OPTIONS="--import=@broker-interceptor/interceptor-node/preload"
node app.js
```

`/v1/keys/manifest` is still required so the manifest signature can be verified.

## Configuration

| Option | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `brokerUrl` | `string` | Yes | - | Broker base URL |
| `workloadId` | `string` | Yes | - | Workload identity used for manifest endpoint |
| `sessionToken` | `string` | No* | - | Static session token |
| `mtlsCertPath` | `string` | No* | - | Absolute path |
| `mtlsKeyPath` | `string` | No* | - | Absolute path |
| `mtlsCaPath` | `string` | No | - | Absolute path |
| `manifestPath` | `string` | No | - | Absolute local manifest path |
| `sessionTtlSeconds` | `number` | No | `3600` | Auto-session requested TTL |
| `manifestRefreshIntervalMs` | `number` | No | `300000` | Manifest refresh interval |
| `failOnManifestError` | `boolean` | No | `true` | If `true`, initialization fails on manifest fetch/verify error |
| `manifestFailurePolicy` | `'use_last_valid' \| 'fail_closed' \| 'fail_open'` | No | `'use_last_valid'` | Runtime behavior when refresh fails |
| `integrationOverrides` | `Array<{integrationId, match}>` | No | - | Deterministic `integration_id` selection for specific request scopes |
| `logger` | `Logger` | No | console | `{debug, info, warn, error}` |

\* Provide either `sessionToken` OR (`mtlsCertPath` + `mtlsKeyPath`).

### Preload environment variable mapping

- `BROKER_URL` -> `brokerUrl`
- `BROKER_WORKLOAD_ID` -> `workloadId`
- `BROKER_SESSION_TOKEN` -> `sessionToken`
- `BROKER_MTLS_CERT_PATH` -> `mtlsCertPath`
- `BROKER_MTLS_KEY_PATH` -> `mtlsKeyPath`
- `BROKER_MTLS_CA_PATH` -> `mtlsCaPath`
- `BROKER_MANIFEST_PATH` -> `manifestPath`
- `BROKER_SESSION_TTL_SECONDS` -> `sessionTtlSeconds`
- `BROKER_MANIFEST_REFRESH_MS` -> `manifestRefreshIntervalMs`
- `BROKER_FAIL_ON_MANIFEST_ERROR` -> `failOnManifestError`
- `BROKER_MANIFEST_FAILURE_POLICY` -> `manifestFailurePolicy`
- `BROKER_LOG_LEVEL` -> logger level (`debug`, `info`, `silent`)

## Runtime Behavior and Errors

- `use_last_valid` (default):
  - keep routing with the last verified manifest while unexpired
  - once expired and refresh is unavailable, protected traffic is blocked
- `fail_closed`: block protected traffic immediately when manifest is unavailable.
- `fail_open`: pass through when manifest is unavailable/expired.

- `ApprovalRequiredError`: broker returned `202 approval_required`.
- `RequestDeniedError`: broker returned policy denial (`400/403` OpenAPI error payload).
- `ManifestUnavailableError`: manifest is unavailable/expired under active failure policy.
- invalid integration override match: request fails closed with an error instead of falling back to a different manifest match.

## Explicit Integration Overrides

- Use `integrationOverrides` only when manifest URL matching is not enough to choose the intended broker integration.
- Each override defines:
  - `integrationId`
  - `match.hosts`
  - `match.path_groups`
  - optional `match.schemes` and `match.ports`
- Override matching uses the same host/path semantics as manifest matching.
- Hosts must be exact. Wildcards are rejected.
- Path groups support exact paths, prefix patterns like `/x/*`, and anchored regex patterns like `^/x/.*$`.
- If more than one override matches the same request, the request is blocked.
- If an override references an integration missing from the manifest, initialization fails.
- If an override matches a request but no manifest rule for that `integration_id` matches the URL, the request is blocked.
- Workloads without `integrationOverrides` keep the existing transparent first-match manifest behavior.
- Preload-only configuration does not currently expose `integrationOverrides`; use programmatic initialization when deterministic integration selection is required.

## Child process propagation

- Child Node processes receive broker env vars and preload injection via `NODE_OPTIONS`.
- Existing `NODE_OPTIONS` values are preserved.
- duplicate preload import flags are deduplicated.

## API Surface

- `initializeInterceptor(config)`
- `shutdownInterceptor()`
- `refreshManifest()`
- `getManifest()`
- `isInitialized()`

## Verify It Works

1. Start app with `BROKER_LOG_LEVEL=debug`.
2. Confirm startup log indicates interceptor initialized and rules loaded.
3. Send one request that should match manifest rules and confirm interception log appears.
4. Send one request that should not match and confirm it passes through.
5. Trigger a policy denial and verify `RequestDeniedError` is observed by the app.
6. If using approval flows, verify `ApprovalRequiredError` handling path.

## Package Scripts

- `pnpm --filter @broker-interceptor/interceptor-node test:service:intercepted`
  - runs service with preload via `node --import` flags
  - keeps script aligned with current Node ESM preload behavior

## Non-goals

- This package does not enforce network-level egress controls.
- This package does not provide complete interception coverage for non-Node runtimes.

## License

Private - All rights reserved
