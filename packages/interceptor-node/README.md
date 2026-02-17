# @broker-interceptor/interceptor-node

Node.js request interceptor for routing HTTP/HTTPS traffic through the broker.

> **Note**: This is a proof-of-concept implementation that establishes the protocol patterns for the production
> eBPF-based interceptor. The same concepts (manifest format, matching rules, execute protocol) will be used in the eBPF
> implementation for Kubernetes environments.

## Features

- **Transparent interception**: Patches Node's `http`, `https`, `fetch`, and `child_process` modules
- **Pre-TLS interception**: Intercepts requests before TLS encryption, so no MITM or custom CA needed
- **Manifest-based routing**: Only intercepts requests matching manifest rules
- **Child process propagation**: Automatically propagates interception to spawned Node processes
- **Zero-code change option**: Can be enabled via `NODE_OPTIONS` without modifying application code

## Installation

```bash
pnpm add @broker-interceptor/interceptor-node
```

## Usage

### Option 1: Programmatic initialization

Use this when you want fine-grained control over interceptor initialization:

```typescript
import {initializeInterceptor, shutdownInterceptor} from '@broker-interceptor/interceptor-node';

// Initialize the interceptor
const result = await initializeInterceptor({
  brokerUrl: 'https://broker.example.com',
  sessionToken: 'tok_abc123...',

  // Optional: custom logger
  logger: {
    debug: msg => console.debug(msg),
    info: msg => console.info(msg),
    warn: msg => console.warn(msg),
    error: msg => console.error(msg)
  }
});

if (result.ok) {
  console.log(`Interceptor initialized with ${result.manifest.match_rules.length} rules`);
} else {
  console.error(`Failed to initialize: ${result.error}`);
}

// Your application code...
// All HTTP/HTTPS requests matching manifest rules will be routed through the broker

// Shutdown when done
shutdownInterceptor();
```

### Option 2: Preload via NODE_OPTIONS (zero-code change)

Enable interception without modifying your application code:

```bash
# Set environment variables
export BROKER_URL=https://broker.example.com
export BROKER_SESSION_TOKEN=tok_abc123...

# Enable interception via NODE_OPTIONS
export NODE_OPTIONS="--require @broker-interceptor/interceptor-node/preload"

# Run your application as normal
node app.js
```

Or in a single command:

```bash
BROKER_URL=https://broker.example.com \
BROKER_SESSION_TOKEN=tok_abc123 \
NODE_OPTIONS="--require @broker-interceptor/interceptor-node/preload" \
node app.js
```

## Configuration

### Programmatic API

| Option                      | Type      | Required | Default  | Description                                   |
| --------------------------- | --------- | -------- | -------- | --------------------------------------------- |
| `brokerUrl`                 | `string`  | Yes      | -        | Base URL of the broker API                    |
| `sessionToken`              | `string`  | Yes      | -        | Session token for broker authentication       |
| `manifestPath`              | `string`  | No       | -        | Local manifest file path (skips broker fetch) |
| `mtlsCertPath`              | `string`  | No       | -        | Path to mTLS client certificate (PEM)         |
| `mtlsKeyPath`               | `string`  | No       | -        | Path to mTLS client private key (PEM)         |
| `mtlsCaPath`                | `string`  | No       | -        | Path to broker CA certificate (PEM)           |
| `manifestRefreshIntervalMs` | `number`  | No       | `300000` | Manifest refresh interval (5 minutes)         |
| `failOnManifestError`       | `boolean` | No       | `true`   | Exit if manifest fetch fails                  |
| `logger`                    | `Logger`  | No       | Console  | Custom logger implementation                  |

### Environment Variables (for preload)

| Variable                        | Required | Description                                           |
| ------------------------------- | -------- | ----------------------------------------------------- |
| `BROKER_URL`                    | Yes      | Base URL of the broker API                            |
| `BROKER_SESSION_TOKEN`          | Yes      | Session token for broker authentication               |
| `BROKER_MANIFEST_PATH`          | No       | Local manifest file path                              |
| `BROKER_MTLS_CERT_PATH`         | No       | Path to mTLS client certificate                       |
| `BROKER_MTLS_KEY_PATH`          | No       | Path to mTLS client private key                       |
| `BROKER_MTLS_CA_PATH`           | No       | Path to broker CA certificate                         |
| `BROKER_MANIFEST_REFRESH_MS`    | No       | Manifest refresh interval in milliseconds             |
| `BROKER_FAIL_ON_MANIFEST_ERROR` | No       | Set to "false" to continue without manifest           |
| `BROKER_LOG_LEVEL`              | No       | Log level: "debug", "info", "warn", "error", "silent" |

## Error Handling

The interceptor may throw special errors when requests are blocked:

```typescript
import {
  ApprovalRequiredError,
  RequestDeniedError,
} from '@broker-interceptor/interceptor-node'

try {
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    body: JSON.stringify({ model: 'gpt-4', messages: [...] }),
  })
} catch (error) {
  if (error instanceof ApprovalRequiredError) {
    console.log(`Request needs approval: ${error.approvalId}`)
    console.log(`Risk tier: ${error.summary.risk_tier}`)
    console.log(`Expires at: ${error.expiresAt}`)
  } else if (error instanceof RequestDeniedError) {
    console.log(`Request denied: ${error.reason}`)
    console.log(`Correlation ID: ${error.correlationId}`)
  } else {
    throw error
  }
}
```

## Manual URL Matching

You can check if a URL would be intercepted without making a request:

```typescript
import {matchUrl, shouldIntercept, getManifest} from '@broker-interceptor/interceptor-node';

const manifest = getManifest();
if (manifest) {
  // Check if URL would be intercepted
  const willIntercept = shouldIntercept('https://api.openai.com/v1/chat', manifest);
  console.log(`Will intercept: ${willIntercept}`);

  // Get detailed match information
  const match = matchUrl('https://api.openai.com/v1/chat', manifest);
  if (match.matched) {
    console.log(`Matched rule: ${match.integrationId}`);
    console.log(`Provider: ${match.rule.provider}`);
  }
}
```

## How It Works

1. **Initialization**: The interceptor fetches a signed manifest from the broker containing match rules
2. **Module patching**: Patches `http.request`, `https.request`, `fetch`, and `child_process.spawn/exec/fork`
3. **Request interception**: When a request matches manifest rules, it's forwarded to the broker's `/execute` endpoint
4. **Policy evaluation**: The broker evaluates policies and either executes, requires approval, or denies the request
5. **Response forwarding**: The response from the upstream API (via broker) is returned to the application

### Architecture

```
┌─────────────────────┐      ┌─────────────┐      ┌──────────────────┐
│   Your Application  │      │   Broker    │      │  Upstream API    │
│                     │      │             │      │  (e.g., OpenAI)  │
│  fetch('https://    │      │             │      │                  │
│   api.openai.com')  │──────│─────────────│──────│                  │
│                     │      │             │      │                  │
│  Intercepted before │      │ Policy      │      │                  │
│  TLS handshake      │──────│ evaluation  │──────│                  │
│                     │      │             │      │                  │
└─────────────────────┘      └─────────────┘      └──────────────────┘
        │                           │
        │   Request/Response        │
        │   in plaintext            │
        │                           │
   ┌────┴────┐                      │
   │ Patches │                      │
   │ http/   │                      │
   │ https/  │                      │
   │ fetch   │                      │
   └─────────┘                      │
```

## Comparison to Traditional Approaches

| Feature             | This Interceptor    | MITM Proxy    | OS-level Proxy     |
| ------------------- | ------------------- | ------------- | ------------------ |
| Requires root/admin | No                  | Sometimes     | Yes                |
| Requires custom CA  | No                  | Yes           | No                 |
| Works in containers | Yes                 | Complex setup | Requires NET_ADMIN |
| Application changes | None (with preload) | Proxy config  | None               |
| Non-Node processes  | No\*                | Yes           | Yes                |

\*Child Node processes are automatically intercepted via `NODE_OPTIONS` propagation.

## Testing

```bash
# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage
```

## License

Private - All rights reserved
