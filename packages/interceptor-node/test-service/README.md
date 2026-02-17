# Test Service for Broker Interceptor

This is a minimal test service demonstrating the broker interceptor in action.

## What it does

- Exposes a `/chat` endpoint that accepts POST requests with a `message` field
- Forwards the message to OpenAI's Chat Completions API using `gpt-4o-mini` (cheapest model)
- Returns the AI response

## Architecture Overview

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐     ┌─────────────┐
│  Test Service   │────▶│  Interceptor │────▶│  broker-api │────▶│   OpenAI    │
│  (this server)  │     │   (patches   │     │  /execute   │     │     API     │
│                 │     │   fetch())   │     │             │     │             │
└─────────────────┘     └──────────────┘     └─────────────┘     └─────────────┘
        │                                           │
        │                                           ▼
        │                                    Policy Engine
        │                                    (allow/deny/approval)
        ▼
   curl /chat
```

## Prerequisites

- Node.js 18+
- OpenAI API key
- Running broker infrastructure (admin-api + broker-api)
- jq (for enrollment script)

## Complete Setup Flow

### Step 1: Create Tenant, Workload, and Integration via Admin API

Using the admin-web UI or direct API calls:

```bash
# 1. Create a tenant (or use existing)
# 2. Create a workload - you'll get:
#    - workload_id: w_xxx
#    - enrollment_token: xxx (valid for 15 minutes!)
# 3. Create an OpenAI integration - you'll get:
#    - integration_id: int_xxx
```

Note the following values:

- `TENANT_ID` - e.g., `t_fcc746800c124aa985c2f2ac599742a3`
- `WORKLOAD_ID` - e.g., `w_1edd58cf79bb4053bdedd078f33e40ef`
- `ENROLLMENT_TOKEN` - e.g., `Y-VIjgTCFsiWSgY6...`
- `INTEGRATION_ID` - e.g., `int_1fde97a6131b4b6c99a0afed59774e45`

### Step 2: Enroll Workload to Get mTLS Certificates

The enrollment process generates a signed client certificate:

```bash
# Edit enroll.sh with your values, then run:
cd test-service
chmod +x enroll.sh

# Set your values
export ADMIN_API_URL=http://localhost:8080
export TENANT_ID=t_fcc746800c124aa985c2f2ac599742a3
export WORKLOAD_ID=w_1edd58cf79bb4053bdedd078f33e40ef
export ENROLLMENT_TOKEN=Y-VIjgTCFsiWSgY6ceNxPePVdZNzKAXu8vtIyMUHgqE

# Run enrollment
./enroll.sh
```

This will:

1. Generate a private key (`certs/workload.key`) if not exists
2. Create a CSR with the proper SPIFFE SAN URI
3. Submit CSR to admin-api enrollment endpoint
4. Save the signed certificate (`certs/workload.crt`) and CA chain (`certs/ca-chain.pem`)

**Important**: Enrollment tokens expire in 15 minutes! If expired, create a new workload.

### Step 3: Update manifest.json (optional)

The manifest is auto-fetched from the broker using your mTLS credentials.

For local testing without broker-api running, you can use a local manifest file:

```json
{
  "match_rules": [
    {
      "integration_id": "int_1fde97a6131b4b6c99a0afed59774e45",
      ...
    }
  ]
}
```

### Step 4: Run the Test Service

#### Without interception (direct to OpenAI)

```bash
# From the interceptor-node package root
pnpm build
OPENAI_API_KEY=sk-... pnpm test:service
```

#### With interception (through broker)

```bash
# Build the interceptor package first
pnpm build

# Set environment variables
export OPENAI_API_KEY=sk-...
export BROKER_URL=https://localhost:8081          # broker-api URL
export BROKER_LOG_LEVEL=debug

# mTLS credentials (session tokens are auto-acquired using these)
export BROKER_MTLS_CERT_PATH=$(pwd)/test-service/certs/workload.crt
export BROKER_MTLS_KEY_PATH=$(pwd)/test-service/certs/workload.key
export BROKER_MTLS_CA_PATH=$(pwd)/test-service/certs/ca-chain.pem

# Optional: use local manifest instead of auto-fetching from broker
# export BROKER_MANIFEST_PATH=$(pwd)/test-service/manifest.json
# export BROKER_FAIL_ON_MANIFEST_ERROR=false

# Run with interceptor preload
pnpm test:service:intercepted
```

## Testing

Once the server is running:

```bash
# Health check
curl http://localhost:3000/health

# Send a chat message
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, what is 2+2?"}'
```

## Expected Output

### Without interception

```json
{"response": "Hello! 2 + 2 equals 4. Is there anything else you'd like to know?"}
```

### With interception (debug logging)

```
[broker-interceptor] Initializing broker interceptor for https://localhost:8081
[broker-interceptor] Manifest loaded: 1 rules
[server] Test service listening on http://localhost:3000
[broker-interceptor] Intercepting request to https://api.openai.com/v1/chat/completions
```

## Troubleshooting

### Enrollment Errors

| Error                      | Cause                        | Fix                                               |
| -------------------------- | ---------------------------- | ------------------------------------------------- |
| `enrollment_token_invalid` | Token doesn't match workload | Verify workload_id and token match                |
| `enrollment_token_expired` | Token older than 15 min      | Create new workload for new token                 |
| `enrollment_token_used`    | Token already consumed       | Create new workload                               |
| `csr_san_mismatch`         | CSR SAN URI wrong            | Re-run enroll.sh with correct tenant/workload IDs |
| `csr_eku_missing`          | CSR missing clientAuth       | Use enroll.sh (don't manually create CSR)         |

### Interception Errors

| Error                   | Cause                  | Fix                          |
| ----------------------- | ---------------------- | ---------------------------- |
| `ApprovalRequiredError` | Request needs approval | Approve via admin UI/API     |
| `RequestDeniedError`    | Policy blocked request | Check integration policies   |
| `Manifest fetch failed` | Can't reach broker     | Verify BROKER_URL is correct |
| `mtls_required` / `mtls_not_authorized` | Broker did not accept workload mTLS cert | Ensure `BROKER_API_TLS_REQUIRE_CLIENT_CERT=true`, use `BROKER_ADMIN_API_CERT_ISSUER_MODE=local`, and re-enroll workload cert |

For local compose mTLS verification:

```bash
openssl verify -CAfile ../../apps/broker-api/certs/ca.crt ./certs/workload.crt
openssl x509 -in ./certs/workload.crt -pubkey -noout | openssl pkey -pubin -outform der | shasum -a 256
openssl pkey -in ./certs/workload.key -pubout -outform der | shasum -a 256
```

## Files

```
test-service/
├── README.md          # This file
├── server.ts          # Express-like HTTP server
├── manifest.json      # Local manifest for testing (optional)
├── enroll.sh          # Certificate enrollment script
└── certs/
    ├── workload.key   # Private key (generated)
    ├── workload.csr   # Certificate signing request (generated)
    ├── workload.crt   # Signed certificate (from enrollment)
    ├── ca-chain.pem   # CA chain (from enrollment)
    └── csr.conf       # OpenSSL config (generated)
```
