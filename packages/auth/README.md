# @broker-interceptor/auth

Security primitives for broker authentication and certificate enrollment.

This package focuses on:

- Workload identity via mTLS client certificates
- Short-lived session token issuance and binding
- DPoP proof verification and replay defense
- Vault PKI role/policy safety helpers
- CSR validation for enrollment flows

It is intentionally framework-agnostic. You wire these primitives in your API layer.

## What It Provides

### mTLS identity

- `extractWorkloadPrincipal`
- `verifyMtls`
- `createMtlsMiddleware`

Use these to extract SAN/fingerprint/EKU from the TLS socket and enforce workload-level identity checks.

### Session token lifecycle

- `issueSession`
- `hashToken`
- `verifySessionBinding`

Use these to mint opaque session tokens and bind them to cert fingerprint (and optionally DPoP key thumbprint).

### DPoP

- `verifyDpopProofJwt`
- `verifyBoundDpopProofJwt`
- `verifyDpopClaimsOnly`
- `normalizeHtu`
- `calculateJwkThumbprint`

Use these to verify DPoP proofs (`typ`, `alg`, embedded public `jwk`, signature, `htm`/`htu`/`iat`/`jti`, optional `ath`) with replay protection.
For DPoP-bound session routes, prefer `verifyBoundDpopProofJwt` so `expectedJkt`, `accessToken`, and `jtiStore` are required at the call site.

### OIDC admin token helpers

- `verifyOidcAccessToken`
- `validateIssuerAudience`
- `extractAdminClaims`

Use these in control-plane admin auth flows to verify OIDC JWT signatures/claims and normalize admin identity claims (`issuer`, `subject`, `roles`, `tenant scope`) with fail-closed reason codes.

### Enrollment and Vault helpers

- `parseAndValidateCsr`
- `validateCsrInfo`
- `issueExternalCaEnrollment`
- `buildVaultRoleSpec`
- `computeRoleUpdate`
- `validateVaultPolicy`
- `isUnsafeVaultPolicy`
- `signCsrWithVault`

Use these to enforce CSR SAN/EKU requirements, integrate external-CA enrollment in a fail-closed way, and keep Vault PKI role/policy posture safe by default.

`issueExternalCaEnrollment` behavior:

- returns only trust metadata (`mtlsCaPem`, optional `enrollmentReference`)
- enforces timeout/abort support (`timeoutMs`, `signal`)
- fails closed with stable error codes:
  - `external_ca_not_configured`
  - `external_ca_unreachable`
  - `external_ca_profile_invalid`
  - `external_ca_enrollment_denied`
- sanitizes client-facing error messages (provider internals are not surfaced)
- rejects malformed/oversized PEM payloads and any returned private key material

### Storage bridge status

DB-integrated auth storage adapters are exported with stable (non-suffixed) names:

- `createAuthStorageScope`
- `persistSessionRecord`
- `getSessionRecordByTokenHash`
- `issueEnrollmentTokenRecord`
- `consumeEnrollmentTokenRecordByHash`
- `loadWorkloadRecordBySanUri`
- `createDpopReplayJtiStore`

These methods delegate to injected repository adapters and now use stable naming.

Dependency injection model:

- `@broker-interceptor/auth` does not create Postgres/Redis clients.
- App processes must create storage clients once per process and pass those clients down.
- App passes repository implementations into auth factory (`createAuthStorageScope`), not raw SQL/Redis calls in auth.
- Backend ownership is explicit by method:
  - Redis-backed paths: sessions, enrollment tokens, DPoP replay
  - Postgres-backed paths: workload lookup by SAN URI
- Storage method signatures require corresponding repository + consumer-provided `clients` bundle (`clients.redis`, `clients.postgres`).
- `createAuthStorageScope(...)` binds repositories and clients once, so scoped methods do not need per-call repository/client arguments.
- Cross-package transaction use is supported:
  - provide a default `transactionClient` at scope creation, or
  - pass `transactionClient` per method call to override for a single call chain.

```ts
import {createAuthStorageScope} from '@broker-interceptor/auth';

const postgresClient = createPostgresClientOnce();
const redisClient = createRedisClientOnce();

const authStorage = createAuthStorageScope({
  clients: {
    postgres: postgresClient,
    redis: redisClient
  },
  repositories: {
    sessionStore: dbAuth.sessionStore,
    enrollmentTokenStore: dbAuth.enrollmentTokenStore,
    workloadStore: dbAuth.workloadStore,
    replayStore: dbAuth.replayStore
  }
});

// Methods delegate directly to injected adapters.
await authStorage.persistSessionRecord({session});

// Optional transaction passthrough when app coordinates one tx across packages.
await authStorage.loadWorkloadRecordBySanUri({
  sanUri: 'spiffe://tenant/workload',
  transactionClient: appTransactionClient
});
```

### Boundary contracts (Zod)

- `jwkSchema`
- `dpopClaimsSchema`
- `dpopPayloadSchema`
- `workloadRecordSchema`
- `peerCertificateSchema`
- `parsedCsrSchema`

These runtime validation schemas are re-exported from `@broker-interceptor/schemas` so contract definitions stay centralized.

## Recommended Request Pipeline

For broker data plane endpoints:

1. `requireMtls` (`createMtlsMiddleware`)
2. Resolve session by bearer token hash
3. If session is DPoP-bound (or policy requires DPoP), verify DPoP proof
4. Validate session binding (`verifySessionBinding`)
5. Continue to policy/forwarding/business logic

This keeps auth and replay controls ahead of business handlers.

## Usage Example

```ts
import type {Request, Response} from 'express';
import type {TLSSocket} from 'tls';
import {
  createMtlsMiddleware,
  hashToken,
  issueSession,
  verifyBoundDpopProofJwt,
  verifyDpopProofJwt,
  verifySessionBinding
} from '@broker-interceptor/auth';

const requireMtls = createMtlsMiddleware<Request, Response>({
  getTlsSocket: req => req.socket as TLSSocket,
  loadWorkload: ({sanUri}) => workloadStore.getBySanUri(sanUri),
  setContext: ({req, context}) => {
    (req as Request & {mtls?: unknown}).mtls = context;
  },
  onError: ({res, error}) => {
    res.status(401).json({error});
  }
});

// POST /v1/session
// mTLS already validated by requireMtls.
async function issueBrokerSession(req: Request, res: Response) {
  const dpopJwt = req.header('DPoP');
  let dpopKeyThumbprint: string | undefined;

  if (dpopJwt) {
    const dpop = await verifyDpopProofJwt({
      dpopJwt,
      method: 'POST',
      url: 'https://broker.example/v1/session'
    });
    if (!dpop.ok) {
      return res.status(401).json({error: dpop.error});
    }
    dpopKeyThumbprint = dpop.jkt;
  }

  const issued = issueSession({
    workloadId: 'w1',
    tenantId: 't1',
    certFingerprint256: 'AA:BB:CC',
    ttlSeconds: 300,
    dpopKeyThumbprint
  });

  await sessionStore.insert(issued.session);
  return res.json({session_token: issued.token, expires_at: issued.session.expiresAt});
}

// POST /v1/execute
async function execute(req: Request, res: Response) {
  const token = req.header('Authorization')?.replace(/^Bearer\s+/i, '');
  if (!token) {
    return res.status(401).json({error: 'missing_bearer'});
  }

  const session = await sessionStore.getByTokenHash(hashToken(token));
  if (!session) {
    return res.status(401).json({error: 'session_not_found'});
  }

  let proofJkt: string | undefined;
  const dpopJwt = req.header('DPoP');
  if (session.dpopKeyThumbprint || dpopJwt) {
    if (!dpopJwt) {
      return res.status(401).json({error: 'dpop_required'});
    }

    const dpop = await verifyBoundDpopProofJwt({
      dpopJwt,
      method: req.method,
      url: 'https://broker.example/v1/execute',
      expectedJkt: session.dpopKeyThumbprint,
      accessToken: token,
      tenantId: session.tenantId,
      sessionId: session.sessionId,
      jtiStore
    });
    if (!dpop.ok) {
      return res.status(401).json({error: dpop.error});
    }
    proofJkt = dpop.jkt;
  }

  const binding = verifySessionBinding({
    session,
    certFingerprint256: 'AA:BB:CC',
    dpopKeyThumbprint: proofJkt
  });
  if (!binding.ok) {
    return res.status(401).json({error: binding.error});
  }

  return res.json({ok: true});
}
```

### External CA Enrollment Example

```ts
import {issueExternalCaEnrollment} from '@broker-interceptor/auth';

const result = await issueExternalCaEnrollment({
  input: {
    tenantId: 't1',
    workloadName: 'payments-worker'
  },
  timeoutMs: 5000,
  provider: {
    issueEnrollment: async ({tenantId, workloadName, signal}) => {
      const response = await externalCaClient.enroll({
        tenantId,
        workloadName,
        signal
      });
      return {
        ok: true,
        value: {
          mtlsCaPem: response.caPem,
          enrollmentReference: response.requestId
        }
      };
    }
  }
});

if (!result.ok) {
  // Map stable error codes to API response + audit events.
  throw new Error(result.error.code);
}

return result.value;
```

## Security Notes

- Use a shared `jtiStore` (for example Redis) in multi-instance deployments.
- Use stable externally visible URLs for DPoP `htu` verification (especially behind proxies).
- DPoP `htu` normalization rejects non-HTTP(S) schemes and URLs with userinfo.
- Keep DPoP verification in auth middleware/wiring, not inside business handlers.
- `issueSession` fails closed on invalid TTL/entropy/ID inputs and throws `SessionInputValidationError`.
- `issueExternalCaEnrollment` uses bounded timeouts and stable, sanitized error semantics.
- Treat all request-derived and adapter-derived payloads as untrusted and validate at boundaries.

## Development

```bash
pnpm --filter @broker-interceptor/auth test
pnpm --filter @broker-interceptor/auth test:coverage
pnpm --filter @broker-interceptor/auth lint
pnpm --filter @broker-interceptor/auth build
```
