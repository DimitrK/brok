# @broker-interceptor/canonicalizer

Canonicalization and template-validation package for the broker execute pipeline.

This package is responsible for:

- Validating and compiling templates before execution
- Building a canonical request descriptor from execute input
- Enforcing template constraints (host, method, path, query, headers, body policy)
- Returning stable, typed error codes for fail-closed behavior

It is framework-agnostic and intended to be used by API/repository layers.

## Contract Source of Truth

This package uses `@broker-interceptor/schemas` as the DTO and parser source of truth.

- `TemplateSchema`
- `OpenApiExecuteRequestSchema`
- `CanonicalRequestDescriptorSchema`

Do not redefine these DTOs locally.

## Exposed Interface

Main execution/canonicalization:

- `canonicalizeExecuteRequest`
- `CanonicalizeExecuteRequestInputSchema`
- `CanonicalizationContextSchema`
- `BodyDigestModeSchema`

Template validation/compilation:

- `compileCanonicalizerTemplate`
- `validateTemplateForUpload`
- `validateTemplatePublish`
- `selectMatchingPathGroup`
- `normalizeTemplateHost`

Error/result contracts:

- `canonicalizerErrorCodes`
- `CanonicalizerResult<T>`
- `CanonicalizerErrorCode`
- `ok` / `err`

Storage integration contracts:

- `createCanonicalizerPersistenceBridge`
- `CanonicalizerPersistenceDependencies`
- `CanonicalizerStorageContext`
- `run_with_transaction_context` (optional dependency hook)

This storage contract enforces package boundaries:
- apps own Postgres/Redis client lifecycle
- apps inject repository adapters into canonicalizer
- optional transaction client is passed through call chains via `context.transaction_client`

## Usage

### 1) Canonicalize an execute request

```ts
import {canonicalizeExecuteRequest} from '@broker-interceptor/canonicalizer';
import type {Template, OpenApiExecuteRequest} from '@broker-interceptor/schemas';

const template: Template = loadTemplate();
const executeRequest: OpenApiExecuteRequest = requestBody;

const result = canonicalizeExecuteRequest({
  context: {
    tenant_id: 't_123',
    workload_id: 'w_456',
    integration_id: executeRequest.integration_id
  },
  template,
  execute_request: executeRequest,
  body_digest_mode: 'high_risk_only'
});

if (!result.ok) {
  // stable reason code, safe for policy/audit mapping
  throw new Error(`${result.error.code}: ${result.error.message}`);
}

const {descriptor, matched_path_group_id, canonical_url} = result.value;
```

### 1.1) Inject storage dependencies (app-owned clients only)

```ts
import {
  createCanonicalizerPersistenceBridge,
  type CanonicalizerPersistenceDependencies
} from '@broker-interceptor/canonicalizer';

const dependencies: CanonicalizerPersistenceDependencies = {
  template_store: appProvidedTemplateStore,
  approval_store: appProvidedApprovalStore,
  audit_store: appProvidedAuditStore,
  cache_store: appProvidedCacheStore
};

const storageBridge = createCanonicalizerPersistenceBridge(dependencies);
```

No package-level client initialization is performed here. Apps create and manage clients once per process.

### 2) Validate a template on upload

```ts
import {validateTemplateForUpload} from '@broker-interceptor/canonicalizer';

const validated = validateTemplateForUpload(candidateTemplate);
if (!validated.ok) {
  throw new Error(`${validated.error.code}: ${validated.error.message}`);
}
```

### 3) Validate template publish rules (immutability/versioning)

```ts
import {validateTemplatePublish} from '@broker-interceptor/canonicalizer';

const publishCheck = validateTemplatePublish({
  candidate: nextTemplateVersion,
  existing_templates: existingVersionsFromStore
});

if (!publishCheck.ok) {
  throw new Error(`${publishCheck.error.code}: ${publishCheck.error.message}`);
}
```

## Notes

- Canonicalization rejects URL userinfo and fragments.
- Query keys are allowlist-driven and deterministically sorted.
- Duplicate query keys are rejected unless explicitly allowed by template constraints.
- Body limits/content-types are enforced from template `body_policy`.
- Output descriptor is validated against `CanonicalRequestDescriptorSchema`.

## Pending Implementations (`_INCOMPLETE`)

Canonicalizer package status:

- No local `_INCOMPLETE` methods remain in `@broker-interceptor/canonicalizer`.

Pending wiring in other package:

1. Module:
- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/apps/broker-api/src/dependencyBridge.ts`

2. Incomplete methods currently present there:
- `listRequiredDependencies_INCOMPLETE`
- `getIntegrationByTenantAndIdFromDb_INCOMPLETE`
- `getTemplateByTenantTemplateIdVersionFromDb_INCOMPLETE`
- `findOpenApprovalByCanonicalDescriptorFromDb_INCOMPLETE`
- `appendAuditEventToDb_INCOMPLETE`
- `getTemplateCacheFromRedis_INCOMPLETE`
- `setTemplateCacheInRedis_INCOMPLETE`
- `setApprovalOnceCacheInRedis_INCOMPLETE`
- `incrementRateLimitCounterInRedis_INCOMPLETE`
- `loadManifestVerificationKeysFromDb_INCOMPLETE`
- `loadActiveManifestSigningKeyFromKms_INCOMPLETE`
- `signManifestWithCryptoPackage_INCOMPLETE`
- `verifyManifestSignatureWithCryptoPackage_INCOMPLETE`

3. Canonicalizer methods pending runtime wiring from broker-api execute pipeline:
- `canonicalizeExecuteRequest` (from this package)
- `validateTemplateForUpload` (from this package)

4. Mapping for pending cross-package wiring:
- Other package module: `apps/broker-api/src/dependencyBridge.ts`
- Other package pending method: `listRequiredDependencies_INCOMPLETE`
- Canonicalizer methods to wire: `canonicalizeExecuteRequest`, `validateTemplateForUpload`

## Pending Feedback

- None.
- Latest resolved dependency feedback:
`/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/db/external_feedback/broker-interceptor/canonicalizer/archive/missing_methods_response.md`

## Development

```bash
pnpm --filter @broker-interceptor/canonicalizer build
pnpm --filter @broker-interceptor/canonicalizer lint
pnpm --filter @broker-interceptor/canonicalizer test
pnpm --filter @broker-interceptor/canonicalizer test:coverage
```
