# @broker-interceptor/schemas

Central contract package for cross-package DTOs and runtime parsers.

Source of truth:

- `openapi.yaml`
- `*.schema.json` files in this folder

Generated outputs:

- `src/generated/schemas.ts` (Zod schemas + inferred DTO types)

## Rules

- Do not re-define API DTOs in app/package code.
- Import DTO types and parsers from `@broker-interceptor/schemas`.
- When contracts change, update source schemas/OpenAPI and regenerate.

## Usage

```ts
import {ManifestSchema, type Manifest, OpenApiExecuteRequestSchema} from '@broker-interceptor/schemas'

const manifest: Manifest = ManifestSchema.parse(input)
const executeReq = OpenApiExecuteRequestSchema.parse(requestBody)
```

## Development

```bash
pnpm --filter @broker-interceptor/schemas run generate
pnpm --filter @broker-interceptor/schemas build
pnpm --filter @broker-interceptor/schemas lint
```
