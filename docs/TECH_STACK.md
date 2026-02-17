# Recommended ecosystem stack

## Backend (broker + control plane)

- **Node.js + TypeScript**
- **NestJS (running on Express)** as the default structure for a multi-engineer codebase NestJS explicitly uses
  `@nestjs/platform-express` by default and calls Express “battle tested” and “production-ready,” which matches your
  hiring/ecosystem requirement. ([docs.nestjs.com][1]) You still get Express middleware compatibility and familiarity,
  but with enforced conventions (modules, DI, pipes/guards, testing patterns).

If you strongly prefer minimalism, Express alone is still fine, but Nest tends to reduce “every engineer invents their
own patterns” as the team grows.

## Database

- **PostgreSQL** for anything beyond a single-node proof. (Audit + approvals + multi-tenancy + retention are a
  Postgres-shaped problem.)
- **SQLite only for local development**.

## ORM / migrations

- **Prisma** Prisma’s docs position it as a Node.js + TypeScript ORM with type safety and automated migrations.
  ([Prisma][2]) NestJS also has a Prisma recipe, which improves onboarding and standardization. ([docs.nestjs.com][3])

## Frontend (admin UI)

- **React + TypeScript** (largest pool + ecosystem)
- Typical pairing: Vite + React Router; keep it boring.

## Security posture helpers

- For Express hardening, use its documented production security best practices and standard hardening middleware like
  Helmet. ([expressjs.com][4])
- For SSRF risk in `/execute`, keep your existing “allowlist + deny redirects + DNS/IP validation” posture aligned with
  OWASP SSRF guidance. ([OWASP Cheat Sheet Series][5])

---

## SDK / interceptor

### Build a custom interceptor, but keep it narrow

Given your scope (“attacker can’t use broker-issued tokens without passing the broker”), you don’t need to intercept
everything. You need **reliable interception for the supported stacks**, plus a **zero-interception primary path**.

**Primary integration path (most reliable): base URL override**

- For OpenAI/Anthropic-style SDKs, make the broker the configured base URL. This avoids monkey-patching entirely and is
  the most stable approach.

**Secondary path (best-effort interception): custom**

- Support a documented compatibility matrix:
  - Axios via request interceptor/adapter
  - Node `http`/`https` for direct calls
  - `fetch` via explicit wrapper (avoid deep global patching unless you’re willing to own breakage)

- Manifest-driven matching (your signed manifest) decides what gets routed to `/v1/execute`.

This keeps the SDK simple, testable, and operationally predictable.

---

## Project structure

Below is a repo layout that matches your constraints (popular, easy hiring) and the architecture you’ve already
specified (control plane + data plane separation, schema-driven contracts, custom interceptor).

It follows the standard monorepo split of `apps/` for deployables and `packages/` (or `libs/`) for shared code, which is
the recommendation in both Nest monorepo guidance and Turborepo structuring guidance. ([docs.nestjs.com][1])

---

### Monorepo tooling choice

- **pnpm workspaces** for package management and linking internal packages (widely used, simple). ([pnpm.io][2])
- **Turborepo** for task orchestration + caching as the repo grows (optional but common). ([Turborepo][3])

---

### Proposed repo tree

```text
broker/
  apps/
    broker-api/                 # Data plane: mTLS + session + execute + manifest
      src/
      test/
      Dockerfile

    broker-admin-api/           # Control plane: tenants, workloads, templates, policies, audit query, approvals
      src/
      test/
      Dockerfile

    admin-web/                  # React + TS admin UI
      src/
      public/
      vite.config.ts
      Dockerfile

    docs-site/                  # Optional: docs (Docusaurus) / ADRs rendered
      ...

  packages/
    schemas/                    # JSON Schemas: template, manifest, audit, canonical descriptor, etc
      template.schema.json
      manifest.schema.json
      audit-event.schema.json
      ...
      src/                      # Optional: TS types generated from schema
      package.json

    db/                         # Prisma schema, migrations, generated client wrapper
      prisma/
        schema.prisma
        migrations/
      src/
      package.json

    policy-engine/              # Deterministic policy evaluation + approval logic
      src/
      package.json

    canonicalizer/              # URL canonicalization + descriptor builder (RFC3986 rules implemented here)
      src/
      package.json

    ssrf-guard/                 # DNS resolve + IP range denylist + redirect policy enforcement
      src/
      package.json

    forwarder/                  # Upstream HTTP client, header allowlists, hop-by-hop stripping, framing rules
      src/
      package.json

    crypto/                     # Envelope encryption helpers, key handling, token binding utilities
      src/
      package.json

    auth/                       # mTLS identity extraction, session token issuance/validation, optional DPoP
      src/
      package.json

    audit/                      # Audit event emitter + storage adapter + query utilities
      src/
      package.json

    interceptor-node/           # Custom interceptor SDK (manifest-driven)
      src/
      package.json

    shared/                     # Shared TS types/utilities (non-security critical helpers)
      src/
      package.json

  infra/
    docker/                     # local dev compose, reverse proxy, cert tooling
    k8s/                        # helm charts/manifests if you go there later
    terraform/                  # optional infrastructure as code
    scripts/                    # cert bootstrap, db init, migrations

  .github/
    workflows/                  # CI pipelines

  turbo.json                    # Turborepo task graph (if used)
  pnpm-workspace.yaml           # pnpm workspace definition
  package.json
  tsconfig.base.json
  README.md
  ADRs/
```

## Key boundary decisions

### 1) Split data plane and control plane into separate deployables

**apps/broker-api** (data plane)

- `/v1/session`, `/v1/execute`, `/v1/workloads/{id}/manifest`, and manifest key distribution
- mTLS required everywhere; bearer session required except session issuance

**apps/broker-admin-api** (control plane)

- tenants, workloads, integrations, templates, policies, approvals UI actions, audit queries
- bearer auth (OIDC/SSO later), no workload mTLS needed

This is the cleanest way to avoid security confusion and to scale and harden them differently.

### 2) Make `packages/schemas` the contract source of truth

- All request/response DTOs in Nest should be generated from schemas or at least validated against them at runtime.
- Your interceptor should validate and cache manifests strictly (signature verification + TTL enforcement).

### 3) Keep “execute pipeline” code isolated and testable

Put these as separate packages with explicit APIs:

- canonicalizer
- ssrf-guard
- policy-engine
- forwarder
- auth
- audit

This makes it possible to write focused security regression suites (SSRF vectors, canonicalization test cases,
hop-by-hop header handling) without booting the whole server.

---

## NestJS monorepo mechanics & Turborepo

- Use pnpm + Turborepo for the monorepo, and use NestJS inside the apps
- Keep Nest apps under `apps/`, shared libs under `packages/`, use pnpm workspaces and optionally Turborepo.

---

## Interceptor SDK layout

`packages/interceptor-node`

- One public entrypoint: `initBrokerInterceptor({ brokerUrl, workloadCertPath?, tokenProvider? })`
- Submodules by HTTP stack:
  - axios adapter
  - fetch wrapper (explicit wrapper, not “patch everything”)
  - http/https agent wrapper (best effort)

- Manifest cache + signature verification

Given your decision to avoid MSW, keeping the interceptor as a normal library with a clear support matrix is the right
operational approach.

---

Here’s a concrete, “pnpm + Turborepo + NestJS + React” repo definition you can implement immediately.

# How to proceed:

## 1) Bootstrap the monorepo

Use Turborepo’s official scaffold:

```bash
pnpm dlx create-turbo@latest
```

This is the recommended entrypoint for a new Turborepo repo. ([Turborepo][1])

## 2) Workspace layout

Use the standard `apps/` + `packages/` split (Turborepo’s common convention), and define the workspace in
`pnpm-workspace.yaml`:

**pnpm-workspace.yaml**

```yaml
packages:
  - 'apps/*'
  - 'packages/*'
```

pnpm workspaces are enabled by a `pnpm-workspace.yaml` at the repo root. ([pnpm.io][2])

## 3) Turborepo task graph

Add/adjust `turbo.json` with a minimal pipeline that supports build, test, lint, typecheck, dev:

**turbo.json**

```json
{
  "$schema": "https://turborepo.org/schema.json",
  "pipeline": {
    "build": {"dependsOn": ["^build"], "outputs": ["dist/**"]},
    "test": {"dependsOn": ["^build"]},
    "lint": {},
    "typecheck": {},
    "dev": {"cache": false, "persistent": true}
  }
}
```

The `dependsOn: ["^build"]` pattern is the established way to ensure dependency builds happen first. ([Stack
Overflow][3])

## 4) Apps and packages you’ll create

### apps/

- `apps/broker-api` (data plane - mTLS + session + execute + manifest)
- `apps/broker-admin-api` (control plane - OIDC/bearer)
- `apps/admin-web` (React admin UI)

### packages/

- `packages/schemas` (JSON Schemas + generated TS types)
- `packages/db` (Prisma schema, migrations, client wrapper)
- `packages/policy-engine`
- `packages/canonicalizer`
- `packages/ssrf-guard`
- `packages/forwarder`
- `packages/auth`
- `packages/audit`
- `packages/crypto`
- `packages/interceptor-node`

This matches the “monorepo with multiple apps + shared packages” pattern that Turborepo is intended to accelerate.
([Strapi][4])

## 5) Root scripts (pnpm + turbo)

**package.json (root)**

```json
{
  "private": true,
  "packageManager": "pnpm@9.15.9",
  "scripts": {
    "build": "turbo run build",
    "dev": "turbo run dev",
    "test": "turbo run test",
    "lint": "turbo run lint",
    "typecheck": "turbo run typecheck"
  }
}
```

Turborepo’s getting started flow assumes `turbo` orchestrates tasks across workspaces. ([Turborepo][5])

## 6) NestJS inside Turborepo

You’ll scaffold Nest apps under `apps/` and shared Nest libs (if you want) under `packages/`. This approach is common
and doesn’t require adopting Nest CLI “monorepo mode” (which is optional). Turborepo’s structure is independent of
framework. ([Strapi][4])

If you want a reference for Prisma + Turborepo specifically, Prisma publishes a guide for Turborepo usage. ([Prisma][6])

---


## 7) Zod for validation and type inference
You'll use zod for validation of request params, schema creation and typescript inference
