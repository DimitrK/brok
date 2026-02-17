# Broker Interceptor

## Overview

This project implements a broker and interceptor to protect third-party secrets and enforce policy on protected outbound
calls.

## Security invariants

See `docs/threat-model.md` for the full threat model and invariants.

## Admin authentication

See `docs/admin-auth.md` for the admin authentication model and audit requirements.

## Codespace Review Log

### 2026-02-08 (`packages/db`)

- Completed an additional storage-focused review against:
  - `docs/development/engineering-process.md`
  - `docs/development/data-storage-postgres-redis-rules.md`
- Result: no direct N+1 query pattern found in repository implementations (no await-in-loop data fetch pattern).
- Follow-up risks identified:
  - `TemplateRepository.listLatestTemplatesByTenant` currently fetches all active versions and deduplicates in memory.
  - Several tenant-scoped list queries sort by `createdAt` without composite `(tenant_id, created_at)` indexes.

## Local Development Setup

### Prerequisites

- Node.js 20+
- pnpm 9+
- Docker and Docker Compose

### Quick Start

1. **Install dependencies:**

   ```bash
   pnpm install
   ```

2. **Start infrastructure (PostgreSQL + Redis + migrations):**

   ```bash
   pnpm infra:up
   ```

   This starts PostgreSQL/Redis and applies Prisma migrations.

3. **Build all packages:**

   ```bash
   pnpm build
   ```

4. **Start the services:**

   Terminal 1 - broker-admin-api (control plane):

   ```bash
   cd apps/broker-admin-api
   pnpm dev
   ```

   Terminal 2 - broker-api (data plane):

   ```bash
   cd apps/broker-api
   pnpm dev
   ```

### Containerized API Stack

Run both APIs as Docker services (plus postgres/redis):

```bash
pnpm infra:up:apps
pnpm infra:smoke
```

Optional profiles:

- Include management tools:
  - `pnpm infra:up:apps:tools`
- Include local Vault dev:
  - `pnpm infra:up:apps:vault`

### Infrastructure Commands

| Command                              | Description                                                   |
| ------------------------------------ | ------------------------------------------------------------- |
| `pnpm infra:up`                      | Start PostgreSQL + Redis and run migrations                   |
| `pnpm infra:up:tools`                | Also starts pgAdmin and Redis Commander                       |
| `pnpm infra:up:apps`                 | Start PostgreSQL + Redis + both API containers                |
| `pnpm infra:up:apps:tools`           | Start full stack plus pgAdmin and Redis Commander             |
| `pnpm infra:up:apps:vault`           | Start full stack plus local Vault dev service                 |
| `pnpm infra:smoke`                   | Validate `broker-admin-api` and `broker-api` health endpoints |
| `pnpm infra:down`                    | Stop containers (preserves data)                              |
| `pnpm infra:down:volumes`            | Stop containers and delete all data                           |
| `pnpm infra:prod:config`             | Validate production compose env/config                        |
| `pnpm infra:prod:up`                 | Start production compose stack (requires production env)      |
| `pnpm infra:prod:down`               | Stop production compose stack                                 |
| `pnpm docker:build:broker-admin-api` | Build production image for control-plane API                  |
| `pnpm docker:build:broker-api`       | Build production image for data-plane API                     |
| `pnpm db:migrate`                    | Run pending migrations                                        |
| `pnpm db:migrate:dev`                | Create new migration during development                       |
| `pnpm db:studio`                     | Open Prisma Studio for database inspection                    |

### Connection Details

Default Docker Compose configuration:

| Service                        | URL                                                | Credentials                       |
| ------------------------------ | -------------------------------------------------- | --------------------------------- |
| PostgreSQL                     | `postgresql://broker:broker@127.0.0.1:5432/broker` | broker / broker                   |
| Redis                          | `redis://:broker@127.0.0.1:6379`                   | password: broker                  |
| broker-admin-api (`--apps`)    | `http://localhost:8080/healthz`                    | static auth in `.env`             |
| broker-api (`--apps`)          | `https://localhost:8081/healthz`                   | mTLS/session flows                |
| pgAdmin (with --tools)         | `http://localhost:5050`                            | admin@broker.local / admin        |
| Redis Commander (with --tools) | `http://localhost:8082`                            | -                                 |
| Vault dev (with `--vault`)     | `http://localhost:8200`                            | token: `dev-root-token` (default) |

### Environment Configuration

Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

For production compose, use:

```bash
cp .env.production.example .env.production
```

Key environment variables:

**broker-admin-api (port 8080):**

- `BROKER_ADMIN_API_INFRA_ENABLED=true`
- `BROKER_ADMIN_API_DATABASE_URL=postgresql://broker:broker@127.0.0.1:5432/broker`
- `BROKER_ADMIN_API_REDIS_URL=redis://:broker@127.0.0.1:6379`

**broker-api (port 8081):**

- `BROKER_API_INFRA_ENABLED=true`
- `BROKER_API_DATABASE_URL=postgresql://broker:broker@127.0.0.1:5432/broker`
- `BROKER_API_REDIS_URL=redis://:broker@127.0.0.1:6379`

Docker app-profile defaults (container network):

- `BROKER_ADMIN_API_DATABASE_URL_DOCKER=postgresql://broker:broker@postgres:5432/broker`
- `BROKER_ADMIN_API_REDIS_URL_DOCKER=redis://:broker@redis:6379`
- `BROKER_API_DATABASE_URL_DOCKER=postgresql://broker:broker@postgres:5432/broker`
- `BROKER_API_REDIS_URL_DOCKER=redis://:broker@redis:6379`

## CI and Production Notes

- CI now validates both code quality and compose orchestration:
  - `.github/workflows/ci.yml` runs lint/typecheck/test/build plus a container smoke test.
- Production container images are defined in:
  - `apps/broker-admin-api/Dockerfile`
  - `apps/broker-api/Dockerfile`
- Production compose template:
  - `docker-compose.production.yml`
- For production runtime, set strict env values at minimum:
  - `NODE_ENV=production`
  - Admin API: `BROKER_ADMIN_API_SECRET_KEY_B64`, OIDC or hardened static auth, vault config if vault mode is enabled
  - Broker API: `BROKER_API_STATE_PATH` or `BROKER_API_INITIAL_STATE_JSON`
  - Both APIs: externalized `*_DATABASE_URL` and `*_REDIS_URL`

### Project Structure

```
broker-interceptor/
├── apps/
│   ├── broker-admin-api/   # Control plane API (port 8080)
│   ├── broker-api/         # Data plane API (port 8081)
│   └── admin-web/          # Admin UI (React)
├── packages/
│   ├── db/                 # Prisma schema + repositories
│   ├── schemas/            # OpenAPI/Zod schemas
│   ├── auth/               # Authentication utilities
│   ├── crypto/             # Cryptographic operations
│   ├── policy-engine/      # Policy evaluation
│   └── ...                 # Other shared packages
├── docker-compose.yml      # Local/CI compose stack with profiles
└── scripts/                # Infra lifecycle and smoke scripts
```
