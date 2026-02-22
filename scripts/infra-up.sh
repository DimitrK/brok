#!/usr/bin/env bash
# Infrastructure setup script for broker-interceptor.
# Usage: ./scripts/infra-up.sh [--migrate] [--no-migrate] [--tools] [--apps] [--vault]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

RUN_MIGRATE=false
WITH_TOOLS=false
WITH_APPS=false
WITH_VAULT=false
POSTGRES_USER="${BROKER_POSTGRES_USER:-broker}"
POSTGRES_DB="${BROKER_POSTGRES_DB:-broker}"
POSTGRES_PORT="${BROKER_POSTGRES_PORT:-5432}"
REDIS_PASSWORD="${BROKER_REDIS_PASSWORD:-broker}"
REDIS_PORT="${BROKER_REDIS_PORT:-6379}"
BROKER_ADMIN_API_PORT_VALUE="${BROKER_ADMIN_API_PORT:-8080}"
BROKER_API_PORT_VALUE="${BROKER_API_PORT:-8081}"

usage() {
  cat <<EOF
Usage: $0 [--migrate] [--no-migrate] [--tools] [--apps] [--vault]

Options:
  --migrate      Run Prisma migrations after core services are healthy
  --no-migrate   Skip Prisma migrations (overrides --migrate)
  --tools        Include pgAdmin and Redis Commander
  --apps         Start broker-admin-api and broker-api Docker services
  --vault        Start local Vault dev service
  --help         Show this help message
EOF
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name"
    exit 1
  fi
}

wait_for_check() {
  local description="$1"
  local timeout_seconds="$2"
  local sleep_seconds=1
  shift 2
  local elapsed=0

  until "$@" >/dev/null 2>&1; do
    elapsed=$((elapsed + sleep_seconds))
    if [ "$elapsed" -ge "$timeout_seconds" ]; then
      echo "Timed out waiting for ${description} (${timeout_seconds}s)."
      exit 1
    fi
    sleep "$sleep_seconds"
  done
}

wait_for_container_healthy() {
  local service_name="$1"
  local timeout_seconds="$2"
  local sleep_seconds="${3:-1}"
  local elapsed=0
  local container_id=""
  local health_status=""

  while true; do
    container_id="$(docker compose ps -q "$service_name" 2>/dev/null || true)"
    if [ -n "$container_id" ]; then
      health_status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id" 2>/dev/null || true)"
      if [ "$health_status" = "healthy" ]; then
        return 0
      fi
    fi

    elapsed=$((elapsed + sleep_seconds))
    if [ "$elapsed" -ge "$timeout_seconds" ]; then
      echo "Timed out waiting for ${service_name} container to become healthy (${timeout_seconds}s)."
      exit 1
    fi
    sleep "$sleep_seconds"
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --migrate)
      RUN_MIGRATE=true
      shift
      ;;
    --no-migrate)
      RUN_MIGRATE=false
      shift
      ;;
    --tools)
      WITH_TOOLS=true
      shift
      ;;
    --apps)
      WITH_APPS=true
      shift
      ;;
    --vault)
      WITH_VAULT=true
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

cd "$ROOT_DIR"

require_command docker
docker compose version >/dev/null

if [ "$RUN_MIGRATE" = true ]; then
  require_command pnpm
fi

echo "Starting core infrastructure (postgres + redis)..."
docker compose up -d postgres redis

echo "Waiting for PostgreSQL to be healthy..."
wait_for_check \
  "PostgreSQL" \
  120 \
  docker compose exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"
echo "PostgreSQL is ready."

echo "Waiting for Redis to be healthy..."
wait_for_check \
  "Redis" \
  120 \
  sh -c "docker compose exec -T redis redis-cli -a \"$REDIS_PASSWORD\" ping | grep -q PONG"
echo "Redis is ready."

if [ "$WITH_TOOLS" = true ]; then
  echo "Starting management tools (pgAdmin + Redis Commander)..."
  docker compose --profile tools up -d pgadmin redis-commander
fi

if [ "$WITH_VAULT" = true ]; then
  echo "Starting local Vault dev service..."
  docker compose --profile vault up -d vault
  wait_for_check \
    "Vault" \
    120 \
    docker compose exec -T vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status'
  echo "Vault is ready."
fi

if [ "$RUN_MIGRATE" = true ]; then
  echo "Running Prisma migrations..."
  export DATABASE_URL="${DATABASE_URL:-postgresql://${POSTGRES_USER}:${BROKER_POSTGRES_PASSWORD:-broker}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}}"
  pnpm --filter @broker-interceptor/db exec prisma migrate deploy --schema ./prisma/schema.prisma
  echo "Prisma migrations completed."
fi

if [ "$WITH_APPS" = true ]; then
  echo "Building and starting broker-admin-api + broker-api containers..."
  docker compose --profile apps up -d --build broker-admin-api broker-api

  echo "Waiting for broker-admin-api container to become healthy..."
  wait_for_container_healthy "broker-admin-api" 180
  echo "broker-admin-api is healthy."

  echo "Waiting for broker-api container to become healthy..."
  wait_for_container_healthy "broker-api" 180
  echo "broker-api is healthy."
fi

echo
echo "Infrastructure is ready."
echo
echo "Core services:"
echo "  PostgreSQL: postgresql://${POSTGRES_USER}:${BROKER_POSTGRES_PASSWORD:-broker}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"
echo "  Redis:      redis://:${REDIS_PASSWORD}@127.0.0.1:${REDIS_PORT}"

if [ "$WITH_APPS" = true ]; then
  echo
  echo "API services:"
  echo "  broker-admin-api: http://localhost:${BROKER_ADMIN_API_PORT_VALUE}/healthz"
  echo "  broker-api:       https://localhost:${BROKER_API_PORT_VALUE}/healthz"
fi

if [ "$WITH_TOOLS" = true ]; then
  echo
  echo "Management tools:"
  echo "  pgAdmin:         http://localhost:5050 (admin@broker.local / admin)"
  echo "  Redis Commander: http://localhost:8082"
fi

if [ "$WITH_VAULT" = true ]; then
  echo
  echo "Vault dev:"
  echo "  URL:   http://localhost:8200"
  echo "  Token: ${BROKER_ADMIN_API_VAULT_TOKEN:-dev-root-token}"
fi
