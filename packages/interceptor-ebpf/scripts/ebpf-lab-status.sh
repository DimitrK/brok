#!/usr/bin/env bash
set -euo pipefail

HOST_CONTAINER="${EBPF_LAB_HOST_CONTAINER:-interceptor-ebpf-host-lab}"
NESTED_CONTAINER="${EBPF_LAB_NESTED_CONTAINER:-nested-interceptor-node-test-service}"

if ! command -v docker >/dev/null 2>&1; then
  echo "[ebpf-lab] docker CLI is required"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[ebpf-lab] cannot access docker daemon. Start Docker Desktop and verify CLI access."
  exit 1
fi

if ! docker ps -a --format '{{.Names}}' | grep -Fxq "$HOST_CONTAINER"; then
  echo "[ebpf-lab] host container not found: ${HOST_CONTAINER}"
  exit 0
fi

echo "[ebpf-lab] host container status"
docker ps --filter "name=^/${HOST_CONTAINER}$"

echo "[ebpf-lab] nested container status"
docker exec "$HOST_CONTAINER" docker ps --filter "name=^/${NESTED_CONTAINER}$"
