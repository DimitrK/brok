#!/usr/bin/env bash
set -euo pipefail

HOST_CONTAINER="${EBPF_LAB_HOST_CONTAINER:-interceptor-ebpf-host-lab}"

if ! command -v docker >/dev/null 2>&1; then
  echo "[ebpf-lab] docker CLI is required"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[ebpf-lab] cannot access docker daemon. Start Docker Desktop and verify CLI access."
  exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -Fxq "$HOST_CONTAINER"; then
  echo "[ebpf-lab] stopping ${HOST_CONTAINER}"
  docker rm -f "$HOST_CONTAINER" >/dev/null
  echo "[ebpf-lab] stopped"
else
  echo "[ebpf-lab] nothing to stop"
fi
