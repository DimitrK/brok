#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

HOST_IMAGE="${EBPF_LAB_HOST_IMAGE:-interceptor-ebpf-host:local}"
HOST_CONTAINER="${EBPF_LAB_HOST_CONTAINER:-interceptor-ebpf-host-lab}"
NESTED_IMAGE="${EBPF_LAB_NESTED_IMAGE:-interceptor-node-test:nested}"
NESTED_CONTAINER="${EBPF_LAB_NESTED_CONTAINER:-nested-interceptor-node-test-service}"
LAB_PORT="${EBPF_LAB_PORT:-3000}"
REQUIRE_HOST_PORT="${EBPF_LAB_REQUIRE_HOST_PORT:-false}"
BROKER_URL_VALUE="${BROKER_URL:-https://localhost:8081}"
BROKER_WORKLOAD_ID_VALUE="${BROKER_WORKLOAD_ID:-w_f73d1dc18e9c41bc89c5928d5bc67230}"
OPENAI_API_KEY_VALUE="${OPENAI_API_KEY:-int_c7baa65e33244fb8b8bcd51a7072b57f}"
BROKER_MTLS_CERT_PATH_VALUE="${BROKER_MTLS_CERT_PATH:-./test-service/certs/workload.crt}"
BROKER_MTLS_KEY_PATH_VALUE="${BROKER_MTLS_KEY_PATH:-./test-service/certs/workload.key}"
BROKER_MTLS_CA_PATH_VALUE="${BROKER_MTLS_CA_PATH:-./test-service/certs/ca-chain.pem}"
BROKER_LOG_LEVEL_VALUE="${BROKER_LOG_LEVEL:-debug}"
BROKER_FAIL_ON_MANIFEST_ERROR_VALUE="${BROKER_FAIL_ON_MANIFEST_ERROR:-false}"
BROKER_TUNNEL_PORT="${EBPF_LAB_BROKER_TUNNEL_PORT:-8081}"

HOST_DOCKERFILE="${ROOT_DIR}/packages/interceptor-ebpf/docker/ebpf-host.Dockerfile"
NESTED_DOCKERFILE_IN_HOST="/workspace/packages/interceptor-ebpf/docker/interceptor-node-test.Dockerfile"

if ! command -v docker >/dev/null 2>&1; then
  echo "[ebpf-lab] docker CLI is required"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "[ebpf-lab] curl is required"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[ebpf-lab] cannot access docker daemon. Start Docker Desktop and verify CLI access."
  exit 1
fi

printf '[ebpf-lab] building host image %s\n' "$HOST_IMAGE"
docker build -f "$HOST_DOCKERFILE" -t "$HOST_IMAGE" "$ROOT_DIR"

if docker ps -a --format '{{.Names}}' | grep -Fxq "$HOST_CONTAINER"; then
  printf '[ebpf-lab] removing existing host container %s\n' "$HOST_CONTAINER"
  docker rm -f "$HOST_CONTAINER" >/dev/null
fi

printf '[ebpf-lab] starting host container %s\n' "$HOST_CONTAINER"
docker run -d \
  --name "$HOST_CONTAINER" \
  --privileged \
  --cgroupns=host \
  -e DOCKER_TLS_CERTDIR= \
  --add-host host.docker.internal:host-gateway \
  -v "$ROOT_DIR:/workspace" \
  -p "${LAB_PORT}:3000" \
  "$HOST_IMAGE" >/dev/null

printf '[ebpf-lab] waiting for nested dockerd...\n'
for _ in $(seq 1 60); do
  if docker exec "$HOST_CONTAINER" docker info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker exec "$HOST_CONTAINER" docker info >/dev/null

printf '[ebpf-lab] starting broker tunnel in host container: localhost:%s -> host.docker.internal:8081\n' "$BROKER_TUNNEL_PORT"
docker exec "$HOST_CONTAINER" sh -lc '
  if [ -f /tmp/ebpf-lab-broker-tunnel.pid ]; then
    kill "$(cat /tmp/ebpf-lab-broker-tunnel.pid)" >/dev/null 2>&1 || true
    rm -f /tmp/ebpf-lab-broker-tunnel.pid
  fi
'
docker exec -d "$HOST_CONTAINER" sh -lc \
  "echo \$\$ > /tmp/ebpf-lab-broker-tunnel.pid; exec socat TCP-LISTEN:${BROKER_TUNNEL_PORT},fork,reuseaddr TCP:host.docker.internal:8081"

printf '[ebpf-lab] building nested test-service image %s\n' "$NESTED_IMAGE"
docker exec "$HOST_CONTAINER" docker build -f "$NESTED_DOCKERFILE_IN_HOST" -t "$NESTED_IMAGE" /workspace >/dev/null

if docker exec "$HOST_CONTAINER" docker ps -a --format '{{.Names}}' | grep -Fxq "$NESTED_CONTAINER"; then
  printf '[ebpf-lab] removing existing nested container %s\n' "$NESTED_CONTAINER"
  docker exec "$HOST_CONTAINER" docker rm -f "$NESTED_CONTAINER" >/dev/null
fi

printf '[ebpf-lab] starting nested test-service container %s\n' "$NESTED_CONTAINER"
docker exec "$HOST_CONTAINER" docker run -d \
  --name "$NESTED_CONTAINER" \
  --network host \
  -e BROKER_URL="$BROKER_URL_VALUE" \
  -e BROKER_WORKLOAD_ID="$BROKER_WORKLOAD_ID_VALUE" \
  -e OPENAI_API_KEY="$OPENAI_API_KEY_VALUE" \
  -e BROKER_MTLS_CERT_PATH="$BROKER_MTLS_CERT_PATH_VALUE" \
  -e BROKER_MTLS_KEY_PATH="$BROKER_MTLS_KEY_PATH_VALUE" \
  -e BROKER_MTLS_CA_PATH="$BROKER_MTLS_CA_PATH_VALUE" \
  -e BROKER_LOG_LEVEL="$BROKER_LOG_LEVEL_VALUE" \
  -e BROKER_FAIL_ON_MANIFEST_ERROR="$BROKER_FAIL_ON_MANIFEST_ERROR_VALUE" \
  "$NESTED_IMAGE" \
  pnpm test:service:intercepted >/dev/null

if ! docker exec "$HOST_CONTAINER" docker ps --filter "name=^/${NESTED_CONTAINER}$" --filter "status=running" --format '{{.Names}}' | grep -Fxq "$NESTED_CONTAINER"; then
  echo "[ebpf-lab] nested container failed to stay running; recent logs:"
  docker exec "$HOST_CONTAINER" docker logs "$NESTED_CONTAINER" --tail 120 || true
  exit 1
fi

printf '[ebpf-lab] waiting for nested health endpoint (inside host container): http://localhost:3000/health\n'
for _ in $(seq 1 60); do
  if docker exec "$HOST_CONTAINER" curl -fsS "http://localhost:3000/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker exec "$HOST_CONTAINER" curl -fsS "http://localhost:3000/health" >/dev/null

HOST_ENDPOINT_STATUS="unavailable"
if curl -fsS "http://localhost:${LAB_PORT}/health" >/dev/null 2>&1; then
  HOST_ENDPOINT_STATUS="available"
elif [[ "$REQUIRE_HOST_PORT" == "true" ]]; then
  echo "[ebpf-lab] host endpoint check failed: http://localhost:${LAB_PORT}/health"
  echo "[ebpf-lab] set EBPF_LAB_REQUIRE_HOST_PORT=false to allow startup without host-port validation."
  exit 1
fi

cat <<MSG

[ebpf-lab] ready
- host container: ${HOST_CONTAINER}
- nested test-service: ${NESTED_CONTAINER}
- endpoint: http://localhost:${LAB_PORT}
- endpoint_status: ${HOST_ENDPOINT_STATUS}

Try:
  curl -X POST http://localhost:${LAB_PORT}/chat \\
    -H "Content-Type: application/json" \\
    -d '{"message":"hello"}'

If endpoint_status is unavailable, verify from inside host container:
  docker exec ${HOST_CONTAINER} curl -fsS http://localhost:3000/health

Stop:
  pnpm --filter @broker-interceptor/interceptor-ebpf run docker:ebpf-lab:down

MSG
