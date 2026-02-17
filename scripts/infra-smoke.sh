#!/usr/bin/env bash
# Smoke checks for the local/CI broker-interceptor stack.

set -euo pipefail

ADMIN_URL="${BROKER_ADMIN_API_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
DATA_URL="${BROKER_API_HEALTH_URL:-https://127.0.0.1:8081/healthz}"
TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-90}"
DATA_URL_INSECURE_TLS="${BROKER_API_HEALTH_INSECURE_TLS:-true}"

usage() {
  cat <<EOF
Usage: $0 [--timeout <seconds>]

Environment overrides:
  BROKER_ADMIN_API_HEALTH_URL (default: http://127.0.0.1:8080/healthz)
  BROKER_API_HEALTH_URL       (default: https://127.0.0.1:8081/healthz)
  BROKER_API_HEALTH_INSECURE_TLS (default: true)
  SMOKE_TIMEOUT_SECONDS       (default: 90)
EOF
}

wait_for_http() {
  local description="$1"
  local url="$2"
  local timeout_seconds="$3"
  local insecure_tls="${4:-false}"
  local elapsed=0

  local curl_cmd=(curl -fsS)
  if [[ "$url" == https://* ]] && [[ "$insecure_tls" == "true" ]]; then
    curl_cmd+=(--insecure)
  fi

  until "${curl_cmd[@]}" "$url" >/dev/null 2>&1; do
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge "$timeout_seconds" ]; then
      echo "Timed out waiting for ${description} at ${url}"
      return 1
    fi
    sleep 1
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)
      TIMEOUT_SECONDS="$2"
      shift 2
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

if ! command -v curl >/dev/null 2>&1; then
  echo "Missing required command: curl"
  exit 1
fi

echo "Checking broker-admin-api health endpoint..."
wait_for_http "broker-admin-api" "$ADMIN_URL" "$TIMEOUT_SECONDS" "false"
echo "broker-admin-api is healthy."

echo "Checking broker-api health endpoint..."
wait_for_http "broker-api" "$DATA_URL" "$TIMEOUT_SECONDS" "$DATA_URL_INSECURE_TLS"
echo "broker-api is healthy."

echo "Smoke check passed."
