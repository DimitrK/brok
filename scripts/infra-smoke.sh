#!/usr/bin/env bash
# Smoke checks for the local/CI broker-interceptor stack.

set -euo pipefail

ADMIN_URL="${BROKER_ADMIN_API_HEALTH_URL:-http://127.0.0.1:${BROKER_ADMIN_API_PORT:-8080}/healthz}"
DATA_URL="${BROKER_API_HEALTH_URL:-https://127.0.0.1:${BROKER_API_PORT:-8081}/healthz}"
TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-90}"
CURL_MAX_TIME_SECONDS="${SMOKE_CURL_MAX_TIME_SECONDS:-5}"
DATA_URL_INSECURE_TLS="${BROKER_API_HEALTH_INSECURE_TLS:-false}"
DATA_URL_CA_CERT="${BROKER_API_HEALTH_CA_CERT:-apps/broker-api/certs/ca.crt}"
DATA_URL_CLIENT_CERT="${BROKER_API_HEALTH_CLIENT_CERT:-apps/broker-api/certs/healthcheck-client.crt}"
DATA_URL_CLIENT_KEY="${BROKER_API_HEALTH_CLIENT_KEY:-apps/broker-api/certs/healthcheck-client.key}"

usage() {
  cat <<EOF
Usage: $0 [--timeout <seconds>]

Environment overrides:
  BROKER_ADMIN_API_HEALTH_URL (default: http://127.0.0.1:${BROKER_ADMIN_API_PORT:-8080}/healthz)
  BROKER_API_HEALTH_URL       (default: https://127.0.0.1:${BROKER_API_PORT:-8081}/healthz)
  BROKER_API_HEALTH_INSECURE_TLS (default: false)
  BROKER_API_HEALTH_CA_CERT (default: apps/broker-api/certs/ca.crt)
  BROKER_API_HEALTH_CLIENT_CERT (default: apps/broker-api/certs/healthcheck-client.crt)
  BROKER_API_HEALTH_CLIENT_KEY (default: apps/broker-api/certs/healthcheck-client.key)
  SMOKE_TIMEOUT_SECONDS       (default: 90)
  SMOKE_CURL_MAX_TIME_SECONDS (default: 5)
EOF
}

wait_for_http() {
  local description="$1"
  local url="$2"
  local timeout_seconds="$3"
  shift 3
  local elapsed=0

  local curl_cmd=(curl -fsS --connect-timeout 2 --max-time "$CURL_MAX_TIME_SECONDS" "$@")

  until "${curl_cmd[@]}" "$url" >/dev/null 2>&1; do
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge "$timeout_seconds" ]; then
      echo "Timed out waiting for ${description} at ${url}"
      return 1
    fi
    sleep 1
  done
}

build_data_plane_tls_args() {
  if [[ "$DATA_URL" != https://* ]]; then
    return 0
  fi

  if [[ "$DATA_URL_INSECURE_TLS" == "true" ]]; then
    echo "--insecure"
    return 0
  fi

  if [[ ! -f "$DATA_URL_CA_CERT" ]]; then
    echo "Missing BROKER_API_HEALTH_CA_CERT file: $DATA_URL_CA_CERT" >&2
    echo "Set BROKER_API_HEALTH_INSECURE_TLS=true to bypass verification for local debugging." >&2
    return 1
  fi
  if [[ ! -f "$DATA_URL_CLIENT_CERT" ]]; then
    echo "Missing BROKER_API_HEALTH_CLIENT_CERT file: $DATA_URL_CLIENT_CERT" >&2
    return 1
  fi
  if [[ ! -f "$DATA_URL_CLIENT_KEY" ]]; then
    echo "Missing BROKER_API_HEALTH_CLIENT_KEY file: $DATA_URL_CLIENT_KEY" >&2
    return 1
  fi

  echo "--cacert $DATA_URL_CA_CERT --cert $DATA_URL_CLIENT_CERT --key $DATA_URL_CLIENT_KEY"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --insecure-tls)
      DATA_URL_INSECURE_TLS=true
      shift
      ;;
    --secure-tls)
      DATA_URL_INSECURE_TLS=false
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

if ! command -v curl >/dev/null 2>&1; then
  echo "Missing required command: curl"
  exit 1
fi

echo "Checking broker-admin-api health endpoint..."
wait_for_http "broker-admin-api" "$ADMIN_URL" "$TIMEOUT_SECONDS"
echo "broker-admin-api is healthy."

echo "Checking broker-api health endpoint..."
DATA_TLS_ARGS_STRING="$(build_data_plane_tls_args)"
IFS=' ' read -r -a DATA_TLS_ARGS <<<"$DATA_TLS_ARGS_STRING"
wait_for_http "broker-api" "$DATA_URL" "$TIMEOUT_SECONDS" "${DATA_TLS_ARGS[@]}"
echo "broker-api is healthy."

echo "Smoke check passed."
