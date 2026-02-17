#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

packages=(
  "audit"
  "auth"
  "crypto"
  "forwarder"
  "policy-engine"
  "ssrf-guard"
)

echo "broker-api external feedback status"
echo "repo: ${REPO_ROOT}"
echo

for package_name in "${packages[@]}"; do
  request_path="${REPO_ROOT}/packages/${package_name}/external_feedback/broker-interceptor/broker-api/missing_methods.md"
  reply_path=""
  status="pending"
  updated_at="-"

  for candidate in \
    "${REPO_ROOT}/packages/${package_name}/external_feedback/broker-interceptor/broker-api/missing_methods_reply.md" \
    "${REPO_ROOT}/packages/${package_name}/external_feedback/broker-interceptor/broker-api/missing_methods_response.md"; do
    if [[ -f "${candidate}" ]]; then
      reply_path="${candidate}"
      status="reply_received"
      updated_at="$(date -r "${candidate}" "+%Y-%m-%d %H:%M:%S")"
      break
    fi
  done

  echo "[${package_name}] ${status}"
  echo "  request: ${request_path}"
  echo "  reply:   ${reply_path:--}"
  echo "  reply_updated_at: ${updated_at}"
  echo
done
