#!/bin/bash

set -euo pipefail

ADMIN_API_URL="${ADMIN_API_URL:-http://localhost:8080}"
TENANT_ID="${TENANT_ID:-}"
WORKLOAD_ID="${WORKLOAD_ID:-}"
ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN:-}"
CERT_TTL_SECONDS="${CERT_TTL_SECONDS:-86400}"

if [[ -z "${TENANT_ID}" || -z "${WORKLOAD_ID}" || -z "${ENROLLMENT_TOKEN}" ]]; then
  echo "TENANT_ID, WORKLOAD_ID and ENROLLMENT_TOKEN are required"
  exit 1
fi

SAN_URI="spiffe://broker/tenants/${TENANT_ID}/workloads/${WORKLOAD_ID}"
CERTS_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "${CERTS_DIR}"

KEY_FILE="${CERTS_DIR}/workload.key"
CSR_FILE="${CERTS_DIR}/workload.csr"
CSR_CONF="${CERTS_DIR}/workload-openssl.cnf"
CERT_FILE="${CERTS_DIR}/workload.crt"
CA_FILE="${CERTS_DIR}/ca-chain.pem"

if [[ ! -f "${KEY_FILE}" ]]; then
  openssl ecparam -genkey -name prime256v1 -noout -out "${KEY_FILE}"
fi

cat > "${CSR_CONF}" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = backup-workload

[req_ext]
subjectAltName = URI:${SAN_URI}
extendedKeyUsage = clientAuth
EOF

openssl req -new -key "${KEY_FILE}" -out "${CSR_FILE}" -config "${CSR_CONF}"

RESPONSE=$(curl -sS -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg token "${ENROLLMENT_TOKEN}" \
    --arg csr "$(cat "${CSR_FILE}")" \
    --argjson ttl "${CERT_TTL_SECONDS}" \
    '{enrollment_token: $token, csr_pem: $csr, requested_ttl_seconds: $ttl}')" \
  "${ADMIN_API_URL}/v1/workloads/${WORKLOAD_ID}/enroll")

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
BODY=$(echo "${RESPONSE}" | sed '$d')

if [[ "${HTTP_CODE}" != "200" ]]; then
  echo "${BODY}" | jq .
  exit 1
fi

echo "${BODY}" | jq -r '.client_cert_pem' > "${CERT_FILE}"
echo "${BODY}" | jq -r '.ca_chain_pem' > "${CA_FILE}"

echo "Enrollment complete"
echo "BROKER_MTLS_CERT_PATH=${CERT_FILE}"
echo "BROKER_MTLS_KEY_PATH=${KEY_FILE}"
echo "BROKER_MTLS_CA_PATH=${CA_FILE}"
