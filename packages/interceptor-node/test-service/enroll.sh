#!/bin/bash
#
# Workload Enrollment Script
#
# This script generates a proper CSR with SPIFFE SAN URI and enrolls
# the workload with the broker admin API to get mTLS certificates.
#
# The resulting certificates can be used directly with the interceptor -
# session tokens are automatically acquired and refreshed by the interceptor.
#
# Usage:
#   ./enroll.sh
#
# Prerequisites:
#   - openssl installed
#   - curl installed
#   - jq installed (for JSON parsing)
#
# Environment variables (or edit the defaults below):
#   ADMIN_API_URL      - URL of the broker admin API (for enrollment)
#   TENANT_ID          - Your tenant ID
#   WORKLOAD_ID        - Your workload ID  
#   ENROLLMENT_TOKEN   - Enrollment token from workload creation
#   CERT_TTL_SECONDS   - Certificate TTL (default: 86400 = 24 hours)

set -e

# ============================================
# Configuration - Update these values!
# ============================================
ADMIN_API_URL="${ADMIN_API_URL:-http://localhost:8080}"
TENANT_ID="${TENANT_ID:-t_fcc746800c124aa985c2f2ac599742a3}"
WORKLOAD_ID="${WORKLOAD_ID:-w_1edd58cf79bb4053bdedd078f33e40ef}"
ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN:-Y-VIjgTCFsiWSgY6ceNxPePVdZNzKAXu8vtIyMUHgqE}"
CERT_TTL_SECONDS="${CERT_TTL_SECONDS:-86400}"

# Derived values
SAN_URI="spiffe://broker/tenants/${TENANT_ID}/workloads/${WORKLOAD_ID}"
CERTS_DIR="$(dirname "$0")/certs"

echo "=========================================="
echo "Workload Enrollment"
echo "=========================================="
echo "Admin API:    ${ADMIN_API_URL}"
echo "Tenant ID:    ${TENANT_ID}"
echo "Workload ID:  ${WORKLOAD_ID}"
echo "SAN URI:      ${SAN_URI}"
echo "Certs Dir:    ${CERTS_DIR}"
echo ""

# Create certs directory if it doesn't exist
mkdir -p "${CERTS_DIR}"

# ============================================
# Step 1: Generate private key (if not exists)
# ============================================
KEY_FILE="${CERTS_DIR}/workload.key"
if [ -f "${KEY_FILE}" ]; then
  echo "[1/4] Using existing private key: ${KEY_FILE}"
else
  echo "[1/4] Generating private key..."
  openssl ecparam -genkey -name prime256v1 -noout -out "${KEY_FILE}"
  echo "      Created: ${KEY_FILE}"
fi

# ============================================
# Step 2: Create OpenSSL config for CSR
# ============================================
echo "[2/4] Creating OpenSSL config for CSR with SAN URI..."

CSR_CONF="${CERTS_DIR}/csr.conf"
cat > "${CSR_CONF}" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = workload

[req_ext]
# Subject Alternative Name - SPIFFE URI for workload identity
subjectAltName = URI:${SAN_URI}
# Extended Key Usage - Client Authentication required by broker
extendedKeyUsage = clientAuth
EOF

echo "      Created: ${CSR_CONF}"

# ============================================
# Step 3: Generate CSR with SAN URI
# ============================================
echo "[3/4] Generating CSR with SPIFFE SAN URI..."

CSR_FILE="${CERTS_DIR}/workload.csr"
openssl req -new \
  -key "${KEY_FILE}" \
  -out "${CSR_FILE}" \
  -config "${CSR_CONF}"

# Verify the CSR contains the SAN
echo "      Verifying CSR extensions..."
if openssl req -in "${CSR_FILE}" -text -noout 2>/dev/null | grep -q "URI:spiffe://"; then
  echo "      ✓ CSR contains SPIFFE SAN URI"
else
  echo "      ✗ ERROR: CSR is missing SPIFFE SAN URI!"
  exit 1
fi

if openssl req -in "${CSR_FILE}" -text -noout 2>/dev/null | grep -q "TLS Web Client Authentication"; then
  echo "      ✓ CSR contains Client Auth EKU"
else
  echo "      ✗ ERROR: CSR is missing Client Auth EKU!"
  exit 1
fi

echo "      Created: ${CSR_FILE}"

# ============================================
# Step 4: Enroll with admin API
# ============================================
echo "[4/4] Enrolling workload with admin API..."

CSR_PEM=$(cat "${CSR_FILE}")

ENROLL_PAYLOAD=$(cat << EOF
{
  "enrollment_token": "${ENROLLMENT_TOKEN}",
  "csr_pem": $(echo "${CSR_PEM}" | jq -Rs .),
  "requested_ttl_seconds": ${CERT_TTL_SECONDS}
}
EOF
)

ENROLL_URL="${ADMIN_API_URL}/v1/workloads/${WORKLOAD_ID}/enroll"
echo "      POST ${ENROLL_URL}"

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "${ENROLL_PAYLOAD}" \
  "${ENROLL_URL}")

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
BODY=$(echo "${RESPONSE}" | sed '$d')

if [ "${HTTP_CODE}" = "200" ]; then
  echo "      ✓ Enrollment successful!"
  
  # Extract and save certificates
  CERT_FILE="${CERTS_DIR}/workload.crt"
  CA_FILE="${CERTS_DIR}/ca-chain.pem"
  
  echo "${BODY}" | jq -r '.client_cert_pem' > "${CERT_FILE}"
  echo "${BODY}" | jq -r '.ca_chain_pem' > "${CA_FILE}"
  EXPIRES_AT=$(echo "${BODY}" | jq -r '.expires_at')
  
  echo ""
  echo "=========================================="
  echo "✓ Enrollment Complete!"
  echo "=========================================="
  echo "Certificate: ${CERT_FILE}"
  echo "CA Chain:    ${CA_FILE}"
  echo "Private Key: ${KEY_FILE}"
  echo "Expires At:  ${EXPIRES_AT}"
  echo ""
  echo "Use these with the interceptor (session tokens are auto-managed):"
  echo "  export BROKER_URL=https://localhost:8081"
  echo "  export BROKER_MTLS_CERT_PATH=${CERT_FILE}"
  echo "  export BROKER_MTLS_KEY_PATH=${KEY_FILE}"
  echo "  export BROKER_MTLS_CA_PATH=${CA_FILE}"
else
  echo "      ✗ Enrollment failed! HTTP ${HTTP_CODE}"
  echo ""
  echo "Response body:"
  echo "${BODY}" | jq . 2>/dev/null || echo "${BODY}"
  echo ""
  echo "Common errors:"
  echo "  - enrollment_token_invalid: Token doesn't match workload"
  echo "  - enrollment_token_expired: Token expired (default 15min TTL)"
  echo "  - enrollment_token_used: Token already consumed"
  echo "  - csr_san_mismatch: CSR SAN URI doesn't match expected"
  echo "  - csr_eku_missing: CSR missing clientAuth EKU"
  exit 1
fi
