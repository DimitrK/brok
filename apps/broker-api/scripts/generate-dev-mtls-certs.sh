#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../certs"
FORCE_ROTATE="false"
RENEW_BEFORE_DAYS="30"
VALIDITY_DAYS="397"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --force)
      FORCE_ROTATE="true"
      shift
      ;;
    --renew-before-days)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --renew-before-days" >&2
        exit 1
      fi
      RENEW_BEFORE_DAYS="$2"
      shift 2
      ;;
    --validity-days)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --validity-days" >&2
        exit 1
      fi
      VALIDITY_DAYS="$2"
      shift 2
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      OUTPUT_DIR="$1"
      shift
      ;;
  esac
done

case "$RENEW_BEFORE_DAYS" in
  ''|*[!0-9]*)
    echo "--renew-before-days must be a non-negative integer" >&2
    exit 1
    ;;
esac
case "$VALIDITY_DAYS" in
  ''|*[!0-9]*)
    echo "--validity-days must be a positive integer" >&2
    exit 1
    ;;
esac

mkdir -p "${OUTPUT_DIR}"

CA_KEY="${OUTPUT_DIR}/ca.key"
CA_CERT="${OUTPUT_DIR}/ca.crt"
SERVER_KEY="${OUTPUT_DIR}/server.key"
SERVER_CSR="${OUTPUT_DIR}/server.csr"
SERVER_CERT="${OUTPUT_DIR}/server.crt"
SERVER_EXT="${OUTPUT_DIR}/server.ext"
HEALTHCHECK_KEY="${OUTPUT_DIR}/healthcheck-client.key"
HEALTHCHECK_CSR="${OUTPUT_DIR}/healthcheck-client.csr"
HEALTHCHECK_CERT="${OUTPUT_DIR}/healthcheck-client.crt"
HEALTHCHECK_EXT="${OUTPUT_DIR}/healthcheck-client.ext"
WORKLOAD_KEY="${OUTPUT_DIR}/workload-client.key"
WORKLOAD_CSR="${OUTPUT_DIR}/workload-client.csr"
WORKLOAD_CERT="${OUTPUT_DIR}/workload-client.crt"
WORKLOAD_EXT="${OUTPUT_DIR}/workload-client.ext"
CA_SERIAL="${OUTPUT_DIR}/ca.srl"

have_required_files="true"
for required_file in \
  "${CA_KEY}" \
  "${CA_CERT}" \
  "${SERVER_KEY}" \
  "${SERVER_CERT}" \
  "${HEALTHCHECK_KEY}" \
  "${HEALTHCHECK_CERT}" \
  "${WORKLOAD_KEY}" \
  "${WORKLOAD_CERT}"; do
  if [ ! -f "${required_file}" ]; then
    have_required_files="false"
    break
  fi
done

if [ "${FORCE_ROTATE}" = "false" ] && [ "${have_required_files}" = "true" ]; then
  renew_before_seconds=$((RENEW_BEFORE_DAYS * 24 * 60 * 60))
  if \
    openssl x509 -checkend "${renew_before_seconds}" -noout -in "${CA_CERT}" >/dev/null 2>&1 && \
    openssl x509 -checkend "${renew_before_seconds}" -noout -in "${SERVER_CERT}" >/dev/null 2>&1 && \
    openssl x509 -checkend "${renew_before_seconds}" -noout -in "${HEALTHCHECK_CERT}" >/dev/null 2>&1 && \
    openssl x509 -checkend "${renew_before_seconds}" -noout -in "${WORKLOAD_CERT}" >/dev/null 2>&1; then
    echo "Existing broker-api dev mTLS certificates are valid for at least ${RENEW_BEFORE_DAYS} days."
    echo "Use --force to rotate immediately."
    exit 0
  fi
fi

rm -f \
  "${CA_KEY}" \
  "${CA_CERT}" \
  "${SERVER_KEY}" \
  "${SERVER_CERT}" \
  "${HEALTHCHECK_KEY}" \
  "${HEALTHCHECK_CERT}" \
  "${WORKLOAD_KEY}" \
  "${WORKLOAD_CERT}" \
  "${CA_SERIAL}"

openssl req \
  -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -days "${VALIDITY_DAYS}" \
  -nodes \
  -keyout "${CA_KEY}" \
  -out "${CA_CERT}" \
  -subj "/CN=broker-api-dev-ca"

cat >"${SERVER_EXT}" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl req \
  -newkey rsa:2048 \
  -nodes \
  -keyout "${SERVER_KEY}" \
  -out "${SERVER_CSR}" \
  -subj "/CN=broker-api.local"

openssl x509 \
  -req \
  -in "${SERVER_CSR}" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -CAcreateserial \
  -out "${SERVER_CERT}" \
  -days "${VALIDITY_DAYS}" \
  -sha256 \
  -extfile "${SERVER_EXT}"

cat >"${HEALTHCHECK_EXT}" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

openssl req \
  -newkey rsa:2048 \
  -nodes \
  -keyout "${HEALTHCHECK_KEY}" \
  -out "${HEALTHCHECK_CSR}" \
  -subj "/CN=broker-api-healthcheck"

openssl x509 \
  -req \
  -in "${HEALTHCHECK_CSR}" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -out "${HEALTHCHECK_CERT}" \
  -days "${VALIDITY_DAYS}" \
  -sha256 \
  -extfile "${HEALTHCHECK_EXT}" \
  -CAserial "${CA_SERIAL}"

cat >"${WORKLOAD_EXT}" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://broker/tenants/t_1/workloads/w_1
EOF

openssl req \
  -newkey rsa:2048 \
  -nodes \
  -keyout "${WORKLOAD_KEY}" \
  -out "${WORKLOAD_CSR}" \
  -subj "/CN=broker-workload-t1-w1"

openssl x509 \
  -req \
  -in "${WORKLOAD_CSR}" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -out "${WORKLOAD_CERT}" \
  -days "${VALIDITY_DAYS}" \
  -sha256 \
  -extfile "${WORKLOAD_EXT}" \
  -CAserial "${CA_SERIAL}"

rm -f "${SERVER_CSR}" "${SERVER_EXT}" "${HEALTHCHECK_CSR}" "${HEALTHCHECK_EXT}" "${WORKLOAD_CSR}" "${WORKLOAD_EXT}"

echo "Generated broker-api development mTLS certificates in ${OUTPUT_DIR}:"
echo "  - CA: ${CA_CERT}"
echo "  - Server cert/key: ${SERVER_CERT}, ${SERVER_KEY}"
echo "  - Healthcheck client cert/key: ${HEALTHCHECK_CERT}, ${HEALTHCHECK_KEY}"
echo "  - Workload client cert/key: ${WORKLOAD_CERT}, ${WORKLOAD_KEY}"
