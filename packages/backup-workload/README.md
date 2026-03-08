# Backup Workload

This workload exports and restores broker state through the normal broker execution path.

It backs up:

- Postgres data from `BACKUP_WORKLOAD_DATABASE_URL`
- `broker-admin-api` local CA material when `BROKER_ADMIN_API_CERT_ISSUER_MODE=local`
- `broker-api` TLS certificate directory when `BACKUP_WORKLOAD_BROKER_API_CERTS_DIR` is set
- Shared broker secret keys required to decrypt stored integration secrets

The bundle is:

- versioned with an auto-incrementing counter
- date-stamped in the backup id
- AES-256-GCM encrypted before upload
- stored in S3 as chunked objects so it does not depend on large broker request limits

## Run

Run this package from its own directory so it can use its package-local `.env` file:

```bash
cd packages/backup-workload
cp .env.example .env
```

Fill `.env` with the backup-workload-specific settings:

```dotenv
BACKUP_WORKLOAD_BROKER_URL=https://localhost:8081
BACKUP_WORKLOAD_WORKLOAD_ID=w_backup_workload
BACKUP_WORKLOAD_S3_INTEGRATION_ID=int_backup_primary
BACKUP_WORKLOAD_MTLS_CERT_PATH=./certs/workload.crt
BACKUP_WORKLOAD_MTLS_KEY_PATH=./certs/workload.key
BACKUP_WORKLOAD_MTLS_CA_PATH=./certs/ca-chain.pem

BACKUP_WORKLOAD_S3_ENDPOINT=https://backup-bucket.s3.eu-west-1.amazonaws.com
BACKUP_WORKLOAD_S3_PREFIX=backups/broker-prod
BACKUP_WORKLOAD_ENCRYPTION_KEY_B64=...
BACKUP_WORKLOAD_DATABASE_URL=postgresql://broker:broker@127.0.0.1:5432/broker
BACKUP_WORKLOAD_DB_DUMP_CONTAINER=broker-postgres
BROKER_ADMIN_API_SECRET_KEY_B64=...
BROKER_API_SECRET_KEY_B64=...
```

Then run the workload from the same directory:

```bash
pnpm run backup
```

The package launcher automatically loads `.env` and initializes `interceptor-node` programmatically with an explicit
integration override for the configured S3 endpoint. `BACKUP_WORKLOAD_S3_INTEGRATION_ID` is required so backup traffic
uses the intended broker integration even when multiple S3 integrations exist.

Restore requires an explicit confirmation token:

```bash
BACKUP_WORKLOAD_RESTORE_CONFIRM=RESTORE \
BACKUP_WORKLOAD_RESTORE_BROKER_API_CERTS_DIR=/run/certs/broker-api \
BACKUP_WORKLOAD_RESTORE_ADMIN_CA_CERT_PATH=/run/certs/broker-admin/ca.crt \
BACKUP_WORKLOAD_RESTORE_ADMIN_CA_KEY_PATH=/run/certs/broker-admin/ca.key \
pnpm run restore -- --version 12
```

The restore command prints the workspace containing:

- restored bundle contents
- `service-secrets.json` with the shared secret keys that must be re-applied to runtime configuration
- restore status for broker-api certs and broker-admin local CA files when destination paths are configured

## Required S3 Template Shape

Create the backup integration with the typed `IntegrationWrite.secret_material` DTO from
`packages/schemas/openapi.yaml` / `packages/schemas/integration-write.schema.json`. Do not wrap the credentials in a
JSON string.

Example admin API payload:

```json
{
  "provider": "aws_s3",
  "name": "broker-backups",
  "template_id": "tpl_backup_s3",
  "secret_material": {
    "type": "aws_sigv4",
    "access_key_id": "AKIA...",
    "secret_access_key": "...",
    "session_token": "...",
    "region": "eu-west-1"
  }
}
```

`session_token` is optional.

The S3 integration template must use a path-group constraint that tells broker-api to sign requests with AWS SigV4:

```json
{
  "constraints": {
    "upstream_auth": {
      "type": "aws_sigv4",
      "service": "s3"
    }
  }
}
```

The template must cover both request classes used by this package:

- bucket-root listing calls:
  `GET /?list-type=2&prefix=<configured-prefix>/[&continuation-token=<token>]`
- object reads and writes under the configured backup prefix:
  `GET /<prefix>/<backup-id>/...` and `PUT /<prefix>/<backup-id>/...`

Backup version discovery depends on the bucket-root `list-type=2` listing call before every upload and restore, so
that path group must be allowed explicitly.

For a complete example, use [`assets/s3-template.example.json`](./assets/s3-template.example.json).

## Region Rules

`secret_material.region` is always required by the DTO, including for S3-compatible endpoints that do not use an AWS
hostname. Set it to the signing region expected by that provider; do not rely on broker-side inference for non-AWS
hosts.

## Important

- A backup without `BROKER_ADMIN_API_SECRET_KEY_B64` and `BROKER_API_SECRET_KEY_B64` is incomplete for secret restoration.
- Prefer `BACKUP_WORKLOAD_DB_DUMP_CONTAINER=broker-postgres` for local Docker Compose environments so the dump uses the same PostgreSQL major version as the running database container.
- If you are not using the container path, `BACKUP_WORKLOAD_DB_DUMP_BIN` must point to a `pg_dump` binary whose major version matches the target PostgreSQL server. On Homebrew PostgreSQL 16 this is typically `/opt/homebrew/opt/postgresql@16/bin/pg_dump`.
- `BROKER_ADMIN_API_CERT_ISSUER_MODE=vault` cannot export Vault's internal CA private key; the backup records Vault dependency metadata instead.
- The restore path replays SQL into the target database. Use an empty or disposable database unless you intentionally want an in-place restore.
- Restore validates per-chunk and full-ciphertext SHA-256 before decrypting the bundle.
