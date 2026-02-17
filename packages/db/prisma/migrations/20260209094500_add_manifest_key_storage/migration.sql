-- Create enums
CREATE TYPE "ManifestSigningAlgorithm" AS ENUM ('EdDSA', 'ES256');
CREATE TYPE "ManifestSigningKeyStatus" AS ENUM ('active', 'retired', 'revoked');

-- Create tables
CREATE TABLE "manifest_signing_keys" (
  "id" TEXT NOT NULL,
  "kid" TEXT NOT NULL,
  "alg" "ManifestSigningAlgorithm" NOT NULL,
  "public_jwk" JSONB NOT NULL,
  "private_key_ref" TEXT NOT NULL,
  "status" "ManifestSigningKeyStatus" NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "activated_at" TIMESTAMPTZ,
  "retired_at" TIMESTAMPTZ,
  "revoked_at" TIMESTAMPTZ,
  CONSTRAINT "manifest_signing_keys_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_manifest_signing_keys_kid_nonempty" CHECK (length("kid") > 0),
  CONSTRAINT "ck_manifest_signing_keys_private_ref_nonempty" CHECK (length("private_key_ref") > 0),
  CONSTRAINT "ck_manifest_signing_keys_status_timestamps" CHECK (
    (
      "status" = 'active'
      AND "activated_at" IS NOT NULL
      AND "retired_at" IS NULL
      AND "revoked_at" IS NULL
    ) OR (
      "status" = 'retired'
      AND "retired_at" IS NOT NULL
      AND "revoked_at" IS NULL
    ) OR (
      "status" = 'revoked'
      AND "revoked_at" IS NOT NULL
    )
  )
);

CREATE TABLE "manifest_keyset_metadata" (
  "id" TEXT NOT NULL,
  "keyset_name" TEXT NOT NULL,
  "etag" TEXT NOT NULL,
  "generated_at" TIMESTAMPTZ NOT NULL,
  "max_age_seconds" INTEGER NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "manifest_keyset_metadata_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_manifest_keyset_metadata_etag" CHECK ("etag" ~ '^W/".+"$'),
  CONSTRAINT "ck_manifest_keyset_metadata_max_age" CHECK ("max_age_seconds" >= 30 AND "max_age_seconds" <= 300)
);

-- Create indexes
CREATE UNIQUE INDEX "manifest_signing_keys_kid_key" ON "manifest_signing_keys"("kid");
CREATE INDEX "idx_manifest_signing_keys_status_activated_at" ON "manifest_signing_keys"("status", "activated_at" DESC);
CREATE INDEX "idx_manifest_signing_keys_status_created_at" ON "manifest_signing_keys"("status", "created_at" DESC);
CREATE UNIQUE INDEX "uq_manifest_signing_keys_single_active" ON "manifest_signing_keys"("status") WHERE "status" = 'active';

CREATE UNIQUE INDEX "manifest_keyset_metadata_keyset_name_key" ON "manifest_keyset_metadata"("keyset_name");
