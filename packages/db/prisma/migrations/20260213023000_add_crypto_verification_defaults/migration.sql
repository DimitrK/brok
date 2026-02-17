CREATE TABLE "crypto_verification_defaults" (
  "id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "require_temporal_validity" BOOLEAN NOT NULL DEFAULT TRUE,
  "max_clock_skew_seconds" INTEGER NOT NULL DEFAULT 0,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "crypto_verification_defaults_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "uq_crypto_verification_defaults_tenant_id" UNIQUE ("tenant_id"),
  CONSTRAINT "ck_crypto_verification_defaults_max_clock_skew_seconds" CHECK (
    "max_clock_skew_seconds" >= 0 AND "max_clock_skew_seconds" <= 300
  )
);

CREATE INDEX "idx_crypto_verification_defaults_tenant_id"
  ON "crypto_verification_defaults"("tenant_id");

ALTER TABLE "crypto_verification_defaults"
  ADD CONSTRAINT "crypto_verification_defaults_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;
