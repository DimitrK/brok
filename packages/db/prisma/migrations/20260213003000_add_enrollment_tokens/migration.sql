CREATE TABLE "enrollment_tokens" (
  "id" TEXT NOT NULL,
  "token_hash" TEXT NOT NULL,
  "workload_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "expires_at" TIMESTAMPTZ NOT NULL,
  "used_at" TIMESTAMPTZ,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "enrollment_tokens_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_enrollment_tokens_token_hash" CHECK ("token_hash" ~ '^[a-f0-9]{64}$'),
  CONSTRAINT "ck_enrollment_tokens_expires_after_created" CHECK ("expires_at" > "created_at"),
  CONSTRAINT "ck_enrollment_tokens_used_after_created" CHECK (
    "used_at" IS NULL OR "used_at" >= "created_at"
  )
);

CREATE UNIQUE INDEX "enrollment_tokens_token_hash_key" ON "enrollment_tokens"("token_hash");
CREATE INDEX "idx_enrollment_tokens_tenant_workload" ON "enrollment_tokens"("tenant_id", "workload_id");
CREATE INDEX "idx_enrollment_tokens_expires_at" ON "enrollment_tokens"("expires_at");
CREATE INDEX "idx_enrollment_tokens_used_at" ON "enrollment_tokens"("used_at");

ALTER TABLE "enrollment_tokens"
  ADD CONSTRAINT "enrollment_tokens_workload_id_fkey"
  FOREIGN KEY ("workload_id") REFERENCES "workloads"("workload_id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "enrollment_tokens"
  ADD CONSTRAINT "enrollment_tokens_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;
