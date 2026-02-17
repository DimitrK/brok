CREATE TABLE "audit_redaction_profiles" (
  "id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "profile_id" TEXT NOT NULL,
  "profile_json" JSONB NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_redaction_profiles_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "audit_redaction_profiles_tenant_id_key" ON "audit_redaction_profiles"("tenant_id");

ALTER TABLE "audit_redaction_profiles"
  ADD CONSTRAINT "audit_redaction_profiles_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;
