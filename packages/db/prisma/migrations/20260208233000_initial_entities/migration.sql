-- Create enums
CREATE TYPE "UserRole" AS ENUM ('owner', 'admin', 'auditor', 'operator');
CREATE TYPE "WorkloadEnrollmentMode" AS ENUM ('broker_ca', 'external_ca');
CREATE TYPE "SecretType" AS ENUM ('api_key', 'oauth_refresh_token');
CREATE TYPE "TemplateStatus" AS ENUM ('active', 'disabled');
CREATE TYPE "PolicyRuleType" AS ENUM ('allow', 'deny', 'approval_required', 'rate_limit');
CREATE TYPE "ApprovalStatus" AS ENUM ('pending', 'approved', 'denied', 'expired', 'executed', 'canceled');
CREATE TYPE "RiskTier" AS ENUM ('low', 'medium', 'high');
CREATE TYPE "AuditEventType" AS ENUM (
  'session_issued',
  'execute',
  'policy_decision',
  'approval_created',
  'approval_decided',
  'violation',
  'throttle',
  'sandbox_alert',
  'admin_action'
);
CREATE TYPE "AuditDecision" AS ENUM ('allowed', 'denied', 'approval_required', 'throttled');

-- Create tables
CREATE TABLE "tenants" (
  "id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "tenants_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "human_users" (
  "id" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "display_name" TEXT,
  "oidc_subject" TEXT,
  "oidc_issuer" TEXT,
  "enabled" BOOLEAN NOT NULL DEFAULT TRUE,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "human_users_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "human_user_roles" (
  "id" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  "role" "UserRole" NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "human_user_roles_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "workloads" (
  "id" TEXT NOT NULL,
  "workload_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "mtls_san_uri" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL,
  "ip_allowlist" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "enrollment_mode" "WorkloadEnrollmentMode" NOT NULL DEFAULT 'broker_ca',
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "workloads_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "workload_sessions" (
  "id" TEXT NOT NULL,
  "session_id" TEXT NOT NULL,
  "workload_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "cert_fingerprint_256" TEXT NOT NULL,
  "token_hash" TEXT NOT NULL,
  "dpop_jkt" TEXT,
  "scopes" JSONB NOT NULL,
  "expires_at" TIMESTAMPTZ NOT NULL,
  "revoked_at" TIMESTAMPTZ,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "workload_sessions_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "integrations" (
  "id" TEXT NOT NULL,
  "integration_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "provider" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "template_id" TEXT NOT NULL,
  "template_version" INTEGER,
  "enabled" BOOLEAN NOT NULL,
  "secret_ref" TEXT,
  "secret_version" INTEGER,
  "last_rotated_at" TIMESTAMPTZ,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "integrations_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_integrations_template_version_positive" CHECK ("template_version" IS NULL OR "template_version" >= 1),
  CONSTRAINT "ck_integrations_secret_pointer" CHECK (
    (
      "secret_ref" IS NULL AND "secret_version" IS NULL
    ) OR (
      "secret_ref" IS NOT NULL AND "secret_version" IS NOT NULL AND "secret_version" >= 1
    )
  )
);

CREATE TABLE "secrets" (
  "id" TEXT NOT NULL,
  "secret_ref" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "integration_id" TEXT NOT NULL,
  "type" "SecretType" NOT NULL,
  "active_version" INTEGER NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "secrets_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_secrets_active_version_positive" CHECK ("active_version" >= 1)
);

CREATE TABLE "secret_versions" (
  "id" TEXT NOT NULL,
  "secret_ref" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "key_id" TEXT NOT NULL,
  "content_encryption_alg" TEXT NOT NULL,
  "key_encryption_alg" TEXT NOT NULL,
  "wrapped_data_key_b64" TEXT NOT NULL,
  "iv_b64" TEXT NOT NULL,
  "ciphertext_b64" TEXT NOT NULL,
  "auth_tag_b64" TEXT NOT NULL,
  "aad_b64" TEXT,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "secret_versions_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_secret_versions_version_positive" CHECK ("version" >= 1),
  CONSTRAINT "ck_secret_versions_alg" CHECK ("content_encryption_alg" = 'A256GCM'),
  CONSTRAINT "ck_secret_versions_required_payload" CHECK (
    length("key_id") > 0
    AND length("key_encryption_alg") > 0
    AND length("wrapped_data_key_b64") > 0
    AND length("iv_b64") > 0
    AND length("ciphertext_b64") > 0
    AND length("auth_tag_b64") > 0
    AND (
      "aad_b64" IS NULL OR length("aad_b64") > 0
    )
  )
);

CREATE TABLE "template_versions" (
  "id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "template_id" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "provider" TEXT NOT NULL,
  "status" "TemplateStatus" NOT NULL DEFAULT 'active',
  "template_json" JSONB NOT NULL,
  "published_by" TEXT,
  "published_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "template_versions_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_template_versions_version_positive" CHECK ("version" >= 1)
);

CREATE TABLE "policy_rules" (
  "id" TEXT NOT NULL,
  "policy_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT TRUE,
  "rule_type" "PolicyRuleType" NOT NULL,
  "workload_id" TEXT,
  "integration_id" TEXT NOT NULL,
  "template_id" TEXT,
  "template_version" INTEGER,
  "action_group" TEXT NOT NULL,
  "method" TEXT NOT NULL,
  "host" TEXT NOT NULL,
  "query_keys" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "constraints_json" JSONB,
  "rate_limit_max_requests" INTEGER,
  "rate_limit_interval_seconds" INTEGER,
  "policy_json" JSONB NOT NULL,
  "created_by" TEXT,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "policy_rules_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_policy_rules_template_version_positive" CHECK (
    "template_version" IS NULL OR "template_version" >= 1
  ),
  CONSTRAINT "ck_policy_rules_scope_method" CHECK (
    "method" IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
  ),
  CONSTRAINT "ck_policy_rules_scope_host" CHECK (
    "host" <> ''
    AND position('*' in "host") = 0
    AND position('://' in "host") = 0
    AND position('/' in "host") = 0
    AND position('?' in "host") = 0
    AND position('#' in "host") = 0
    AND position('@' in "host") = 0
    AND right("host", 1) <> '.'
  ),
  CONSTRAINT "ck_policy_rules_rate_limit_shape" CHECK (
    (
      "rule_type" = 'rate_limit'
      AND "rate_limit_max_requests" IS NOT NULL
      AND "rate_limit_interval_seconds" IS NOT NULL
      AND "rate_limit_max_requests" >= 1
      AND "rate_limit_interval_seconds" >= 1
    ) OR (
      "rule_type" <> 'rate_limit'
      AND "rate_limit_max_requests" IS NULL
      AND "rate_limit_interval_seconds" IS NULL
    )
  )
);

CREATE TABLE "approval_requests" (
  "id" TEXT NOT NULL,
  "approval_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "status" "ApprovalStatus" NOT NULL,
  "expires_at" TIMESTAMPTZ NOT NULL,
  "correlation_id" TEXT NOT NULL,
  "workload_id" TEXT NOT NULL,
  "integration_id" TEXT NOT NULL,
  "action_group" TEXT NOT NULL,
  "risk_tier" "RiskTier" NOT NULL,
  "destination_host" TEXT NOT NULL,
  "method" TEXT NOT NULL,
  "path" TEXT NOT NULL,
  "descriptor_sha256" TEXT NOT NULL,
  "canonical_descriptor" JSONB NOT NULL,
  "approval_json" JSONB NOT NULL,
  "decided_at" TIMESTAMPTZ,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "approval_requests_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_approval_requests_method" CHECK (
    "method" IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
  ),
  CONSTRAINT "ck_approval_requests_descriptor_sha" CHECK (
    "descriptor_sha256" ~ '^[a-f0-9]{64}$'
  )
);

CREATE TABLE "audit_events" (
  "id" TEXT NOT NULL,
  "event_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "timestamp" TIMESTAMPTZ NOT NULL,
  "workload_id" TEXT,
  "integration_id" TEXT,
  "correlation_id" TEXT NOT NULL,
  "event_type" "AuditEventType" NOT NULL,
  "decision" "AuditDecision",
  "action_group" TEXT,
  "risk_tier" "RiskTier",
  "upstream_status_code" INTEGER,
  "latency_ms" INTEGER,
  "event_json" JSONB NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_audit_events_upstream_status_code" CHECK (
    "upstream_status_code" IS NULL OR (
      "upstream_status_code" >= 100 AND "upstream_status_code" <= 599
    )
  ),
  CONSTRAINT "ck_audit_events_latency_ms" CHECK (
    "latency_ms" IS NULL OR "latency_ms" >= 0
  )
);

-- Create unique constraints and indexes
CREATE UNIQUE INDEX "tenants_tenant_id_key" ON "tenants"("tenant_id");

CREATE UNIQUE INDEX "human_users_user_id_key" ON "human_users"("user_id");
CREATE UNIQUE INDEX "uq_human_users_tenant_email" ON "human_users"("tenant_id", "email");
CREATE INDEX "idx_human_users_tenant" ON "human_users"("tenant_id");

CREATE UNIQUE INDEX "uq_human_user_roles_user_role" ON "human_user_roles"("user_id", "role");
CREATE INDEX "idx_human_user_roles_role" ON "human_user_roles"("role");

CREATE UNIQUE INDEX "workloads_workload_id_key" ON "workloads"("workload_id");
CREATE UNIQUE INDEX "workloads_mtls_san_uri_key" ON "workloads"("mtls_san_uri");
CREATE UNIQUE INDEX "uq_workloads_tenant_name" ON "workloads"("tenant_id", "name");
CREATE INDEX "idx_workloads_tenant" ON "workloads"("tenant_id");

CREATE UNIQUE INDEX "workload_sessions_session_id_key" ON "workload_sessions"("session_id");
CREATE UNIQUE INDEX "workload_sessions_token_hash_key" ON "workload_sessions"("token_hash");
CREATE INDEX "idx_workload_sessions_tenant_workload" ON "workload_sessions"("tenant_id", "workload_id");
CREATE INDEX "idx_workload_sessions_expires_at" ON "workload_sessions"("expires_at");
CREATE INDEX "idx_workload_sessions_revoked_at" ON "workload_sessions"("revoked_at");

CREATE UNIQUE INDEX "integrations_integration_id_key" ON "integrations"("integration_id");
CREATE UNIQUE INDEX "integrations_secret_ref_key" ON "integrations"("secret_ref");
CREATE UNIQUE INDEX "uq_integrations_tenant_name" ON "integrations"("tenant_id", "name");
CREATE INDEX "idx_integrations_tenant" ON "integrations"("tenant_id");
CREATE INDEX "idx_integrations_template" ON "integrations"("tenant_id", "template_id");

CREATE UNIQUE INDEX "secrets_secret_ref_key" ON "secrets"("secret_ref");
CREATE UNIQUE INDEX "secrets_integration_id_key" ON "secrets"("integration_id");
CREATE INDEX "idx_secrets_tenant" ON "secrets"("tenant_id");
CREATE INDEX "idx_secrets_tenant_integration" ON "secrets"("tenant_id", "integration_id");

CREATE UNIQUE INDEX "uq_secret_versions_secret_ref_version" ON "secret_versions"("secret_ref", "version");
CREATE INDEX "idx_secret_versions_secret_ref_created_at" ON "secret_versions"("secret_ref", "created_at");

CREATE UNIQUE INDEX "uq_template_versions_tenant_template_version" ON "template_versions"("tenant_id", "template_id", "version");
CREATE INDEX "idx_template_versions_tenant_template" ON "template_versions"("tenant_id", "template_id");
CREATE INDEX "idx_template_versions_tenant_template_status" ON "template_versions"("tenant_id", "template_id", "status");

CREATE UNIQUE INDEX "policy_rules_policy_id_key" ON "policy_rules"("policy_id");
CREATE INDEX "idx_policy_rules_primary_scope" ON "policy_rules"("tenant_id", "integration_id", "action_group", "method", "host");
CREATE INDEX "idx_policy_rules_workload_scope" ON "policy_rules"("tenant_id", "workload_id");
CREATE INDEX "idx_policy_rules_enabled" ON "policy_rules"("enabled");

CREATE UNIQUE INDEX "approval_requests_approval_id_key" ON "approval_requests"("approval_id");
CREATE INDEX "idx_approval_requests_scope" ON "approval_requests"("tenant_id", "workload_id", "integration_id");
CREATE INDEX "idx_approval_requests_status_expires_at" ON "approval_requests"("status", "expires_at");
CREATE INDEX "idx_approval_requests_descriptor_sha" ON "approval_requests"("descriptor_sha256");
CREATE UNIQUE INDEX "uq_approval_requests_pending_descriptor" ON "approval_requests"("tenant_id", "workload_id", "integration_id", "descriptor_sha256") WHERE "status" = 'pending';

CREATE UNIQUE INDEX "audit_events_event_id_key" ON "audit_events"("event_id");
CREATE INDEX "idx_audit_events_tenant_timestamp" ON "audit_events"("tenant_id", "timestamp" DESC);
CREATE INDEX "idx_audit_events_tenant_workload_timestamp" ON "audit_events"("tenant_id", "workload_id", "timestamp" DESC);
CREATE INDEX "idx_audit_events_tenant_integration_timestamp" ON "audit_events"("tenant_id", "integration_id", "timestamp" DESC);
CREATE INDEX "idx_audit_events_tenant_action_group_timestamp" ON "audit_events"("tenant_id", "action_group", "timestamp" DESC);
CREATE INDEX "idx_audit_events_tenant_decision_timestamp" ON "audit_events"("tenant_id", "decision", "timestamp" DESC);
CREATE INDEX "idx_audit_events_correlation" ON "audit_events"("correlation_id");

-- Add foreign keys
ALTER TABLE "human_users"
  ADD CONSTRAINT "human_users_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "human_user_roles"
  ADD CONSTRAINT "human_user_roles_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "human_users"("user_id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "workloads"
  ADD CONSTRAINT "workloads_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "workload_sessions"
  ADD CONSTRAINT "workload_sessions_workload_id_fkey"
  FOREIGN KEY ("workload_id") REFERENCES "workloads"("workload_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "workload_sessions"
  ADD CONSTRAINT "workload_sessions_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "integrations"
  ADD CONSTRAINT "integrations_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "secrets"
  ADD CONSTRAINT "secrets_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "secrets"
  ADD CONSTRAINT "secrets_integration_id_fkey"
  FOREIGN KEY ("integration_id") REFERENCES "integrations"("integration_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "secret_versions"
  ADD CONSTRAINT "secret_versions_secret_ref_fkey"
  FOREIGN KEY ("secret_ref") REFERENCES "secrets"("secret_ref") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "template_versions"
  ADD CONSTRAINT "template_versions_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "policy_rules"
  ADD CONSTRAINT "policy_rules_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "approval_requests"
  ADD CONSTRAINT "approval_requests_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "audit_events"
  ADD CONSTRAINT "audit_events_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "secrets"
  ADD CONSTRAINT "secrets_active_version_fkey"
  FOREIGN KEY ("secret_ref", "active_version")
  REFERENCES "secret_versions"("secret_ref", "version")
  DEFERRABLE INITIALLY DEFERRED;

-- Trigger function for updated_at maintenance
CREATE OR REPLACE FUNCTION "set_current_timestamp_updated_at"()
RETURNS TRIGGER AS $$
BEGIN
  NEW."updated_at" = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "trg_tenants_updated_at"
BEFORE UPDATE ON "tenants"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();

CREATE TRIGGER "trg_human_users_updated_at"
BEFORE UPDATE ON "human_users"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();

CREATE TRIGGER "trg_workloads_updated_at"
BEFORE UPDATE ON "workloads"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();

CREATE TRIGGER "trg_workload_sessions_updated_at"
BEFORE UPDATE ON "workload_sessions"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();

CREATE TRIGGER "trg_integrations_updated_at"
BEFORE UPDATE ON "integrations"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();

CREATE TRIGGER "trg_secrets_updated_at"
BEFORE UPDATE ON "secrets"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();

CREATE TRIGGER "trg_policy_rules_updated_at"
BEFORE UPDATE ON "policy_rules"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();

CREATE TRIGGER "trg_approval_requests_updated_at"
BEFORE UPDATE ON "approval_requests"
FOR EACH ROW EXECUTE FUNCTION "set_current_timestamp_updated_at"();
