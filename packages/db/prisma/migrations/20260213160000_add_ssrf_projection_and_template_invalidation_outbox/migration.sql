-- Create enum
CREATE TYPE "TemplateInvalidationOutboxStatus" AS ENUM ('pending', 'delivered', 'failed');

-- Create table
CREATE TABLE "ssrf_guard_decisions" (
  "id" TEXT NOT NULL,
  "event_id" TEXT NOT NULL,
  "timestamp" TIMESTAMPTZ NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "workload_id" TEXT NOT NULL,
  "integration_id" TEXT NOT NULL,
  "template_id" TEXT NOT NULL,
  "template_version" INTEGER NOT NULL,
  "destination_host" TEXT NOT NULL,
  "destination_port" INTEGER NOT NULL,
  "resolved_ips" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "decision" "AuditDecision" NOT NULL,
  "reason_code" TEXT NOT NULL,
  "correlation_id" TEXT NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ssrf_guard_decisions_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_ssrf_guard_decisions_template_version_positive" CHECK ("template_version" >= 1),
  CONSTRAINT "ck_ssrf_guard_decisions_destination_port_range" CHECK ("destination_port" >= 1 AND "destination_port" <= 65535),
  CONSTRAINT "ck_ssrf_guard_decisions_resolved_ips_nonempty" CHECK (cardinality("resolved_ips") >= 1 AND cardinality("resolved_ips") <= 32),
  CONSTRAINT "ck_ssrf_guard_decisions_decision" CHECK ("decision" IN ('allowed', 'denied')),
  CONSTRAINT "ck_ssrf_guard_decisions_reason_code" CHECK (
    "reason_code" IN (
      'invalid_input',
      'request_url_invalid',
      'request_url_userinfo_forbidden',
      'request_url_fragment_forbidden',
      'request_scheme_not_allowed',
      'request_host_not_allowed',
      'request_port_not_allowed',
      'request_ip_literal_forbidden',
      'template_host_invalid',
      'dns_resolution_required',
      'dns_resolution_failed',
      'dns_resolution_empty',
      'resolved_ip_invalid',
      'resolved_ip_denied_private_range',
      'resolved_ip_denied_loopback',
      'resolved_ip_denied_link_local',
      'resolved_ip_denied_metadata_range',
      'redirect_denied'
    )
  )
);

CREATE TABLE "template_invalidation_outbox" (
  "id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "template_id" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "updated_at_signal" TIMESTAMPTZ NOT NULL,
  "payload_json" JSONB NOT NULL,
  "status" "TemplateInvalidationOutboxStatus" NOT NULL DEFAULT 'pending',
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "delivered_at" TIMESTAMPTZ,
  "last_error" TEXT,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "template_invalidation_outbox_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_template_invalidation_outbox_version_positive" CHECK ("version" >= 1),
  CONSTRAINT "ck_template_invalidation_outbox_attempts_nonnegative" CHECK ("attempts" >= 0)
);

-- Create indexes
CREATE UNIQUE INDEX "ssrf_guard_decisions_event_id_key" ON "ssrf_guard_decisions"("event_id");
CREATE INDEX "idx_ssrf_guard_decisions_tenant_timestamp" ON "ssrf_guard_decisions"("tenant_id", "timestamp" DESC);
CREATE INDEX "idx_ssrf_guard_decisions_reason_timestamp" ON "ssrf_guard_decisions"("reason_code", "timestamp" DESC);
CREATE INDEX "idx_ssrf_guard_decisions_host_timestamp" ON "ssrf_guard_decisions"("destination_host", "timestamp" DESC);

CREATE UNIQUE INDEX "uq_template_invalidation_outbox_signal"
  ON "template_invalidation_outbox"("tenant_id", "template_id", "version", "updated_at_signal");
CREATE INDEX "idx_template_invalidation_outbox_status_created_at"
  ON "template_invalidation_outbox"("status", "created_at" ASC);
CREATE INDEX "idx_template_invalidation_outbox_tenant_created_at"
  ON "template_invalidation_outbox"("tenant_id", "created_at" ASC);

-- Add foreign keys
ALTER TABLE "ssrf_guard_decisions"
  ADD CONSTRAINT "ssrf_guard_decisions_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "template_invalidation_outbox"
  ADD CONSTRAINT "template_invalidation_outbox_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;
