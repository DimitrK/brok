CREATE TYPE "AdminNewUserMode" AS ENUM ('allowed', 'blocked');
CREATE TYPE "AdminIdentityStatus" AS ENUM ('active', 'pending', 'disabled');
CREATE TYPE "AdminAccessRequestStatus" AS ENUM ('pending', 'approved', 'denied', 'canceled');

CREATE TABLE "admin_signup_policy" (
  "id" TEXT NOT NULL,
  "new_user_mode" "AdminNewUserMode" NOT NULL DEFAULT 'blocked',
  "require_verified_email" BOOLEAN NOT NULL DEFAULT TRUE,
  "allowed_email_domains" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "updated_by" TEXT NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "admin_signup_policy_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_admin_signup_policy_singleton" CHECK ("id" = 'default')
);

CREATE TABLE "admin_identities" (
  "id" TEXT NOT NULL,
  "identity_id" TEXT NOT NULL,
  "issuer" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "name" TEXT,
  "status" "AdminIdentityStatus" NOT NULL DEFAULT 'active',
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "admin_identities_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_admin_identities_issuer_nonempty" CHECK (length("issuer") > 0),
  CONSTRAINT "ck_admin_identities_subject_nonempty" CHECK (length("subject") > 0),
  CONSTRAINT "ck_admin_identities_email_nonempty" CHECK (length("email") > 0)
);

CREATE TABLE "admin_identity_role_bindings" (
  "id" TEXT NOT NULL,
  "identity_id" TEXT NOT NULL,
  "role" "UserRole" NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "admin_identity_role_bindings_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "admin_identity_tenant_scopes" (
  "id" TEXT NOT NULL,
  "identity_id" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "admin_identity_tenant_scopes_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "admin_access_requests" (
  "id" TEXT NOT NULL,
  "request_id" TEXT NOT NULL,
  "issuer" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "name" TEXT,
  "requested_roles" "UserRole"[] NOT NULL DEFAULT ARRAY[]::"UserRole"[],
  "requested_tenant_ids" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "status" "AdminAccessRequestStatus" NOT NULL DEFAULT 'pending',
  "request_reason" TEXT,
  "decision_reason" TEXT,
  "decided_by" TEXT,
  "decided_at" TIMESTAMPTZ,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "admin_access_requests_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ck_admin_access_requests_principal_nonempty" CHECK (
    length("issuer") > 0 AND length("subject") > 0 AND length("email") > 0
  ),
  CONSTRAINT "ck_admin_access_requests_roles_nonempty" CHECK (cardinality("requested_roles") >= 1),
  CONSTRAINT "ck_admin_access_requests_decision_fields" CHECK (
    (
      "status" = 'pending'
      AND "decided_by" IS NULL
      AND "decided_at" IS NULL
      AND "decision_reason" IS NULL
    ) OR (
      "status" <> 'pending'
      AND "decided_by" IS NOT NULL
      AND "decided_at" IS NOT NULL
    )
  )
);

CREATE UNIQUE INDEX "admin_identities_identity_id_key" ON "admin_identities"("identity_id");
CREATE UNIQUE INDEX "uq_admin_identities_issuer_subject" ON "admin_identities"("issuer", "subject");
CREATE INDEX "idx_admin_identities_email" ON "admin_identities"("email");
CREATE INDEX "idx_admin_identities_status" ON "admin_identities"("status");

CREATE UNIQUE INDEX "uq_admin_identity_role_bindings_identity_role"
  ON "admin_identity_role_bindings"("identity_id", "role");
CREATE INDEX "idx_admin_identity_role_bindings_role"
  ON "admin_identity_role_bindings"("role");

CREATE UNIQUE INDEX "uq_admin_identity_tenant_scopes_identity_tenant"
  ON "admin_identity_tenant_scopes"("identity_id", "tenant_id");
CREATE INDEX "idx_admin_identity_tenant_scopes_tenant"
  ON "admin_identity_tenant_scopes"("tenant_id");

CREATE UNIQUE INDEX "admin_access_requests_request_id_key" ON "admin_access_requests"("request_id");
CREATE INDEX "idx_admin_access_requests_principal_status"
  ON "admin_access_requests"("issuer", "subject", "status");
CREATE INDEX "idx_admin_access_requests_status_created_at"
  ON "admin_access_requests"("status", "created_at" ASC);
CREATE INDEX "idx_admin_access_requests_email_created_at"
  ON "admin_access_requests"("email", "created_at" ASC);
CREATE UNIQUE INDEX "uq_admin_access_requests_pending_per_principal"
  ON "admin_access_requests"("issuer", "subject") WHERE "status" = 'pending';

ALTER TABLE "admin_identity_role_bindings"
  ADD CONSTRAINT "admin_identity_role_bindings_identity_id_fkey"
  FOREIGN KEY ("identity_id") REFERENCES "admin_identities"("identity_id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "admin_identity_tenant_scopes"
  ADD CONSTRAINT "admin_identity_tenant_scopes_identity_id_fkey"
  FOREIGN KEY ("identity_id") REFERENCES "admin_identities"("identity_id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "admin_identity_tenant_scopes"
  ADD CONSTRAINT "admin_identity_tenant_scopes_tenant_id_fkey"
  FOREIGN KEY ("tenant_id") REFERENCES "tenants"("tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

INSERT INTO "admin_signup_policy" (
  "id",
  "new_user_mode",
  "require_verified_email",
  "allowed_email_domains",
  "updated_by"
) VALUES (
  'default',
  'blocked',
  TRUE,
  ARRAY[]::TEXT[],
  'system'
);
