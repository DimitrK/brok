import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';

import {afterEach, describe, expect, it} from 'vitest';

import type {AdminPrincipal} from '../auth';
import {ControlPlaneRepository} from '../repository';

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const directory = tempDirs.pop();
    if (!directory) {
      continue;
    }
    await rm(directory, {recursive: true, force: true});
  }
});

const makeTempStatePath = async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'broker-admin-repo-test-'));
  tempDirs.push(directory);
  return path.join(directory, 'state.json');
};

const makeAdmin = (): AdminPrincipal => ({
  subject: 'admin-user',
  issuer: 'https://broker-admin.local/static',
  email: 'admin-user@local.invalid',
  roles: ['owner'],
  authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
});

describe('control plane repository', () => {
  it('persists state and validates workload/ip operations', async () => {
    const statePath = await makeTempStatePath();
    const repository = await ControlPlaneRepository.create({
      statePath,
      manifestKeys: {keys: []},
      enrollmentTokenTtlSeconds: 600
    });

    const tenant = await repository.createTenant({name: 'Tenant A'});
    const workloadCreate = await repository.createWorkload({
      tenantId: tenant.tenant_id,
      name: 'workload-1',
      ipAllowlist: ['203.0.113.0/24']
    });

    expect(workloadCreate.workload.workload_id).toBeTypeOf('string');
    expect(workloadCreate.enrollmentToken).toBeTypeOf('string');

    await expect(
      repository.createWorkload({
        tenantId: tenant.tenant_id,
        name: 'workload-invalid',
        ipAllowlist: ['not-an-ip']
      })
    ).rejects.toMatchObject({code: 'ip_allowlist_invalid'});

    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Test fixture path is generated in-test and scoped to temp dir.
    const persisted = JSON.parse(await readFile(statePath, 'utf8')) as {
      tenants: Array<{tenant_id: string}>;
      workloads: Array<{workload_id: string}>;
    };
    expect(persisted.tenants).toHaveLength(1);
    expect(persisted.workloads).toHaveLength(1);
  });

  it('supports integration/template/policy lifecycle and audit filters', async () => {
    const repository = await ControlPlaneRepository.create({
      manifestKeys: {keys: []},
      enrollmentTokenTtlSeconds: 600
    });

    const tenant = await repository.createTenant({name: 'Tenant B'});
    await repository.createTemplate({
      payload: {
        template_id: 'tpl_openai_repo',
        version: 1,
        provider: 'openai',
        allowed_schemes: ['https'],
        allowed_ports: [443],
        allowed_hosts: ['api.openai.com'],
        redirect_policy: {mode: 'deny'},
        path_groups: [
          {
            group_id: 'openai_responses',
            risk_tier: 'low',
            approval_mode: 'none',
            methods: ['POST'],
            path_patterns: ['^/v1/responses$'],
            query_allowlist: [],
            header_forward_allowlist: ['content-type'],
            body_policy: {max_bytes: 4096, content_types: ['application/json']}
          }
        ],
        network_safety: {
          deny_private_ip_ranges: true,
          deny_link_local: true,
          deny_loopback: true,
          deny_metadata_ranges: true,
          dns_resolution_required: true
        }
      }
    });

    const integration = await repository.createIntegration({
      tenantId: tenant.tenant_id,
      payload: {
        provider: 'openai',
        name: 'openai',
        template_id: 'tpl_openai_repo',
        secret_material: {type: 'api_key', value: 'sk-secret'}
      },
      secretKey: Buffer.alloc(32, 1),
      secretKeyId: 'kid-1'
    });

    const updated = await repository.updateIntegration({
      integrationId: integration.integration_id,
      enabled: false
    });
    expect(updated.enabled).toBe(false);

    const policy = await repository.createPolicy({
      payload: {
        rule_type: 'allow',
        scope: {
          tenant_id: tenant.tenant_id,
          integration_id: integration.integration_id,
          action_group: 'openai_responses',
          method: 'POST',
          host: 'api.openai.com'
        },
        rate_limit: null
      }
    });
    expect(policy.policy_id).toBeTypeOf('string');

    const auditEvent = repository.createAdminAuditEvent({
      actor: makeAdmin(),
      correlationId: 'corr_1',
      action: 'integration.update',
      tenantId: tenant.tenant_id,
      integrationId: integration.integration_id
    });
    await repository.appendAuditEvent({event: auditEvent});

    const filtered = await repository.listAuditEvents({
      filter: {
        tenantId: tenant.tenant_id,
        integrationId: integration.integration_id
      }
    });
    expect(filtered).toHaveLength(1);

    await repository.deletePolicy({policyId: policy.policy_id ?? 'missing'});
    expect(await repository.listPolicies()).toHaveLength(0);
  });

  it('rotates enrollment tokens for existing workloads with explicit confirmation semantics', async () => {
    const repository = await ControlPlaneRepository.create({
      manifestKeys: {keys: []},
      enrollmentTokenTtlSeconds: 600
    });

    const tenant = await repository.createTenant({name: 'Tenant C'});
    const created = await repository.createWorkload({
      tenantId: tenant.tenant_id,
      name: 'workload-rotate'
    });

    const issuedBeforeEnrollment = await repository.issueWorkloadEnrollmentToken({
      workloadId: created.workload.workload_id,
      rotationMode: 'if_absent'
    });
    expect(issuedBeforeEnrollment.enrollmentToken).toBeTypeOf('string');
    expect(issuedBeforeEnrollment.enrollmentToken).not.toBe(created.enrollmentToken);

    await expect(
      repository.consumeEnrollmentToken({
        workloadId: created.workload.workload_id,
        enrollmentToken: created.enrollmentToken
      })
    ).rejects.toMatchObject({code: 'enrollment_token_used'});

    await expect(
      repository.consumeEnrollmentToken({
        workloadId: created.workload.workload_id,
        enrollmentToken: issuedBeforeEnrollment.enrollmentToken
      })
    ).resolves.toMatchObject({
      workload_id: created.workload.workload_id
    });

    await expect(
      repository.issueWorkloadEnrollmentToken({
        workloadId: created.workload.workload_id,
        rotationMode: 'if_absent'
      })
    ).rejects.toMatchObject({code: 'enrollment_token_rotation_confirmation_required'});

    const forcedRotationToken = await repository.issueWorkloadEnrollmentToken({
      workloadId: created.workload.workload_id,
      rotationMode: 'always'
    });
    expect(forcedRotationToken.enrollmentToken.length).toBeGreaterThan(10);
    expect(new Date(forcedRotationToken.expiresAt).toISOString()).toBe(forcedRotationToken.expiresAt);
  });

  it('loads approval state from disk and enforces approval transitions', async () => {
    const statePath = await makeTempStatePath();
    const now = Date.now();
    const expiredIso = new Date(now - 60_000).toISOString();
    const futureIso = new Date(now + 60_000).toISOString();

    const state = {
      version: 1,
      tenants: [{tenant_id: 't_1', name: 'Tenant A'}],
      workloads: [
        {
          workload_id: 'w_1',
          tenant_id: 't_1',
          name: 'workload',
          mtls_san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1',
          enabled: true
        }
      ],
      integrations: [
        {
          integration_id: 'i_1',
          tenant_id: 't_1',
          provider: 'openai',
          name: 'openai',
          template_id: 'tpl_1',
          enabled: true,
          secret_ref: 'sec_1',
          secret_version: 1,
          last_rotated_at: futureIso
        }
      ],
      templates: [],
      policies: [],
      approvals: [
        {
          approval_id: 'appr_expired',
          status: 'pending',
          expires_at: expiredIso,
          correlation_id: 'corr_expired',
          summary: {
            integration_id: 'i_1',
            action_group: 'openai_responses',
            risk_tier: 'low',
            destination_host: 'api.openai.com',
            method: 'POST',
            path: '/v1/responses'
          },
          canonical_descriptor: {
            tenant_id: 't_1',
            workload_id: 'w_1',
            integration_id: 'i_1',
            template_id: 'tpl_1',
            template_version: 1,
            method: 'POST',
            canonical_url: 'https://api.openai.com/v1/responses',
            matched_path_group_id: 'openai_responses',
            normalized_headers: [],
            query_keys: []
          }
        },
        {
          approval_id: 'appr_active',
          status: 'pending',
          expires_at: futureIso,
          correlation_id: 'corr_active',
          summary: {
            integration_id: 'i_1',
            action_group: 'openai_responses',
            risk_tier: 'low',
            destination_host: 'api.openai.com',
            method: 'POST',
            path: '/v1/responses'
          },
          canonical_descriptor: {
            tenant_id: 't_1',
            workload_id: 'w_1',
            integration_id: 'i_1',
            template_id: 'tpl_1',
            template_version: 1,
            method: 'POST',
            canonical_url: 'https://api.openai.com/v1/responses',
            matched_path_group_id: 'openai_responses',
            normalized_headers: [],
            query_keys: []
          }
        }
      ],
      audit_events: [],
      enrollment_tokens: [],
      secrets: [],
      manifest_keys: {keys: []}
    };
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Test fixture path is generated in-test and scoped to temp dir.
    await writeFile(statePath, JSON.stringify(state, null, 2), 'utf8');

    const repository = await ControlPlaneRepository.create({
      statePath,
      manifestKeys: {keys: []},
      enrollmentTokenTtlSeconds: 600
    });

    const approvals = await repository.listApprovals({});
    expect(approvals.find(item => item.approval_id === 'appr_expired')?.status).toBe('expired');

    const approved = await repository.decideApproval({
      approvalId: 'appr_active',
      decision: 'approved',
      request: {mode: 'rule'}
    });
    expect(approved.approval.status).toBe('approved');
    expect(approved.derivedPolicy?.rule_type).toBe('allow');
  });
});
