/* eslint-disable @typescript-eslint/require-await */
import {beforeEach, describe, expect, it, vi} from 'vitest';

import type {
  ApprovalRequest,
  OpenApiAuditEvent,
  OpenApiIntegration,
  OpenApiManifestKeys,
  OpenApiPolicyRule,
  OpenApiTemplate,
  OpenApiTenantSummary,
  OpenApiWorkload
} from '@broker-interceptor/schemas';

import type {ProcessInfrastructure} from '../infrastructure';

type DbErrorCode =
  | 'validation_error'
  | 'unique_violation'
  | 'conflict'
  | 'not_found'
  | 'integrity_violation'
  | 'state_transition_invalid'
  | 'dependency_missing'
  | 'unexpected_error';

class MockDbRepositoryError extends Error {
  public constructor(
    public readonly code: DbErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'DbRepositoryError';
  }
}

type DbFixture = {
  repositories: {
    adminAuthRepository: {
      getAdminSignupPolicy: ReturnType<typeof vi.fn>;
      setAdminSignupPolicy: ReturnType<typeof vi.fn>;
      listAdminIdentities: ReturnType<typeof vi.fn>;
      getAdminIdentityById: ReturnType<typeof vi.fn>;
      findAdminIdentityByIssuerSubject: ReturnType<typeof vi.fn>;
      createAdminIdentity: ReturnType<typeof vi.fn>;
      updateAdminIdentityStatus: ReturnType<typeof vi.fn>;
      updateAdminIdentityBindings: ReturnType<typeof vi.fn>;
      createAdminAccessRequest: ReturnType<typeof vi.fn>;
      listAdminAccessRequests: ReturnType<typeof vi.fn>;
      transitionAdminAccessRequestStatus: ReturnType<typeof vi.fn>;
      upsertAdminRoleBindings: ReturnType<typeof vi.fn>;
    };
    tenantRepository: {
      list: ReturnType<typeof vi.fn>;
      create: ReturnType<typeof vi.fn>;
      getById: ReturnType<typeof vi.fn>;
    };
    workloadRepository: {
      listByTenant: ReturnType<typeof vi.fn>;
      getById: ReturnType<typeof vi.fn>;
      create: ReturnType<typeof vi.fn>;
      update: ReturnType<typeof vi.fn>;
    };
    enrollmentTokenRepository: {
      issueEnrollmentToken: ReturnType<typeof vi.fn>;
      consumeEnrollmentTokenOnce: ReturnType<typeof vi.fn>;
    };
    integrationRepository: {
      listByTenant: ReturnType<typeof vi.fn>;
      getById: ReturnType<typeof vi.fn>;
      create: ReturnType<typeof vi.fn>;
      update: ReturnType<typeof vi.fn>;
      bindSecret: ReturnType<typeof vi.fn>;
    };
    secretRepository: {
      createSecretEnvelopeVersion: ReturnType<typeof vi.fn>;
      listManifestVerificationKeysWithEtag: ReturnType<typeof vi.fn>;
    };
    templateRepository: {
      getLatestTemplateByTenantTemplateId: ReturnType<typeof vi.fn>;
      createTemplateVersionImmutable: ReturnType<typeof vi.fn>;
      getTemplateByTenantTemplateIdVersion: ReturnType<typeof vi.fn>;
    };
    policyRuleRepository: {
      getPolicyRuleById: ReturnType<typeof vi.fn>;
      createPolicyRule: ReturnType<typeof vi.fn>;
      disablePolicyRule: ReturnType<typeof vi.fn>;
    };
    approvalRequestRepository: {
      list: ReturnType<typeof vi.fn>;
      getById: ReturnType<typeof vi.fn>;
      transitionApprovalStatus: ReturnType<typeof vi.fn>;
    };
    auditEventRepository: {
      queryAuditEvents: ReturnType<typeof vi.fn>;
      appendAuditEvent: ReturnType<typeof vi.fn>;
    };
  };
  transactionClient: {
    enrollmentToken: {
      findUnique: ReturnType<typeof vi.fn>;
    };
  };
  authRedisStores: {
    enrollmentTokenStore: {
      issueEnrollmentToken: ReturnType<typeof vi.fn>;
      consumeEnrollmentTokenByHash: ReturnType<typeof vi.fn>;
    };
  };
};

let activeDbFixture: DbFixture;

vi.mock('@broker-interceptor/db', () => ({
  DbRepositoryError: MockDbRepositoryError,
  createDbRepositories: vi.fn(() => activeDbFixture.repositories),
  runInTransaction: vi.fn(async (_dbClient: unknown, operation: (tx: unknown) => Promise<unknown>) =>
    operation(activeDbFixture.transactionClient)
  ),
  createAuthRedisStores: vi.fn(() => activeDbFixture.authRedisStores)
}));

const makeTemplate = (): OpenApiTemplate => ({
  template_id: 'tpl_openai_db',
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
      body_policy: {
        max_bytes: 4096,
        content_types: ['application/json']
      }
    }
  ],
  network_safety: {
    deny_private_ip_ranges: true,
    deny_link_local: true,
    deny_loopback: true,
    deny_metadata_ranges: true,
    dns_resolution_required: true
  }
});

const makePolicy = ({tenantId, integrationId}: {tenantId: string; integrationId: string}): OpenApiPolicyRule => ({
  policy_id: 'pol_db_1',
  rule_type: 'allow',
  scope: {
    tenant_id: tenantId,
    integration_id: integrationId,
    action_group: 'openai_responses',
    method: 'POST',
    host: 'api.openai.com'
  },
  rate_limit: null
});

const makeApproval = ({
  approvalId,
  tenantId,
  workloadId,
  integrationId
}: {
  approvalId: string;
  tenantId: string;
  workloadId: string;
  integrationId: string;
}): ApprovalRequest => ({
  approval_id: approvalId,
  status: 'pending',
  expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
  correlation_id: 'corr_db',
  summary: {
    integration_id: integrationId,
    action_group: 'openai_responses',
    risk_tier: 'low',
    destination_host: 'api.openai.com',
    method: 'POST',
    path: '/v1/responses'
  },
  canonical_descriptor: {
    tenant_id: tenantId,
    workload_id: workloadId,
    integration_id: integrationId,
    template_id: 'tpl_openai_db',
    template_version: 1,
    method: 'POST',
    canonical_url: 'https://api.openai.com/v1/responses',
    matched_path_group_id: 'openai_responses',
    normalized_headers: [],
    query_keys: []
  }
});

const makeFixture = ({
  tenant,
  workload,
  integration,
  policy,
  approval,
  auditEvent,
  manifestKeys
}: {
  tenant: OpenApiTenantSummary;
  workload: OpenApiWorkload;
  integration: OpenApiIntegration;
  policy: OpenApiPolicyRule;
  approval: ApprovalRequest;
  auditEvent: OpenApiAuditEvent;
  manifestKeys: OpenApiManifestKeys;
  }): DbFixture => ({
  repositories: {
    adminAuthRepository: {
      getAdminSignupPolicy: vi.fn(async () => ({
        new_user_mode: 'blocked',
        require_verified_email: true,
        allowed_email_domains: [],
        updated_at: new Date().toISOString(),
        updated_by: 'system'
      })),
      setAdminSignupPolicy: vi.fn(async ({policy, actor}: {policy: {new_user_mode: 'allowed' | 'blocked'}; actor: string}) => ({
        new_user_mode: policy.new_user_mode,
        require_verified_email: true,
        allowed_email_domains: [],
        updated_at: new Date().toISOString(),
        updated_by: actor
      })),
      listAdminIdentities: vi.fn(async () => ({
        users: [
          {
            identity_id: 'adm_db_1',
            issuer: 'https://issuer.example',
            subject: 'admin-sub-1',
            email: 'admin@example.com',
            status: 'active',
            roles: ['admin'],
            tenant_ids: [tenant.tenant_id],
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      })),
      getAdminIdentityById: vi.fn(async ({identity_id}: {identity_id: string}) => ({
        identity_id,
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: ['admin'],
        tenant_ids: [tenant.tenant_id],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })),
      findAdminIdentityByIssuerSubject: vi.fn(async () => ({
        identity_id: 'adm_db_1',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: ['admin'],
        tenant_ids: [tenant.tenant_id],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })),
      createAdminIdentity: vi.fn(async ({principal}: {principal: {issuer: string; subject: string; email: string; roles: string[]; tenant_ids: string[]}}) => ({
        identity_id: 'adm_db_1',
        issuer: principal.issuer,
        subject: principal.subject,
        email: principal.email,
        status: 'active',
        roles: principal.roles,
        tenant_ids: principal.tenant_ids,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })),
      updateAdminIdentityStatus: vi.fn(async ({identity_id, status}: {identity_id: string; status: 'active' | 'pending' | 'disabled'}) => ({
        identity_id,
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status,
        roles: ['admin'],
        tenant_ids: [tenant.tenant_id],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })),
      updateAdminIdentityBindings: vi.fn(async ({identity_id, patch}: {identity_id: string; patch: {roles?: string[]; tenant_ids?: string[]}}) => ({
        identity_id,
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: patch.roles ?? ['admin'],
        tenant_ids: patch.tenant_ids ?? [tenant.tenant_id],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })),
      createAdminAccessRequest: vi.fn(async ({request_id, principal}: {request_id?: string; principal: {issuer: string; subject: string; email: string; roles: string[]; tenant_ids: string[]}}) => ({
        request_id: request_id ?? 'aar_db_1',
        issuer: principal.issuer,
        subject: principal.subject,
        email: principal.email,
        requested_roles: principal.roles,
        requested_tenant_ids: principal.tenant_ids,
        status: 'pending',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })),
      listAdminAccessRequests: vi.fn(async () => ({
        requests: [
          {
            request_id: 'aar_db_1',
            issuer: 'https://issuer.example',
            subject: 'admin-sub-1',
            email: 'admin@example.com',
            requested_roles: ['admin'],
            requested_tenant_ids: [tenant.tenant_id],
            status: 'pending',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      })),
      transitionAdminAccessRequestStatus: vi.fn(async ({request_id, status, actor}: {request_id: string; status: 'approved' | 'denied' | 'canceled'; actor: string}) => ({
        request_id,
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        requested_roles: ['admin'],
        requested_tenant_ids: [tenant.tenant_id],
        status,
        decided_by: actor,
        decided_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })),
      upsertAdminRoleBindings: vi.fn(async ({issuer, subject, roles, tenant_ids}: {issuer: string; subject: string; roles: string[]; tenant_ids?: string[]}) => ({
        identity_id: 'adm_db_1',
        issuer,
        subject,
        email: 'admin@example.com',
        status: 'active',
        roles,
        tenant_ids: tenant_ids ?? [tenant.tenant_id],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }))
    },
    tenantRepository: {
      list: vi.fn(async () => [tenant, {tenant_id: 'global', name: 'Global Templates'}]),
      create: vi.fn(async ({request}: {request: {name: string}}) => ({
        tenant_id: 't_db_new',
        name: request.name
      })),
      getById: vi.fn(async () => null)
    },
    workloadRepository: {
      listByTenant: vi.fn(async () => [workload]),
      getById: vi.fn(async () => workload),
      create: vi.fn(async () => workload),
      update: vi.fn(async () => ({...workload, enabled: false}))
    },
    enrollmentTokenRepository: {
      issueEnrollmentToken: vi.fn(async () => undefined),
      consumeEnrollmentTokenOnce: vi.fn(async () => undefined)
    },
    integrationRepository: {
      listByTenant: vi.fn(async () => [integration]),
      getById: vi.fn(async () => integration),
      create: vi.fn(async () => integration),
      update: vi.fn(async () => ({...integration, enabled: false})),
      bindSecret: vi.fn(async () => integration)
    },
    secretRepository: {
      createSecretEnvelopeVersion: vi.fn(async () => undefined),
      listManifestVerificationKeysWithEtag: vi.fn(async () => ({
        manifest_keys: manifestKeys,
        etag: 'W/"manifest-etag"',
        generated_at: new Date().toISOString(),
        max_age_seconds: 120
      }))
    },
    templateRepository: {
      getLatestTemplateByTenantTemplateId: vi.fn(async () => makeTemplate()),
      createTemplateVersionImmutable: vi.fn(async ({template}: {template: OpenApiTemplate}) => template),
      getTemplateByTenantTemplateIdVersion: vi.fn(async () => makeTemplate())
    },
    policyRuleRepository: {
      getPolicyRuleById: vi.fn(async () => policy),
      createPolicyRule: vi.fn(async () => policy),
      disablePolicyRule: vi.fn(async () => undefined)
    },
    approvalRequestRepository: {
      list: vi.fn(async () => [approval]),
      getById: vi.fn(async () => approval),
      transitionApprovalStatus: vi.fn(async () => ({...approval, status: 'approved'}))
    },
    auditEventRepository: {
      queryAuditEvents: vi.fn(async () => ({items: [auditEvent], next_cursor: undefined})),
      appendAuditEvent: vi.fn(async () => undefined)
    }
  },
  transactionClient: {
    enrollmentToken: {
      findUnique: vi.fn(async () => null)
    }
  },
  authRedisStores: {
    enrollmentTokenStore: {
      issueEnrollmentToken: vi.fn(async () => undefined),
      consumeEnrollmentTokenByHash: vi.fn(async () => null)
    }
  }
});

describe('control plane repository db wiring', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('routes control-plane flows through db repositories when infrastructure is enabled', async () => {
    const tenant: OpenApiTenantSummary = {
      tenant_id: 't_db_1',
      name: 'Tenant DB'
    };
    const workload: OpenApiWorkload = {
      workload_id: 'w_db_1',
      tenant_id: tenant.tenant_id,
      name: 'workload-db',
      mtls_san_uri: 'spiffe://broker/tenants/t_db_1/workloads/w_db_1',
      enabled: true,
      ip_allowlist: ['203.0.113.0/24'],
      created_at: new Date().toISOString()
    };
    const integration: OpenApiIntegration = {
      integration_id: 'i_db_1',
      tenant_id: tenant.tenant_id,
      provider: 'openai',
      name: 'openai-db',
      template_id: 'tpl_openai_db',
      enabled: true,
      secret_ref: 'sec_db_1',
      secret_version: 1,
      last_rotated_at: new Date().toISOString()
    };
    const policy = makePolicy({
      tenantId: tenant.tenant_id,
      integrationId: integration.integration_id
    });
    const approval = makeApproval({
      approvalId: 'appr_db_1',
      tenantId: tenant.tenant_id,
      workloadId: workload.workload_id,
      integrationId: integration.integration_id
    });
    const manifestKeys: OpenApiManifestKeys = {
      keys: [
        {
          kid: 'mk_db_1',
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'AQ',
          use: 'sig',
          alg: 'EdDSA'
        }
      ]
    };

    const baseAuditEvent: OpenApiAuditEvent = {
      event_id: 'evt_db_1',
      timestamp: new Date().toISOString(),
      tenant_id: tenant.tenant_id,
      workload_id: workload.workload_id,
      integration_id: integration.integration_id,
      correlation_id: 'corr_db',
      event_type: 'admin_action',
      decision: null,
      action_group: null,
      risk_tier: null,
      destination: null,
      latency_ms: null,
      upstream_status_code: null,
      canonical_descriptor: null,
      policy: null,
      message: 'db test',
      metadata: {}
    };

    activeDbFixture = makeFixture({
      tenant,
      workload,
      integration,
      policy,
      approval,
      auditEvent: baseAuditEvent,
      manifestKeys
    });

    const {ControlPlaneRepository} = await import('../repository');
    const processInfrastructure = {
      enabled: true,
      prisma: {
        templateVersion: {
          findMany: vi.fn(async () => [{templateJson: makeTemplate()}])
        },
        policyRule: {
          findMany: vi.fn(async () => [{policyJson: policy}])
        }
      },
      redis: {},
      redisKeyPrefix: 'broker-admin-api:test',
      withTransaction: async <T>(operation: () => Promise<T>) => operation(),
      close: async () => undefined
    } as unknown as ProcessInfrastructure;

    const repository = await ControlPlaneRepository.create({
      manifestKeys: {keys: []},
      enrollmentTokenTtlSeconds: 600,
      processInfrastructure
    });

    expect(await repository.listTenants()).toEqual([tenant]);
    expect(await repository.createTenant({name: 'Tenant DB 2'})).toEqual({
      tenant_id: 't_db_new',
      name: 'Tenant DB 2'
    });
    expect(await repository.getAdminSignupPolicy()).toMatchObject({
      new_user_mode: 'blocked'
    });
    expect(
      await repository.setAdminSignupPolicy({
        policy: {new_user_mode: 'allowed'},
        actor: 'owner-user'
      })
    ).toMatchObject({
      new_user_mode: 'allowed',
      updated_by: 'owner-user'
    });
    expect(
      await repository.listAdminUsers({
        status: 'active',
        tenantId: tenant.tenant_id,
        role: 'admin',
        search: 'admin',
        limit: 10
      })
    ).toMatchObject({
      users: [{identity_id: 'adm_db_1'}]
    });
    expect(
      await repository.getAdminUserByIdentityId({
        identityId: 'adm_db_1'
      })
    ).toMatchObject({
      identity_id: 'adm_db_1'
    });
    expect(
      await repository.findAdminIdentityByIssuerSubject({
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1'
      })
    ).toMatchObject({
      subject: 'admin-sub-1'
    });
    expect(
      await repository.createAdminIdentity({
        principal: {
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          roles: ['admin'],
          tenant_ids: [tenant.tenant_id]
        }
      })
    ).toMatchObject({
      subject: 'admin-sub-1'
    });
    expect(
      await repository.setAdminUserStatus({
        identityId: 'adm_db_1',
        status: 'disabled'
      })
    ).toMatchObject({
      identity_id: 'adm_db_1',
      status: 'disabled'
    });
    expect(
      await repository.updateAdminUserRolesAndTenants({
        identityId: 'adm_db_1',
        roles: ['owner'],
        tenantIds: [tenant.tenant_id]
      })
    ).toMatchObject({
      identity_id: 'adm_db_1',
      roles: ['owner']
    });
    expect(
      await repository.updateAdminUser({
        identityId: 'adm_db_1',
        status: 'active',
        roles: ['admin'],
        tenantIds: [tenant.tenant_id]
      })
    ).toMatchObject({
      identity_id: 'adm_db_1',
      status: 'active',
      roles: ['admin']
    });
    expect(
      await repository.createAdminAccessRequest({
        requestId: 'aar_test_1',
        principal: {
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          roles: ['admin'],
          tenant_ids: [tenant.tenant_id]
        }
      })
    ).toMatchObject({
      request_id: 'aar_test_1'
    });
    expect(
      await repository.listAdminAccessRequests({
        status: 'pending',
        tenantId: tenant.tenant_id,
        role: 'admin',
        search: 'admin'
      })
    ).toMatchObject({
      requests: [{request_id: 'aar_db_1'}]
    });
    expect(
      await repository.transitionAdminAccessRequestStatus({
        requestId: 'aar_test_1',
        status: 'approved',
        actor: 'owner-user'
      })
    ).toMatchObject({
      request_id: 'aar_test_1',
      status: 'approved'
    });
    expect(
      await repository.upsertAdminRoleBindings({
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        roles: ['owner'],
        tenantIds: [tenant.tenant_id]
      })
    ).toMatchObject({
      roles: ['owner']
    });
    expect(await repository.listWorkloads({tenantId: tenant.tenant_id})).toHaveLength(1);
    expect((await repository.getWorkload({workloadId: workload.workload_id})).workload_id).toBe(
      workload.workload_id
    );

    const createdWorkload = await repository.createWorkload({
      tenantId: tenant.tenant_id,
      name: 'workload-db',
      enrollmentMode: 'broker_ca',
      ipAllowlist: ['203.0.113.0/24']
    });
    expect(createdWorkload.workload.workload_id).toBe(workload.workload_id);
    expect(createdWorkload.enrollmentToken.length).toBeGreaterThan(0);
    expect(activeDbFixture.repositories.enrollmentTokenRepository.issueEnrollmentToken).toHaveBeenCalledTimes(1);
    expect(activeDbFixture.authRedisStores.enrollmentTokenStore.issueEnrollmentToken).toHaveBeenCalledTimes(1);

    await expect(
      repository.consumeEnrollmentToken({
        workloadId: workload.workload_id,
        enrollmentToken: createdWorkload.enrollmentToken
      })
    ).resolves.toMatchObject({
      workload_id: workload.workload_id
    });
    expect(activeDbFixture.repositories.enrollmentTokenRepository.consumeEnrollmentTokenOnce).toHaveBeenCalledTimes(1);
    expect(activeDbFixture.authRedisStores.enrollmentTokenStore.consumeEnrollmentTokenByHash).toHaveBeenCalledTimes(1);

    expect(await repository.listIntegrations({tenantId: tenant.tenant_id})).toHaveLength(1);
    expect((await repository.getIntegration({integrationId: integration.integration_id})).integration_id).toBe(
      integration.integration_id
    );

    expect(
      await repository.createIntegration({
        tenantId: tenant.tenant_id,
        payload: {
          provider: integration.provider,
          name: integration.name,
          template_id: integration.template_id,
          secret_material: {type: 'api_key', value: 'sk-test'}
        },
        secretKey: Buffer.alloc(32, 1),
        secretKeyId: 'kid-db'
      })
    ).toMatchObject({
      integration_id: integration.integration_id
    });

    expect(
      await repository.updateIntegration({
        integrationId: integration.integration_id,
        enabled: false
      })
    ).toMatchObject({
      enabled: false
    });

    expect(await repository.listTemplates()).toHaveLength(1);
    expect(
      await repository.createTemplate({
        payload: {
          ...makeTemplate(),
          version: 2
        }
      })
    ).toEqual({
      template_id: 'tpl_openai_db',
      version: 2
    });
    expect(await repository.getTemplateVersion({templateId: 'tpl_openai_db', version: 1})).toMatchObject({
      template_id: 'tpl_openai_db',
      version: 1
    });

    expect(await repository.listPolicies()).toHaveLength(1);
    expect((await repository.getPolicy({policyId: policy.policy_id ?? ''})).policy_id).toBe(policy.policy_id);
    expect(
      await repository.createPolicy({
        payload: policy
      })
    ).toMatchObject({
      policy_id: policy.policy_id
    });
    await expect(repository.deletePolicy({policyId: policy.policy_id ?? ''})).resolves.toBeUndefined();

    expect(await repository.listApprovals({})).toHaveLength(1);
    expect((await repository.getApproval({approvalId: approval.approval_id})).approval_id).toBe(approval.approval_id);
    expect(
      await repository.decideApproval({
        approvalId: approval.approval_id,
        decision: 'approved',
        request: {mode: 'once'}
      })
    ).toMatchObject({
      approval: {
        approval_id: approval.approval_id
      }
    });

    expect(
      await repository.listAuditEvents({
        filter: {
          tenantId: tenant.tenant_id
        }
      })
    ).toHaveLength(1);
    await expect(repository.appendAuditEvent({event: baseAuditEvent})).resolves.toBeUndefined();

    expect(await repository.getManifestKeys()).toEqual({
      payload: manifestKeys,
      etag: 'W/"manifest-etag"'
    });
  });

  it('maps db repository errors to api-layer errors', async () => {
    activeDbFixture = makeFixture({
      tenant: {tenant_id: 't_db_1', name: 'Tenant DB'},
      workload: {
        workload_id: 'w_db_1',
        tenant_id: 't_db_1',
        name: 'workload-db',
        mtls_san_uri: 'spiffe://broker/tenants/t_db_1/workloads/w_db_1',
        enabled: true,
        created_at: new Date().toISOString()
      },
      integration: {
        integration_id: 'i_db_1',
        tenant_id: 't_db_1',
        provider: 'openai',
        name: 'openai-db',
        template_id: 'tpl_openai_db',
        enabled: true
      },
      policy: makePolicy({tenantId: 't_db_1', integrationId: 'i_db_1'}),
      approval: makeApproval({
        approvalId: 'appr_db_1',
        tenantId: 't_db_1',
        workloadId: 'w_db_1',
        integrationId: 'i_db_1'
      }),
      auditEvent: {
        event_id: 'evt_db_1',
        timestamp: new Date().toISOString(),
        tenant_id: 't_db_1',
        workload_id: null,
        integration_id: null,
        correlation_id: 'corr_db',
        event_type: 'admin_action',
        decision: null,
        action_group: null,
        risk_tier: null,
        destination: null,
        latency_ms: null,
        upstream_status_code: null,
        canonical_descriptor: null,
        policy: null,
        message: null,
        metadata: {}
      },
      manifestKeys: {keys: []}
    });

    activeDbFixture.repositories.tenantRepository.list.mockRejectedValue(
      new MockDbRepositoryError('validation_error', 'invalid tenant query')
    );

    const {ControlPlaneRepository} = await import('../repository');
    const repository = await ControlPlaneRepository.create({
      manifestKeys: {keys: []},
      enrollmentTokenTtlSeconds: 600,
      processInfrastructure: {
        enabled: true,
        prisma: {
          templateVersion: {
            findMany: vi.fn(async () => [])
          },
          policyRule: {
            findMany: vi.fn(async () => [])
          }
        },
        redis: {},
        redisKeyPrefix: 'broker-admin-api:test',
        withTransaction: async <T>(operation: () => Promise<T>) => operation(),
        close: async () => undefined
      } as unknown as ProcessInfrastructure
    });

    await expect(repository.listTenants()).rejects.toMatchObject({
      code: 'db_validation_error'
    });
  });
});
