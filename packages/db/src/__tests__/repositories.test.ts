import {describe, expect, it, vi} from 'vitest'

import {ApprovalRequestRepository} from '../repositories/approvalRequestRepository.js'
import {AuditEventRepository} from '../repositories/auditEventRepository.js'
import {PolicyRuleRepository} from '../repositories/policyRuleRepository.js'
import {SecretRepository} from '../repositories/secretRepository.js'
import {WorkloadRepository} from '../repositories/workloadRepository.js'
import type {DatabaseClient} from '../types.js'

const notImplemented = <T>() => (): Promise<T> => Promise.reject(new Error('not_implemented'))

type DatabaseClientOverrides = Omit<
  {
    [K in keyof DatabaseClient]?: Partial<DatabaseClient[K]>
  },
  '$transaction'
> & {
  $transaction?: DatabaseClient['$transaction']
}

const createDbClientStub = (overrides: DatabaseClientOverrides = {}): DatabaseClient => {
  const base: DatabaseClient = {
    adminSignupPolicy: {
      findUnique: notImplemented(),
      upsert: notImplemented()
    },
    adminIdentity: {
      create: notImplemented(),
      findUnique: notImplemented(),
      findMany: notImplemented(),
      count: notImplemented(),
      update: notImplemented()
    },
    adminAccessRequest: {
      create: notImplemented(),
      findUnique: notImplemented(),
      findMany: notImplemented(),
      update: notImplemented(),
      updateMany: notImplemented()
    },
    tenant: {
      create: notImplemented(),
      findUnique: notImplemented(),
      findMany: notImplemented()
    },
    humanUser: {
      create: notImplemented(),
      findUnique: notImplemented(),
      findMany: notImplemented(),
      update: notImplemented()
    },
    workload: {
      create: notImplemented(),
      findUnique: notImplemented(),
      findMany: notImplemented(),
      findFirst: notImplemented(),
      update: notImplemented()
    },
    enrollmentToken: {
      create: notImplemented(),
      findUnique: notImplemented(),
      findFirst: notImplemented(),
      updateMany: notImplemented()
    },
    workloadSession: {
      upsert: notImplemented(),
      findFirst: notImplemented(),
      update: notImplemented(),
      deleteMany: notImplemented()
    },
    integration: {
      create: notImplemented(),
      findFirst: notImplemented(),
      findMany: notImplemented(),
      update: notImplemented()
    },
    secret: {
      findUnique: notImplemented(),
      create: notImplemented(),
      update: notImplemented()
    },
    secretVersion: {
      findFirst: notImplemented(),
      create: notImplemented(),
      findUnique: notImplemented(),
      findMany: notImplemented()
    },
    manifestSigningKey: {
      findFirst: notImplemented(),
      findMany: notImplemented(),
      findUnique: notImplemented(),
      create: notImplemented(),
      update: notImplemented()
    },
    manifestKeysetMetadata: {
      findUnique: notImplemented(),
      upsert: notImplemented()
    },
    cryptoVerificationDefaults: {
      findUnique: notImplemented(),
      upsert: notImplemented()
    },
    templateVersion: {
      findMany: notImplemented(),
      create: notImplemented(),
      findUnique: notImplemented(),
      findFirst: notImplemented()
    },
    policyRule: {
      create: notImplemented(),
      findUnique: notImplemented(),
      update: notImplemented(),
      findMany: notImplemented()
    },
    approvalRequest: {
      create: notImplemented(),
      findUnique: notImplemented(),
      findMany: notImplemented(),
      update: notImplemented(),
      findFirst: notImplemented()
    },
    auditEvent: {
      create: notImplemented(),
      findMany: notImplemented()
    },
    ssrfGuardDecision: {
      upsert: notImplemented(),
      findUnique: notImplemented()
    },
    templateInvalidationOutbox: {
      upsert: notImplemented()
    },
    auditRedactionProfile: {
      findUnique: notImplemented(),
      create: notImplemented(),
      upsert: notImplemented()
    }
  }

  return {
    ...base,
    ...overrides,
    adminSignupPolicy: {...base.adminSignupPolicy, ...overrides.adminSignupPolicy},
    adminIdentity: {...base.adminIdentity, ...overrides.adminIdentity},
    adminAccessRequest: {...base.adminAccessRequest, ...overrides.adminAccessRequest},
    tenant: {...base.tenant, ...overrides.tenant},
    humanUser: {...base.humanUser, ...overrides.humanUser},
    workload: {...base.workload, ...overrides.workload},
    enrollmentToken: {...base.enrollmentToken, ...overrides.enrollmentToken},
    workloadSession: {...base.workloadSession, ...overrides.workloadSession},
    integration: {...base.integration, ...overrides.integration},
    secret: {...base.secret, ...overrides.secret},
    secretVersion: {...base.secretVersion, ...overrides.secretVersion},
    manifestSigningKey: {...base.manifestSigningKey, ...overrides.manifestSigningKey},
    manifestKeysetMetadata: {
      ...base.manifestKeysetMetadata,
      ...overrides.manifestKeysetMetadata
    },
    cryptoVerificationDefaults: {
      ...base.cryptoVerificationDefaults,
      ...overrides.cryptoVerificationDefaults
    },
    templateVersion: {...base.templateVersion, ...overrides.templateVersion},
    policyRule: {...base.policyRule, ...overrides.policyRule},
    approvalRequest: {...base.approvalRequest, ...overrides.approvalRequest},
    auditEvent: {...base.auditEvent, ...overrides.auditEvent},
    ssrfGuardDecision: {...base.ssrfGuardDecision, ...overrides.ssrfGuardDecision},
    templateInvalidationOutbox: {
      ...base.templateInvalidationOutbox,
      ...overrides.templateInvalidationOutbox
    },
    auditRedactionProfile: {...base.auditRedactionProfile, ...overrides.auditRedactionProfile}
  }
}

describe('WorkloadRepository', () => {
  it('creates workloads with deterministic default SAN URI', async () => {
    const create = vi.fn((args: Record<string, unknown>) =>
      Promise.resolve({
        workloadId: String((args.data as Record<string, unknown>).workloadId),
        tenantId: String((args.data as Record<string, unknown>).tenantId),
        name: String((args.data as Record<string, unknown>).name),
        mtlsSanUri: String((args.data as Record<string, unknown>).mtlsSanUri),
        enabled: Boolean((args.data as Record<string, unknown>).enabled),
        ipAllowlist: (args.data as Record<string, unknown>).ipAllowlist as string[],
        createdAt: new Date('2026-01-01T00:00:00.000Z')
      })
    )

    const repository = new WorkloadRepository(
      createDbClientStub({
        workload: {
          create
        }
      })
    )

    const workload = await repository.create({
      tenant_id: 't_1',
      workload_id: 'w_1',
      request: {
        name: 'agent',
        enrollment_mode: 'broker_ca',
        ip_allowlist: ['203.0.113.10']
      }
    })

    expect(workload.mtls_san_uri).toBe('spiffe://broker/tenants/t_1/workloads/w_1')
    expect(create).toHaveBeenCalledTimes(1)
  })
})

describe('SecretRepository', () => {
  it('fails closed when envelope ciphertext exceeds bounds', async () => {
    const oversizedCiphertext = Buffer.alloc(1_048_577, 1).toString('base64')
    const repository = new SecretRepository(createDbClientStub())

    await expect(
      repository.createSecretEnvelopeVersion({
        secret_ref: 'sec_1',
        tenant_id: 't_1',
        integration_id: 'int_1',
        secret_type: 'api_key',
        envelope: {
          key_id: 'k_1',
          content_encryption_alg: 'A256GCM',
          key_encryption_alg: 'A256KW',
          wrapped_data_key_b64: Buffer.alloc(32, 2).toString('base64'),
          iv_b64: Buffer.alloc(12, 3).toString('base64'),
          ciphertext_b64: oversizedCiphertext,
          auth_tag_b64: Buffer.alloc(16, 4).toString('base64')
        }
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })
})

describe('PolicyRuleRepository', () => {
  it('normalizes policy scope fields before persistence', async () => {
    const create = vi.fn((args: Record<string, unknown>) =>
      Promise.resolve({
        policyJson: (args.data as Record<string, unknown>).policyJson,
        enabled: true
      })
    )

    const repository = new PolicyRuleRepository(
      createDbClientStub({
        policyRule: {
          create
        }
      })
    )

    const policy = await repository.createPolicyRule({
      policy: {
        policy_id: 'pol_1',
        rule_type: 'allow',
        scope: {
          tenant_id: 't_1',
          integration_id: 'int_1',
          action_group: 'gmail_send',
          method: 'get',
          host: 'Example.COM',
          query_keys: ['b', 'a']
        },
        constraints: {
          allowed_query_keys: ['z', 'a']
        },
        rate_limit: null
      }
    })

    expect(policy.scope.method).toBe('GET')
    expect(policy.scope.host).toBe('example.com')
    expect(policy.scope.query_keys).toEqual(['a', 'b'])
    expect(policy.constraints?.allowed_query_keys).toEqual(['a', 'z'])
    expect(create).toHaveBeenCalledTimes(1)
  })
})

describe('ApprovalRequestRepository', () => {
  it('rejects invalid state transitions', async () => {
    const approval = {
      approval_id: 'apr_1',
      status: 'denied' as const,
      expires_at: '2026-01-01T00:00:00.000Z',
      correlation_id: 'corr_1',
      summary: {
        integration_id: 'int_1',
        action_group: 'gmail_send',
        risk_tier: 'high' as const,
        destination_host: 'gmail.googleapis.com',
        method: 'POST',
        path: '/gmail/v1/users/me/messages/send'
      },
      canonical_descriptor: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'int_1',
        template_id: 'tpl_gmail',
        template_version: 1,
        method: 'POST' as const,
        canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
        matched_path_group_id: 'gmail_send',
        normalized_headers: [],
        query_keys: []
      }
    }

    const update = vi.fn()
    const repository = new ApprovalRequestRepository(
      createDbClientStub({
        approvalRequest: {
          findUnique: vi.fn(() =>
            Promise.resolve({
              status: 'denied' as const,
              approvalJson: approval
            })
          ),
          update
        }
      })
    )

    await expect(
      repository.transitionApprovalStatus({
        approval_id: 'apr_1',
        status: 'approved'
      })
    ).rejects.toMatchObject({
      code: 'state_transition_invalid'
    })

    expect(update).not.toHaveBeenCalled()
  })
})

describe('AuditEventRepository', () => {
  it('rejects cross-tenant cursor usage', async () => {
    const findMany = vi.fn(() => Promise.resolve([]))
    const repository = new AuditEventRepository(
      createDbClientStub({
        auditEvent: {
          findMany
        }
      })
    )

    const cursor = Buffer.from('2026-01-01T00:00:00.000Z|evt_1|t_other', 'utf8').toString('base64url')

    await expect(
      repository.queryAuditEvents({
        tenant_id: 't_1',
        cursor,
        limit: 10
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })

    expect(findMany).not.toHaveBeenCalled()
  })
})
