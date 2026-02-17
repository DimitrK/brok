import {describe, expect, it, vi} from 'vitest'

import {createDbRepositories, runInTransaction} from '../module.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import {AdminAuthRepository} from '../repositories/adminAuthRepository.js'
import {ApprovalRequestRepository} from '../repositories/approvalRequestRepository.js'
import {AuditEventRepository} from '../repositories/auditEventRepository.js'
import {EnrollmentTokenRepository} from '../repositories/enrollmentTokenRepository.js'
import {IntegrationRepository} from '../repositories/integrationRepository.js'
import {PolicyRuleRepository} from '../repositories/policyRuleRepository.js'
import {SecretRepository} from '../repositories/secretRepository.js'
import {SessionRepository} from '../repositories/sessionRepository.js'
import {TemplateRepository} from '../repositories/templateRepository.js'
import {TenantRepository} from '../repositories/tenantRepository.js'
import {UserRepository} from '../repositories/userRepository.js'
import {WorkloadRepository} from '../repositories/workloadRepository.js'
import type {DatabaseClient} from '../types.js'
import {decodeBase64ByteLength, parseCursorPair} from '../utils.js'

const notImplemented = <T>() => (): Promise<T> => Promise.reject(new Error('not_implemented'))

type DatabaseClientOverrides = {
  [K in Exclude<keyof DatabaseClient, '$transaction'>]?: Record<string, unknown>
} & {
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

  const tenantOverrides = (overrides.tenant ?? {}) as Partial<DatabaseClient['tenant']>
  const adminSignupPolicyOverrides = (overrides.adminSignupPolicy ?? {}) as Partial<
    DatabaseClient['adminSignupPolicy']
  >
  const adminIdentityOverrides = (overrides.adminIdentity ?? {}) as Partial<DatabaseClient['adminIdentity']>
  const adminAccessRequestOverrides = (overrides.adminAccessRequest ?? {}) as Partial<
    DatabaseClient['adminAccessRequest']
  >
  const humanUserOverrides = (overrides.humanUser ?? {}) as Partial<DatabaseClient['humanUser']>
  const workloadOverrides = (overrides.workload ?? {}) as Partial<DatabaseClient['workload']>
  const workloadSessionOverrides = (overrides.workloadSession ?? {}) as Partial<
    DatabaseClient['workloadSession']
  >
  const enrollmentTokenOverrides = (overrides.enrollmentToken ?? {}) as Partial<
    DatabaseClient['enrollmentToken']
  >
  const integrationOverrides = (overrides.integration ?? {}) as Partial<DatabaseClient['integration']>
  const secretOverrides = (overrides.secret ?? {}) as Partial<DatabaseClient['secret']>
  const secretVersionOverrides = (overrides.secretVersion ?? {}) as Partial<DatabaseClient['secretVersion']>
  const manifestSigningKeyOverrides = (overrides.manifestSigningKey ?? {}) as Partial<
    DatabaseClient['manifestSigningKey']
  >
  const manifestKeysetMetadataOverrides = (overrides.manifestKeysetMetadata ?? {}) as Partial<
    DatabaseClient['manifestKeysetMetadata']
  >
  const cryptoVerificationDefaultsOverrides = (overrides.cryptoVerificationDefaults ?? {}) as Partial<
    DatabaseClient['cryptoVerificationDefaults']
  >
  const templateVersionOverrides = (overrides.templateVersion ?? {}) as Partial<
    DatabaseClient['templateVersion']
  >
  const policyRuleOverrides = (overrides.policyRule ?? {}) as Partial<DatabaseClient['policyRule']>
  const approvalRequestOverrides = (overrides.approvalRequest ?? {}) as Partial<
    DatabaseClient['approvalRequest']
  >
  const auditEventOverrides = (overrides.auditEvent ?? {}) as Partial<DatabaseClient['auditEvent']>
  const ssrfGuardDecisionOverrides = (overrides.ssrfGuardDecision ?? {}) as Partial<
    DatabaseClient['ssrfGuardDecision']
  >
  const templateInvalidationOutboxOverrides = (overrides.templateInvalidationOutbox ?? {}) as Partial<
    DatabaseClient['templateInvalidationOutbox']
  >
  const auditRedactionProfileOverrides = (overrides.auditRedactionProfile ?? {}) as Partial<
    DatabaseClient['auditRedactionProfile']
  >

  return {
    ...base,
    ...(overrides.$transaction ? {$transaction: overrides.$transaction} : {}),
    adminSignupPolicy: {...base.adminSignupPolicy, ...adminSignupPolicyOverrides},
    adminIdentity: {...base.adminIdentity, ...adminIdentityOverrides},
    adminAccessRequest: {...base.adminAccessRequest, ...adminAccessRequestOverrides},
    tenant: {...base.tenant, ...tenantOverrides},
    humanUser: {...base.humanUser, ...humanUserOverrides},
    workload: {...base.workload, ...workloadOverrides},
    enrollmentToken: {...base.enrollmentToken, ...enrollmentTokenOverrides},
    workloadSession: {...base.workloadSession, ...workloadSessionOverrides},
    integration: {...base.integration, ...integrationOverrides},
    secret: {...base.secret, ...secretOverrides},
    secretVersion: {...base.secretVersion, ...secretVersionOverrides},
    manifestSigningKey: {...base.manifestSigningKey, ...manifestSigningKeyOverrides},
    manifestKeysetMetadata: {
      ...base.manifestKeysetMetadata,
      ...manifestKeysetMetadataOverrides
    },
    cryptoVerificationDefaults: {
      ...base.cryptoVerificationDefaults,
      ...cryptoVerificationDefaultsOverrides
    },
    templateVersion: {...base.templateVersion, ...templateVersionOverrides},
    policyRule: {...base.policyRule, ...policyRuleOverrides},
    approvalRequest: {...base.approvalRequest, ...approvalRequestOverrides},
    auditEvent: {...base.auditEvent, ...auditEventOverrides},
    ssrfGuardDecision: {...base.ssrfGuardDecision, ...ssrfGuardDecisionOverrides},
    templateInvalidationOutbox: {
      ...base.templateInvalidationOutbox,
      ...templateInvalidationOutboxOverrides
    },
    auditRedactionProfile: {...base.auditRedactionProfile, ...auditRedactionProfileOverrides}
  }
}

const createTemplate = ({templateId = 'tpl_gmail', version = 1, provider = 'google_gmail'} = {}) => ({
  template_id: templateId,
  version,
  provider,
  allowed_schemes: ['https' as const],
  allowed_ports: [443 as const],
  allowed_hosts: ['gmail.googleapis.com'],
  redirect_policy: {
    mode: 'deny' as const
  },
  path_groups: [
    {
      group_id: 'gmail_send',
      risk_tier: 'high' as const,
      approval_mode: 'required' as const,
      methods: ['POST' as const],
      path_patterns: ['^/gmail/v1/users/[^/]+/messages/send$'],
      query_allowlist: [],
      header_forward_allowlist: ['content-type'],
      body_policy: {
        max_bytes: 1024,
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
})

const createApproval = (status: 'pending' | 'approved' | 'denied' | 'expired' | 'executed' | 'canceled' = 'pending') => ({
  approval_id: 'apr_1',
  status,
  expires_at: '2026-01-02T00:00:00.000Z',
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
})

const createAuditRedactionProfile = () => ({
  tenant_id: 't_1',
  profile_id: 'arp_1',
  rules: {
    message_action: 'mask' as const,
    metadata_default_action: 'keep' as const,
    metadata_key_actions: {
      token: 'drop' as const
    },
    metadata_allow_keys: ['request_id'],
    sensitive_key_patterns: ['token', 'secret'],
    canonical_header_value_action: 'mask' as const,
    policy_identifier_action: 'hash' as const,
    max_depth: 6,
    max_collection_size: 100,
    max_string_length: 512
  }
})

const createSsrfDecisionProjection = () => ({
  event_id: 'ssrf_evt_1',
  timestamp: '2026-02-13T00:00:00.000Z',
  tenant_id: 't_1',
  workload_id: 'w_1',
  integration_id: 'int_1',
  template_id: 'tpl_gmail',
  template_version: 1,
  destination_host: 'gmail.googleapis.com',
  destination_port: 443,
  resolved_ips: ['203.0.113.10'],
  decision: 'denied' as const,
  reason_code: 'request_host_not_allowed' as const,
  correlation_id: 'corr_1'
})

const createSecretVersionRow = (version: number) => ({
  secretRef: 'sec_1',
  version,
  keyId: 'k_1',
  contentEncryptionAlg: 'A256GCM',
  keyEncryptionAlg: 'A256KW',
  wrappedDataKeyB64: Buffer.alloc(32, 1).toString('base64'),
  ivB64: Buffer.alloc(12, 2).toString('base64'),
  ciphertextB64: Buffer.alloc(64, 3).toString('base64'),
  authTagB64: Buffer.alloc(16, 4).toString('base64'),
  aadB64: null,
  createdAt: new Date('2026-01-01T00:00:00.000Z'),
  secret: {
    tenantId: 't_1',
    integrationId: 'int_1',
    type: 'api_key' as const
  }
})

const createEnrollmentTokenRow = (overrides?: Partial<{
  tokenHash: string
  workloadId: string
  tenantId: string
  expiresAt: Date
  usedAt: Date | null
  createdAt: Date
}>) => ({
  tokenHash: overrides?.tokenHash ?? 'a'.repeat(64),
  workloadId: overrides?.workloadId ?? 'w_1',
  tenantId: overrides?.tenantId ?? 't_1',
  expiresAt: overrides?.expiresAt ?? new Date('2026-02-10T00:00:00.000Z'),
  usedAt: overrides?.usedAt ?? null,
  createdAt: overrides?.createdAt ?? new Date('2026-02-09T00:00:00.000Z')
})

const createManifestSigningKeyRow = (overrides?: Partial<{
  kid: string
  status: 'active' | 'retired' | 'revoked'
  activatedAt: Date | null
  retiredAt: Date | null
  revokedAt: Date | null
}>) => ({
  kid: overrides?.kid ?? 'manifest_v1',
  alg: 'EdDSA' as const,
  publicJwk: {
    kid: overrides?.kid ?? 'manifest_v1',
    kty: 'OKP' as const,
    crv: 'Ed25519' as const,
    x: 'dGVzdF9rZXlfYnl0ZXM',
    alg: 'EdDSA' as const,
    use: 'sig' as const
  },
  privateKeyRef: `kms://broker/manifest/${overrides?.kid ?? 'manifest_v1'}`,
  status: overrides?.status ?? 'active',
  createdAt: new Date('2026-01-01T00:00:00.000Z'),
  activatedAt: overrides?.activatedAt ?? new Date('2026-01-01T00:00:00.000Z'),
  retiredAt: overrides?.retiredAt ?? null,
  revokedAt: overrides?.revokedAt ?? null
})

const createAdminPrincipal = (overrides?: Partial<{
  subject: string
  issuer: string
  email: string
  name: string
  roles: Array<'owner' | 'admin' | 'auditor' | 'operator'>
  tenant_ids: string[]
}>) => ({
  subject: overrides?.subject ?? 'admin-sub-1',
  issuer: overrides?.issuer ?? 'https://accounts.google.com',
  email: overrides?.email ?? 'owner@example.com',
  name: overrides?.name ?? 'Admin Owner',
  roles: overrides?.roles ?? ['owner', 'admin'],
  tenant_ids: overrides?.tenant_ids ?? ['t_2', 't_1']
})

const createAdminIdentityRow = (overrides?: Partial<{
  identityId: string
  issuer: string
  subject: string
  email: string
  name: string | null
  status: 'active' | 'pending' | 'disabled'
  createdAt: Date
  updatedAt: Date
  roleBindings: Array<{role: 'owner' | 'admin' | 'auditor' | 'operator'}>
  tenantScopes: Array<{tenantId: string}>
}>) => ({
  identityId: overrides?.identityId ?? 'adm_1',
  issuer: overrides?.issuer ?? 'https://accounts.google.com',
  subject: overrides?.subject ?? 'admin-sub-1',
  email: overrides?.email ?? 'owner@example.com',
  name: overrides?.name ?? 'Admin Owner',
  status: overrides?.status ?? ('active' as const),
  createdAt: overrides?.createdAt ?? new Date('2026-02-14T00:00:00.000Z'),
  updatedAt: overrides?.updatedAt ?? new Date('2026-02-14T00:00:00.000Z'),
  roleBindings: overrides?.roleBindings ?? [{role: 'owner'}],
  tenantScopes: overrides?.tenantScopes ?? [{tenantId: 't_1'}]
})

const createAdminAccessRequestRow = (overrides?: Partial<{
  requestId: string
  issuer: string
  subject: string
  email: string
  name: string | null
  requestedRoles: Array<'owner' | 'admin' | 'auditor' | 'operator'>
  requestedTenantIds: string[]
  status: 'pending' | 'approved' | 'denied' | 'canceled'
  requestReason: string | null
  decisionReason: string | null
  decidedBy: string | null
  decidedAt: Date | null
  createdAt: Date
  updatedAt: Date
}>) => ({
  requestId: overrides?.requestId ?? 'aar_1',
  issuer: overrides?.issuer ?? 'https://accounts.google.com',
  subject: overrides?.subject ?? 'admin-sub-1',
  email: overrides?.email ?? 'owner@example.com',
  name: overrides?.name ?? 'Admin Owner',
  requestedRoles: overrides?.requestedRoles ?? ['owner'],
  requestedTenantIds: overrides?.requestedTenantIds ?? ['t_1'],
  status: overrides?.status ?? ('pending' as const),
  requestReason: overrides?.requestReason ?? 'Please approve',
  decisionReason: overrides?.decisionReason ?? null,
  decidedBy: overrides?.decidedBy ?? null,
  decidedAt: overrides?.decidedAt ?? null,
  createdAt: overrides?.createdAt ?? new Date('2026-02-14T00:00:00.000Z'),
  updatedAt: overrides?.updatedAt ?? new Date('2026-02-14T00:00:00.000Z')
})

describe('error mapping', () => {
  it('maps prisma unique violations to stable reason codes', () => {
    try {
      mapDatabaseError({code: 'P2002'})
      throw new Error('expected mapDatabaseError to throw')
    } catch (error) {
      expect(error).toMatchObject({
        code: 'unique_violation'
      })
    }
  })

  it('passes through DbRepositoryError without remapping', () => {
    const error = new DbRepositoryError('validation_error', 'bad input')

    try {
      mapDatabaseError(error)
      throw new Error('expected mapDatabaseError to throw')
    } catch (caught) {
      expect(caught).toBe(error)
    }
  })
})

describe('utils hardening', () => {
  it('rejects malformed base64 payloads', () => {
    try {
      decodeBase64ByteLength('$$$')
      throw new Error('expected decodeBase64ByteLength to throw')
    } catch (error) {
      expect(error).toMatchObject({
        code: 'validation_error'
      })
    }
  })

  it('rejects cursor payloads with invalid timestamps', () => {
    const cursor = Buffer.from('not-a-date|evt_1|t_1', 'utf8').toString('base64url')

    try {
      parseCursorPair(cursor)
      throw new Error('expected parseCursorPair to throw')
    } catch (error) {
      expect(error).toMatchObject({
        code: 'validation_error'
      })
    }
  })
})

describe('TenantRepository', () => {
  it('trims and validates explicit tenant_id at create time', async () => {
    const create = vi.fn(() =>
      Promise.resolve({
        tenantId: 't_1',
        name: 'Acme',
        createdAt: new Date('2026-01-01T00:00:00.000Z')
      })
    )
    const repository = new TenantRepository(createDbClientStub({tenant: {create}}))

    await repository.create({
      tenant_id: '  t_1  ',
      request: {
        name: 'Acme'
      }
    })

    expect(create).toHaveBeenCalledWith({
      data: {
        tenantId: 't_1',
        name: 'Acme'
      }
    })
  })
})

describe('UserRepository', () => {
  it('normalizes and de-duplicates roles before persistence', async () => {
    const create = vi.fn((args: Record<string, unknown>) => {
      void args
      return Promise.resolve({
        userId: 'u_1',
        tenantId: 't_1',
        email: 'owner@example.com',
        enabled: true,
        displayName: null,
        oidcSubject: null,
        oidcIssuer: null,
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        roles: [{role: 'admin'}, {role: 'owner'}]
      })
    })
    const repository = new UserRepository(createDbClientStub({humanUser: {create}}))

    await repository.create({
      tenant_id: 't_1',
      email: 'owner@example.com',
      roles: ['owner', 'admin']
    })

    const [firstCall] = create.mock.calls
    expect(firstCall).toBeDefined()
    expect(firstCall?.[0]).toMatchObject({
      data: {
        roles: {
          create: [{role: 'admin'}, {role: 'owner'}]
        }
      }
    })
  })
})

describe('WorkloadRepository', () => {
  it('normalizes ip allowlist values deterministically', async () => {
    const create = vi.fn((args: Record<string, unknown>) => {
      void args
      return Promise.resolve({
        workloadId: 'w_1',
        tenantId: 't_1',
        name: 'agent',
        mtlsSanUri: 'spiffe://broker/tenants/t_1/workloads/w_1',
        enabled: true,
        ipAllowlist: ['10.0.0.1', '203.0.113.10'],
        createdAt: new Date('2026-01-01T00:00:00.000Z')
      })
    })
    const repository = new WorkloadRepository(createDbClientStub({workload: {create}}))

    await repository.create({
      tenant_id: 't_1',
      workload_id: 'w_1',
      request: {
        name: 'agent',
        enrollment_mode: 'broker_ca',
        ip_allowlist: ['203.0.113.10', '10.0.0.1']
      }
    })

    const [firstCall] = create.mock.calls
    expect(firstCall).toBeDefined()
    expect(firstCall?.[0]).toMatchObject({
      data: {
        ipAllowlist: ['10.0.0.1', '203.0.113.10']
      }
    })
  })

  it('fails closed for duplicate ip allowlist entries', async () => {
    const repository = new WorkloadRepository(createDbClientStub())

    await expect(
      repository.update({
        workload_id: 'w_1',
        request: {
          ip_allowlist: ['203.0.113.10', '203.0.113.10']
        }
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('fails closed for malformed ip allowlist entries', async () => {
    const repository = new WorkloadRepository(createDbClientStub())

    await expect(
      repository.create({
        tenant_id: 't_1',
        request: {
          name: 'agent',
          enrollment_mode: 'broker_ca',
          ip_allowlist: ['not-an-ip']
        }
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })
})

describe('SessionRepository', () => {
  it('returns null for missing token hash lookup', async () => {
    const repository = new SessionRepository(
      createDbClientStub({
        workloadSession: {
          findFirst: vi.fn(() => Promise.resolve(null))
        }
      })
    )

    await expect(
      repository.getSessionByTokenHash({
        token_hash: 'a'.repeat(64)
      })
    ).resolves.toBeNull()
  })

  it('upserts and maps session records with scopes', async () => {
    const upsert = vi.fn(() =>
      Promise.resolve({
        sessionId: '9fd94a2f-4de2-4f1e-b3bf-218d414112d9',
        workloadId: 'w_1',
        tenantId: 't_1',
        certFingerprint256: 'fp_1',
        tokenHash: 'a'.repeat(64),
        expiresAt: new Date('2026-01-01T00:10:00.000Z'),
        dpopJkt: null,
        scopes: ['scope:read']
      })
    )
    const repository = new SessionRepository(
      createDbClientStub({
        workloadSession: {
          upsert
        }
      })
    )

    const result = await repository.upsertSession({
      sessionId: '9fd94a2f-4de2-4f1e-b3bf-218d414112d9',
      workloadId: 'w_1',
      tenantId: 't_1',
      certFingerprint256: 'fp_1',
      tokenHash: 'a'.repeat(64),
      expiresAt: '2026-01-01T00:10:00.000Z',
      scopes: ['scope:read']
    })

    expect(result.scopes).toEqual(['scope:read'])
    expect(upsert).toHaveBeenCalledTimes(1)
  })

  it('deletes expired sessions and returns count', async () => {
    const repository = new SessionRepository(
      createDbClientStub({
        workloadSession: {
          deleteMany: vi.fn(() => Promise.resolve({count: 4}))
        }
      })
    )

    await expect(repository.deleteExpiredSessions()).resolves.toBe(4)
  })
})

describe('IntegrationRepository', () => {
  it('rejects partial secret pointer payloads at create time', async () => {
    const repository = new IntegrationRepository(createDbClientStub())

    await expect(
      repository.create({
        tenant_id: 't_1',
        payload: {
          provider: 'google_gmail',
          name: 'gmail-primary',
          template_id: 'tpl_gmail',
          secret_material: {
            type: 'api_key',
            value: 'redacted'
          }
        },
        secret_ref: 'sec_1'
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('rejects empty tenant filters in getById', async () => {
    const repository = new IntegrationRepository(createDbClientStub())

    await expect(
      repository.getById({
        integration_id: 'int_1',
        tenant_id: '   '
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('resolves execute template with enablement flags', async () => {
    const repository = new IntegrationRepository(
      createDbClientStub({
        workload: {
          findFirst: vi.fn(() => Promise.resolve({enabled: true}))
        },
        integration: {
          findFirst: vi.fn(() =>
            Promise.resolve({
              enabled: true,
              templateId: 'tpl_gmail',
              templateVersion: null
            })
          )
        },
        templateVersion: {
          findFirst: vi.fn(() =>
            Promise.resolve({
              templateId: 'tpl_gmail',
              version: 3,
              provider: 'google_gmail',
              status: 'active',
              templateJson: createTemplate({templateId: 'tpl_gmail', version: 3})
            })
          )
        }
      })
    )

    const result = await repository.getIntegrationTemplateForExecute({
      tenant_id: 't_1',
      workload_id: 'w_1',
      integration_id: 'int_1'
    })

    expect(result.workload_enabled).toBe(true)
    expect(result.integration_enabled).toBe(true)
    expect(result.executable).toBe(true)
    expect(result.execution_status).toBe('executable')
    expect(result.template_id).toBe('tpl_gmail')
    expect(result.template_version).toBe(3)
  })

  it('returns explicit non-executable status when workload is disabled', async () => {
    const repository = new IntegrationRepository(
      createDbClientStub({
        workload: {
          findFirst: vi.fn(() => Promise.resolve({enabled: false}))
        },
        integration: {
          findFirst: vi.fn(() =>
            Promise.resolve({
              enabled: true,
              templateId: 'tpl_gmail',
              templateVersion: null
            })
          )
        },
        templateVersion: {
          findFirst: vi.fn(() =>
            Promise.resolve({
              templateId: 'tpl_gmail',
              version: 3,
              provider: 'google_gmail',
              status: 'active',
              templateJson: createTemplate({templateId: 'tpl_gmail', version: 3})
            })
          )
        }
      })
    )

    const result = await repository.getIntegrationTemplateForExecute({
      tenant_id: 't_1',
      workload_id: 'w_1',
      integration_id: 'int_1'
    })

    expect(result.executable).toBe(false)
    expect(result.execution_status).toBe('workload_disabled')
  })

  it('uses provided transaction_client when resolving execute template', async () => {
    const rootWorkloadFindFirst = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const transactionWorkloadFindFirst = vi.fn(() => Promise.resolve({enabled: true}))
    const transactionIntegrationFindFirst = vi.fn(() =>
      Promise.resolve({
        enabled: true,
        templateId: 'tpl_gmail',
        templateVersion: null
      })
    )
    const transactionTemplateFindFirst = vi.fn(() =>
      Promise.resolve({
        templateId: 'tpl_gmail',
        version: 2,
        provider: 'google_gmail',
        status: 'active',
        templateJson: createTemplate({templateId: 'tpl_gmail', version: 2})
      })
    )

    const repository = new IntegrationRepository(
      createDbClientStub({
        workload: {
          findFirst: rootWorkloadFindFirst
        }
      })
    )

    const transactionClient = createDbClientStub({
      workload: {
        findFirst: transactionWorkloadFindFirst
      },
      integration: {
        findFirst: transactionIntegrationFindFirst
      },
      templateVersion: {
        findFirst: transactionTemplateFindFirst
      }
    })

    const result = await repository.getIntegrationTemplateForExecute(
      {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'int_1',
        transaction_client: transactionClient
      }
    )

    expect(result.template_version).toBe(2)
    expect(rootWorkloadFindFirst).not.toHaveBeenCalled()
    expect(transactionWorkloadFindFirst).toHaveBeenCalledTimes(1)
    expect(transactionIntegrationFindFirst).toHaveBeenCalledTimes(1)
    expect(transactionTemplateFindFirst).toHaveBeenCalledTimes(1)
  })

  it('supports input.context.transaction_client for policy evaluation template lookups', async () => {
    const rootWorkloadFindFirst = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txWorkloadFindFirst = vi.fn(() => Promise.resolve({enabled: true}))
    const txIntegrationFindFirst = vi.fn(() =>
      Promise.resolve({
        enabled: true,
        templateId: 'tpl_gmail',
        templateVersion: 2
      })
    )
    const txTemplateFindFirst = vi.fn(() =>
      Promise.resolve({
        templateId: 'tpl_gmail',
        version: 2,
        provider: 'google_gmail',
        status: 'active',
        templateJson: createTemplate({templateId: 'tpl_gmail', version: 2})
      })
    )

    const repository = new IntegrationRepository(
      createDbClientStub({
        workload: {
          findFirst: rootWorkloadFindFirst
        }
      })
    )

    const result = await repository.getIntegrationTemplateForPolicyEvaluation({
      tenant_id: 't_1',
      workload_id: 'w_1',
      integration_id: 'int_1',
      context: {
        transaction_client: createDbClientStub({
          workload: {
            findFirst: txWorkloadFindFirst
          },
          integration: {
            findFirst: txIntegrationFindFirst
          },
          templateVersion: {
            findFirst: txTemplateFindFirst
          }
        })
      }
    })

    expect(result.integration_enabled).toBe(true)
    expect(result.template.version).toBe(2)
    expect(rootWorkloadFindFirst).not.toHaveBeenCalled()
    expect(txWorkloadFindFirst).toHaveBeenCalledTimes(1)
    expect(txIntegrationFindFirst).toHaveBeenCalledTimes(1)
    expect(txTemplateFindFirst).toHaveBeenCalledTimes(1)
  })

  it('rejects malformed transaction_client for execute-template reads', async () => {
    const repository = new IntegrationRepository(createDbClientStub())

    await expect(
      repository.getIntegrationTemplateForExecute(
        {
          tenant_id: 't_1',
          workload_id: 'w_1',
          integration_id: 'int_1',
          transaction_client: {
            workload: {}
          }
        }
      )
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('fails closed when template binding is missing', async () => {
    const repository = new IntegrationRepository(
      createDbClientStub({
        workload: {
          findFirst: vi.fn(() => Promise.resolve({enabled: true}))
        },
        integration: {
          findFirst: vi.fn(() =>
            Promise.resolve({
              enabled: true,
              templateId: 'tpl_gmail',
              templateVersion: 9
            })
          )
        },
        templateVersion: {
          findFirst: vi.fn(() => Promise.resolve(null))
        }
      })
    )

    await expect(
      repository.getIntegrationTemplateForExecute({
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'int_1'
      })
    ).rejects.toMatchObject({
      code: 'not_found'
    })
  })

  it('resolves integration-template binding with transaction context', async () => {
    const rootFindFirst = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txIntegrationFindFirst = vi.fn(() =>
      Promise.resolve({
        enabled: true,
        templateId: 'tpl_gmail',
        templateVersion: null
      })
    )
    const txTemplateFindFirst = vi.fn(() =>
      Promise.resolve({
        templateId: 'tpl_gmail',
        version: 5,
        provider: 'google_gmail',
        status: 'active',
        templateJson: createTemplate({templateId: 'tpl_gmail', version: 5})
      })
    )

    const repository = new IntegrationRepository(
      createDbClientStub({
        integration: {
          findFirst: rootFindFirst
        }
      })
    )

    const binding = await repository.getIntegrationTemplateBindingByTenantAndId({
      tenant_id: 't_1',
      integration_id: 'int_1',
      context: {
        transaction_client: createDbClientStub({
          integration: {
            findFirst: txIntegrationFindFirst
          },
          templateVersion: {
            findFirst: txTemplateFindFirst
          }
        })
      }
    })

    expect(binding).toMatchObject({
      tenant_id: 't_1',
      integration_id: 'int_1',
      enabled: true,
      template_id: 'tpl_gmail',
      template_version: 5
    })
    expect(rootFindFirst).not.toHaveBeenCalled()
    expect(txIntegrationFindFirst).toHaveBeenCalledTimes(1)
    expect(txTemplateFindFirst).toHaveBeenCalledTimes(1)
  })
})

describe('TemplateRepository', () => {
  it('returns null for inactive template versions in strict by-version lookup', async () => {
    const repository = new TemplateRepository(
      createDbClientStub({
        templateVersion: {
          findUnique: vi.fn(() =>
            Promise.resolve({
              templateId: 'tpl_gmail',
              version: 1,
              provider: 'google_gmail',
              status: 'disabled',
              templateJson: createTemplate({templateId: 'tpl_gmail', version: 1})
            })
          )
        }
      })
    )

    await expect(
      repository.getTemplateByTenantTemplateIdVersion({
        tenant_id: 't_1',
        template_id: 'tpl_gmail',
        version: 1
      })
    ).resolves.toBeNull()
  })

  it('supports getTemplateByIdVersion alias with transaction_client', async () => {
    const rootFindUnique = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const transactionFindUnique = vi.fn(() =>
      Promise.resolve({
        templateId: 'tpl_gmail',
        version: 2,
        provider: 'google_gmail',
        status: 'active',
        templateJson: createTemplate({templateId: 'tpl_gmail', version: 2})
      })
    )

    const repository = new TemplateRepository(
      createDbClientStub({
        templateVersion: {
          findUnique: rootFindUnique
        }
      })
    )

    const template = await repository.getTemplateByIdVersion(
      {
        tenant_id: 't_1',
        template_id: 'tpl_gmail',
        version: 2,
        transaction_client: createDbClientStub({
          templateVersion: {
            findUnique: transactionFindUnique
          }
        })
      }
    )

    expect(template?.template_id).toBe('tpl_gmail')
    expect(template?.version).toBe(2)
    expect(rootFindUnique).not.toHaveBeenCalled()
    expect(transactionFindUnique).toHaveBeenCalledTimes(1)
  })

  it('supports input.context.transaction_client for strict by-version template lookup', async () => {
    const rootFindUnique = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txFindUnique = vi.fn(() =>
      Promise.resolve({
        templateId: 'tpl_gmail',
        version: 3,
        provider: 'google_gmail',
        status: 'active',
        templateJson: createTemplate({templateId: 'tpl_gmail', version: 3})
      })
    )

    const repository = new TemplateRepository(
      createDbClientStub({
        templateVersion: {
          findUnique: rootFindUnique
        }
      })
    )

    const template = await repository.getTemplateByTenantTemplateIdVersion({
      tenant_id: 't_1',
      template_id: 'tpl_gmail',
      version: 3,
      context: {
        transaction_client: createDbClientStub({
          templateVersion: {
            findUnique: txFindUnique
          }
        })
      }
    })

    expect(template?.version).toBe(3)
    expect(rootFindUnique).not.toHaveBeenCalled()
    expect(txFindUnique).toHaveBeenCalledTimes(1)
  })

  it('returns latest active versions per template id', async () => {
    const repository = new TemplateRepository(
      createDbClientStub({
        templateVersion: {
          findMany: vi.fn(() =>
            Promise.resolve([
              {
                templateId: 'tpl_gmail',
                version: 3,
                provider: 'google_gmail',
                status: 'active' as const,
                templateJson: createTemplate({templateId: 'tpl_gmail', version: 3})
              },
              {
                templateId: 'tpl_gmail',
                version: 2,
                provider: 'google_gmail',
                status: 'active' as const,
                templateJson: createTemplate({templateId: 'tpl_gmail', version: 2})
              },
              {
                templateId: 'tpl_calendar',
                version: 4,
                provider: 'google_calendar',
                status: 'active' as const,
                templateJson: createTemplate({
                  templateId: 'tpl_calendar',
                  version: 4,
                  provider: 'google_calendar'
                })
              }
            ])
          )
        }
      })
    )

    const latest = await repository.listLatestTemplatesByTenant({tenant_id: 't_1'})
    expect(latest).toHaveLength(2)
    expect(latest.map(template => template.template_id).sort()).toEqual(['tpl_calendar', 'tpl_gmail'])
  })

  it('supports context.transaction_client for listTemplateVersionsByTenantAndTemplateId', async () => {
    const rootFindMany = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txFindMany = vi.fn(() =>
      Promise.resolve([
        {
          templateId: 'tpl_gmail',
          version: 1,
          provider: 'google_gmail',
          status: 'active' as const,
          templateJson: createTemplate({templateId: 'tpl_gmail', version: 1})
        }
      ])
    )

    const repository = new TemplateRepository(
      createDbClientStub({
        templateVersion: {
          findMany: rootFindMany
        }
      })
    )

    const templates = await repository.listTemplateVersionsByTenantAndTemplateId({
      tenant_id: 't_1',
      template_id: 'tpl_gmail',
      context: {
        transaction_client: createDbClientStub({
          templateVersion: {
            findMany: txFindMany
          }
        })
      }
    })

    expect(templates).toHaveLength(1)
    expect(templates[0]?.template_id).toBe('tpl_gmail')
    expect(rootFindMany).not.toHaveBeenCalled()
    expect(txFindMany).toHaveBeenCalledTimes(1)
  })

  it('persists template invalidation outbox signals idempotently', async () => {
    const upsert = vi.fn((args: Record<string, unknown>) =>
      Promise.resolve({
        tenantId: 't_1',
        templateId: 'tpl_gmail',
        version: 2,
        updatedAtSignal: new Date('2026-02-13T00:00:00.000Z'),
        payloadJson: (args.create as Record<string, unknown>).payloadJson,
        status: 'pending',
        attempts: 0,
        deliveredAt: null,
        lastError: null
      })
    )

    const repository = new TemplateRepository(
      createDbClientStub({
        templateInvalidationOutbox: {
          upsert
        }
      })
    )

    await repository.persistTemplateInvalidationOutbox({
      signal: {
        tenant_id: 't_1',
        template_id: 'tpl_gmail',
        version: 2,
        updated_at: '2026-02-13T00:00:00.000Z'
      }
    })

    expect(upsert).toHaveBeenCalledTimes(1)
  })

  it('treats equivalent offset timestamps as idempotent for template invalidation outbox', async () => {
    const repository = new TemplateRepository(
      createDbClientStub({
        templateInvalidationOutbox: {
          upsert: vi.fn(() =>
            Promise.resolve({
              tenantId: 't_1',
              templateId: 'tpl_gmail',
              version: 2,
              updatedAtSignal: new Date('2026-02-13T00:00:00.000Z'),
              payloadJson: {
                tenant_id: 't_1',
                template_id: 'tpl_gmail',
                version: 2,
                updated_at: '2026-02-13T00:00:00.000Z'
              },
              status: 'pending',
              attempts: 0,
              deliveredAt: null,
              lastError: null
            })
          )
        }
      })
    )

    await expect(
      repository.persistTemplateInvalidationOutbox({
        signal: {
          tenant_id: 't_1',
          template_id: 'tpl_gmail',
          version: 2,
          updated_at: '2026-02-13T00:00:00+00:00'
        }
      })
    ).resolves.toBeUndefined()
  })

  it('supports transaction_client pass-through for template invalidation outbox persistence', async () => {
    const rootUpsert = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txUpsert = vi.fn((args: Record<string, unknown>) =>
      Promise.resolve({
        tenantId: 't_1',
        templateId: 'tpl_gmail',
        version: 2,
        updatedAtSignal: new Date('2026-02-13T00:00:00.000Z'),
        payloadJson: (args.create as Record<string, unknown>).payloadJson,
        status: 'pending',
        attempts: 0,
        deliveredAt: null,
        lastError: null
      })
    )

    const repository = new TemplateRepository(
      createDbClientStub({
        templateInvalidationOutbox: {
          upsert: rootUpsert
        }
      })
    )

    await repository.persistTemplateInvalidationOutbox({
      signal: {
        tenant_id: 't_1',
        template_id: 'tpl_gmail',
        version: 2,
        updated_at: '2026-02-13T00:00:00.000Z'
      },
      context: {
        transaction_client: createDbClientStub({
          templateInvalidationOutbox: {
            upsert: txUpsert
          }
        })
      }
    })

    expect(rootUpsert).not.toHaveBeenCalled()
    expect(txUpsert).toHaveBeenCalledTimes(1)
  })

  it('rejects provider changes across immutable template versions', async () => {
    const repository = new TemplateRepository(
      createDbClientStub({
        templateVersion: {
          findMany: vi.fn(() =>
            Promise.resolve([
              {
                version: 1,
                provider: 'google_calendar',
                templateId: 'tpl_gmail',
                status: 'active' as const,
                templateJson: createTemplate({templateId: 'tpl_gmail', version: 1, provider: 'google_calendar'})
              }
            ])
          )
        }
      })
    )

    await expect(
      repository.createTemplateVersionImmutable({
        tenant_id: 't_1',
        template: createTemplate({templateId: 'tpl_gmail', version: 2, provider: 'google_gmail'})
      })
    ).rejects.toMatchObject({
      code: 'conflict'
    })
  })
})

describe('runInTransaction', () => {
  it('uses provided transaction_client without opening nested transactions', async () => {
    const rootTransaction = vi.fn(() => Promise.reject(new Error('must_not_open_nested_transaction')))
    const transactionClient = createDbClientStub({
      tenant: {
        findUnique: vi.fn(() =>
          Promise.resolve({
            tenantId: 't_1',
            name: 'Acme',
            createdAt: new Date('2026-01-01T00:00:00.000Z')
          })
        )
      }
    })

    const result = await runInTransaction(
      createDbClientStub({
        $transaction: rootTransaction
      }),
      async txClient => txClient.tenant.findUnique({where: {tenantId: 't_1'}}),
      {
        transaction_client: transactionClient
      }
    )

    expect(result).toMatchObject({
      tenantId: 't_1'
    })
    expect(rootTransaction).not.toHaveBeenCalled()
  })

  it('requires transaction support when no transaction_client is supplied', async () => {
    await expect(
      runInTransaction(createDbClientStub(), async () => Promise.resolve('ok'))
    ).rejects.toMatchObject({
      code: 'dependency_missing'
    })
  })
})

describe('PolicyRuleRepository', () => {
  it('rejects whitespace-only optional scope identifiers', async () => {
    const repository = new PolicyRuleRepository(createDbClientStub())

    await expect(
      repository.createPolicyRule({
        policy: {
          rule_type: 'allow',
          scope: {
            tenant_id: 't_1',
            workload_id: '   ',
            integration_id: 'int_1',
            template_id: 'tpl_gmail',
            action_group: 'gmail_send',
            method: 'POST',
            host: 'gmail.googleapis.com'
          },
          rate_limit: null
        }
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('sorts matched policies deterministically by specificity then id', async () => {
    const repository = new PolicyRuleRepository(
      createDbClientStub({
        policyRule: {
          findMany: vi.fn(() =>
            Promise.resolve([
              {
                policyJson: {
                  policy_id: 'pol_1',
                  rule_type: 'allow',
                  scope: {
                    tenant_id: 't_1',
                    integration_id: 'int_1',
                    action_group: 'gmail_send',
                    method: 'POST',
                    host: 'gmail.googleapis.com'
                  },
                  rate_limit: null
                }
              },
              {
                policyJson: {
                  policy_id: 'pol_2',
                  rule_type: 'allow',
                  scope: {
                    tenant_id: 't_1',
                    workload_id: 'w_1',
                    integration_id: 'int_1',
                    action_group: 'gmail_send',
                    method: 'POST',
                    host: 'gmail.googleapis.com'
                  },
                  rate_limit: null
                }
              }
            ])
          )
        }
      })
    )

    const policies = await repository.listPolicyRulesForDescriptorScope({
      descriptor: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'int_1',
        template_id: 'tpl_gmail',
        template_version: 1,
        method: 'POST',
        canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
        matched_path_group_id: 'gmail_send',
        normalized_headers: [],
        query_keys: []
      }
    })

    expect(policies.map(policy => policy.policy_id)).toEqual(['pol_2', 'pol_1'])
  })

  it('supports input.context.transaction_client for descriptor-scope policy listing', async () => {
    const rootFindMany = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txFindMany = vi.fn(() =>
      Promise.resolve([
        {
          policyJson: {
            policy_id: 'pol_tx',
            rule_type: 'allow',
            scope: {
              tenant_id: 't_1',
              integration_id: 'int_1',
              action_group: 'gmail_send',
              method: 'POST',
              host: 'gmail.googleapis.com'
            },
            rate_limit: null
          }
        }
      ])
    )

    const repository = new PolicyRuleRepository(
      createDbClientStub({
        policyRule: {
          findMany: rootFindMany
        }
      })
    )

    const policies = await repository.listPolicyRulesForDescriptorScope({
      descriptor: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'int_1',
        template_id: 'tpl_gmail',
        template_version: 1,
        method: 'POST',
        canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
        matched_path_group_id: 'gmail_send',
        normalized_headers: [],
        query_keys: []
      },
      context: {
        transaction_client: createDbClientStub({
          policyRule: {
            findMany: txFindMany
          }
        })
      }
    })

    expect(policies.map(policy => policy.policy_id)).toEqual(['pol_tx'])
    expect(rootFindMany).not.toHaveBeenCalled()
    expect(txFindMany).toHaveBeenCalledTimes(1)
  })
})

describe('ApprovalRequestRepository', () => {
  it('validates tenant filter when listing approvals', async () => {
    const repository = new ApprovalRequestRepository(createDbClientStub())

    await expect(
      repository.list({
        tenant_id: '   '
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('transitions approval status when move is valid', async () => {
    const approval = createApproval('pending')
    const update = vi.fn(() =>
      Promise.resolve({
        approvalJson: {
          ...approval,
          status: 'approved'
        }
      })
    )

    const repository = new ApprovalRequestRepository(
      createDbClientStub({
        approvalRequest: {
          findUnique: vi.fn(() =>
            Promise.resolve({
              status: 'pending',
              approvalJson: approval
            })
          ),
          update
        }
      })
    )

    const updated = await repository.transitionApprovalStatus({
      approval_id: 'apr_1',
      status: 'approved',
      decided_at: '2026-01-01T00:00:00.000Z'
    })

    expect(updated.status).toBe('approved')
    expect(update).toHaveBeenCalledTimes(1)
  })

  it('does not rewrite approvals for idempotent status updates', async () => {
    const approval = createApproval('approved')
    const update = vi.fn()
    const repository = new ApprovalRequestRepository(
      createDbClientStub({
        approvalRequest: {
          findUnique: vi.fn(() =>
            Promise.resolve({
              status: 'approved',
              approvalJson: approval
            })
          ),
          update
        }
      })
    )

    const result = await repository.transitionApprovalStatus({
      approval_id: 'apr_1',
      status: 'approved'
    })

    expect(result.status).toBe('approved')
    expect(update).not.toHaveBeenCalled()
  })

  it('supports transaction context in createApprovalRequestFromCanonicalDescriptor', async () => {
    const rootCreate = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txCreate = vi.fn((args: Record<string, unknown>) =>
      Promise.resolve({
        approvalJson: (args.data as Record<string, unknown>).approvalJson
      })
    )
    const summary = createApproval().summary
    const descriptor = createApproval().canonical_descriptor

    const repository = new ApprovalRequestRepository(
      createDbClientStub({
        approvalRequest: {
          create: rootCreate
        }
      })
    )

    const created = await repository.createApprovalRequestFromCanonicalDescriptor({
      correlation_id: 'corr_1',
      expires_at: '2026-01-02T00:00:00.000Z',
      summary,
      canonical_descriptor: descriptor,
      context: {
        transaction_client: createDbClientStub({
          approvalRequest: {
            create: txCreate
          }
        })
      }
    })

    expect(created.status).toBe('pending')
    expect(rootCreate).not.toHaveBeenCalled()
    expect(txCreate).toHaveBeenCalledTimes(1)
  })

  it('supports transaction context in findOpenApprovalByCanonicalDescriptor', async () => {
    const rootFindFirst = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txFindFirst = vi.fn(() =>
      Promise.resolve({
        approvalJson: createApproval('pending')
      })
    )

    const repository = new ApprovalRequestRepository(
      createDbClientStub({
        approvalRequest: {
          findFirst: rootFindFirst
        }
      })
    )

    const approval = await repository.findOpenApprovalByCanonicalDescriptor({
      descriptor: createApproval().canonical_descriptor,
      context: {
        transaction_client: createDbClientStub({
          approvalRequest: {
            findFirst: txFindFirst
          }
        })
      }
    })

    expect(approval?.status).toBe('pending')
    expect(rootFindFirst).not.toHaveBeenCalled()
    expect(txFindFirst).toHaveBeenCalledTimes(1)
  })
})

describe('AuditEventRepository', () => {
  it('rejects invalid cursor timestamps', async () => {
    const findMany = vi.fn(() => Promise.resolve([]))
    const repository = new AuditEventRepository(
      createDbClientStub({
        auditEvent: {
          findMany
        }
      })
    )

    const cursor = Buffer.from('not-a-date|evt_1|t_1', 'utf8').toString('base64url')

    await expect(
      repository.queryAuditEvents({
        cursor,
        limit: 10
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })

    expect(findMany).not.toHaveBeenCalled()
  })

  it('returns a next cursor when page limit is reached', async () => {
    const findMany = vi.fn(() =>
      Promise.resolve([
        {
          eventJson: {
            event_id: 'evt_2',
            timestamp: '2026-01-02T00:00:00.000Z',
            tenant_id: 't_1',
            correlation_id: 'corr_1',
            event_type: 'execute'
          },
          eventId: 'evt_2',
          timestamp: new Date('2026-01-02T00:00:00.000Z'),
          tenantId: 't_1'
        }
      ])
    )
    const repository = new AuditEventRepository(
      createDbClientStub({
        auditEvent: {
          findMany
        }
      })
    )

    const page = await repository.queryAuditEvents({
      tenant_id: 't_1',
      limit: 1
    })

    expect(page.items).toHaveLength(1)
    expect(page.next_cursor).toBeDefined()
  })

  it('appends policy decision events via normalized audit schema', async () => {
    const create = vi.fn(() =>
      Promise.resolve({
        eventId: 'evt_1',
        timestamp: new Date('2026-01-01T00:00:00.000Z'),
        tenantId: 't_1',
        eventJson: {
          event_id: 'evt_1',
          timestamp: '2026-01-01T00:00:00.000Z',
          tenant_id: 't_1',
          correlation_id: 'corr_1',
          event_type: 'policy_decision'
        }
      })
    )
    const repository = new AuditEventRepository(
      createDbClientStub({
        auditEvent: {
          create
        }
      })
    )

    await repository.appendPolicyDecisionAuditEvent({
      descriptor: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'int_1',
        template_id: 'tpl_gmail',
        template_version: 1,
        method: 'POST',
        canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
        matched_path_group_id: 'gmail_send',
        normalized_headers: [],
        query_keys: []
      },
      decision: {
        decision: 'denied',
        reason_code: 'policy_deny',
        action_group: 'gmail_send',
        risk_tier: 'high',
        trace: []
      },
      correlation_id: 'corr_1',
      timestamp: '2026-01-01T00:00:00.000Z',
      event_id: 'evt_1'
    })

    expect(create).toHaveBeenCalledTimes(1)
  })

  it('supports transaction context in appendAuditEvent', async () => {
    const rootCreate = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txCreate = vi.fn(() =>
      Promise.resolve({
        eventId: 'evt_1',
        timestamp: new Date('2026-01-01T00:00:00.000Z'),
        tenantId: 't_1',
        eventJson: {}
      })
    )
    const repository = new AuditEventRepository(
      createDbClientStub({
        auditEvent: {
          create: rootCreate
        }
      })
    )

    await repository.appendAuditEvent({
      event: {
        event_id: 'evt_1',
        timestamp: '2026-01-01T00:00:00.000Z',
        tenant_id: 't_1',
        correlation_id: 'corr_1',
        event_type: 'execute'
      },
      context: {
        transaction_client: createDbClientStub({
          auditEvent: {
            create: txCreate
          }
        })
      }
    })

    expect(rootCreate).not.toHaveBeenCalled()
    expect(txCreate).toHaveBeenCalledTimes(1)
  })

  it('supports transaction context in appendPolicyDecisionAuditEvent', async () => {
    const rootCreate = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txCreate = vi.fn(() =>
      Promise.resolve({
        eventId: 'evt_1',
        timestamp: new Date('2026-01-01T00:00:00.000Z'),
        tenantId: 't_1',
        eventJson: {}
      })
    )

    const repository = new AuditEventRepository(
      createDbClientStub({
        auditEvent: {
          create: rootCreate
        }
      })
    )

    await repository.appendPolicyDecisionAuditEvent({
      descriptor: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'int_1',
        template_id: 'tpl_gmail',
        template_version: 1,
        method: 'POST',
        canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
        matched_path_group_id: 'gmail_send',
        normalized_headers: [],
        query_keys: []
      },
      decision: {
        decision: 'allowed',
        reason_code: 'ok',
        action_group: 'gmail_send',
        risk_tier: 'high',
        trace: []
      },
      correlation_id: 'corr_1',
      timestamp: '2026-01-01T00:00:00.000Z',
      event_id: 'evt_1',
      context: {
        transaction_client: createDbClientStub({
          auditEvent: {
            create: txCreate
          }
        })
      }
    })

    expect(rootCreate).not.toHaveBeenCalled()
    expect(txCreate).toHaveBeenCalledTimes(1)
  })

  it('appends ssrf decision projection via idempotent upsert', async () => {
    const projection = createSsrfDecisionProjection()
    const upsert = vi.fn(() =>
      Promise.resolve({
        eventId: projection.event_id,
        timestamp: new Date(projection.timestamp),
        tenantId: projection.tenant_id,
        workloadId: projection.workload_id,
        integrationId: projection.integration_id,
        templateId: projection.template_id,
        templateVersion: projection.template_version,
        destinationHost: projection.destination_host,
        destinationPort: projection.destination_port,
        resolvedIps: projection.resolved_ips,
        decision: projection.decision,
        reasonCode: projection.reason_code,
        correlationId: projection.correlation_id
      })
    )

    const repository = new AuditEventRepository(
      createDbClientStub({
        ssrfGuardDecision: {
          upsert
        }
      })
    )

    const persisted = await repository.appendSsrfGuardDecisionProjection({
      projection
    })

    expect(persisted).toEqual(projection)
    expect(upsert).toHaveBeenCalledTimes(1)
  })

  it('treats equivalent offset timestamps as idempotent for ssrf projection writes', async () => {
    const projection = {
      ...createSsrfDecisionProjection(),
      timestamp: '2026-02-13T00:00:00+00:00'
    }
    const repository = new AuditEventRepository(
      createDbClientStub({
        ssrfGuardDecision: {
          upsert: vi.fn(() =>
            Promise.resolve({
              eventId: projection.event_id,
              timestamp: new Date('2026-02-13T00:00:00.000Z'),
              tenantId: projection.tenant_id,
              workloadId: projection.workload_id,
              integrationId: projection.integration_id,
              templateId: projection.template_id,
              templateVersion: projection.template_version,
              destinationHost: projection.destination_host,
              destinationPort: projection.destination_port,
              resolvedIps: projection.resolved_ips,
              decision: projection.decision,
              reasonCode: projection.reason_code,
              correlationId: projection.correlation_id
            })
          )
        }
      })
    )

    await expect(
      repository.appendSsrfGuardDecisionProjection({
        projection
      })
    ).resolves.toMatchObject({
      event_id: projection.event_id,
      timestamp: '2026-02-13T00:00:00.000Z'
    })
  })

  it('supports transaction_client pass-through for ssrf decision projection writes', async () => {
    const projection = createSsrfDecisionProjection()
    const rootUpsert = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txUpsert = vi.fn(() =>
      Promise.resolve({
        eventId: projection.event_id,
        timestamp: new Date(projection.timestamp),
        tenantId: projection.tenant_id,
        workloadId: projection.workload_id,
        integrationId: projection.integration_id,
        templateId: projection.template_id,
        templateVersion: projection.template_version,
        destinationHost: projection.destination_host,
        destinationPort: projection.destination_port,
        resolvedIps: projection.resolved_ips,
        decision: projection.decision,
        reasonCode: projection.reason_code,
        correlationId: projection.correlation_id
      })
    )

    const repository = new AuditEventRepository(
      createDbClientStub({
        ssrfGuardDecision: {
          upsert: rootUpsert
        }
      })
    )

    const persisted = await repository.appendSsrfGuardDecisionProjection({
      projection,
      context: {
        transaction_client: createDbClientStub({
          ssrfGuardDecision: {
            upsert: txUpsert
          }
        })
      }
    })

    expect(persisted).toEqual(projection)
    expect(rootUpsert).not.toHaveBeenCalled()
    expect(txUpsert).toHaveBeenCalledTimes(1)
  })

  it('rejects conflicting ssrf projection payload for existing event_id', async () => {
    const projection = createSsrfDecisionProjection()
    const repository = new AuditEventRepository(
      createDbClientStub({
        ssrfGuardDecision: {
          upsert: vi.fn(() =>
            Promise.resolve({
              eventId: projection.event_id,
              timestamp: new Date(projection.timestamp),
              tenantId: projection.tenant_id,
              workloadId: projection.workload_id,
              integrationId: projection.integration_id,
              templateId: projection.template_id,
              templateVersion: projection.template_version,
              destinationHost: projection.destination_host,
              destinationPort: projection.destination_port,
              resolvedIps: projection.resolved_ips,
              decision: projection.decision,
              reasonCode: 'dns_resolution_failed',
              correlationId: projection.correlation_id
            })
          )
        }
      })
    )

    await expect(
      repository.appendSsrfGuardDecisionProjection({
        projection
      })
    ).rejects.toMatchObject({
      code: 'conflict'
    })
  })

  it('returns null when tenant redaction profile is missing', async () => {
    const repository = new AuditEventRepository(
      createDbClientStub({
        auditRedactionProfile: {
          findUnique: vi.fn(() => Promise.resolve(null))
        }
      })
    )

    await expect(
      repository.getAuditRedactionProfileByTenant({
        tenant_id: 't_1'
      })
    ).resolves.toBeNull()
  })

  it('upserts tenant redaction profile with strict schema validation', async () => {
    const profile = createAuditRedactionProfile()

    const repository = new AuditEventRepository(
      createDbClientStub({
        auditRedactionProfile: {
          upsert: vi.fn(() =>
            Promise.resolve({
              tenantId: 't_1',
              profileId: 'arp_1',
              profileJson: profile
            })
          )
        }
      })
    )

    const upserted = await repository.upsertAuditRedactionProfile({
      profile
    })

    expect(upserted.profile_id).toBe('arp_1')
    expect(upserted.tenant_id).toBe('t_1')
  })

  it('supports db_context.transaction_client pass-through for redaction profile reads', async () => {
    const rootFindUnique = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txFindUnique = vi.fn(() =>
      Promise.resolve({
        tenantId: 't_1',
        profileId: 'arp_1',
        profileJson: createAuditRedactionProfile()
      })
    )

    const repository = new AuditEventRepository(
      createDbClientStub({
        auditRedactionProfile: {
          findUnique: rootFindUnique
        }
      })
    )

    const profile = await repository.getAuditRedactionProfileByTenant({
      tenant_id: 't_1',
      db_context: {
        transaction_client: createDbClientStub({
          auditRedactionProfile: {
            findUnique: txFindUnique
          }
        })
      }
    })

    expect(profile?.tenant_id).toBe('t_1')
    expect(rootFindUnique).not.toHaveBeenCalled()
    expect(txFindUnique).toHaveBeenCalledTimes(1)
  })

  it('fails closed for malformed db_context.transaction_client on redaction profile access', async () => {
    const repository = new AuditEventRepository(createDbClientStub())

    await expect(
      repository.getAuditRedactionProfileByTenant({
        tenant_id: 't_1',
        db_context: {
          transaction_client: {
            auditRedactionProfile: {}
          }
        }
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })
})

describe('EnrollmentTokenRepository', () => {
  it('issues enrollment tokens with required fields', async () => {
    const create = vi.fn(() => Promise.resolve(createEnrollmentTokenRow()))
    const findUnique = vi.fn(() => Promise.resolve({tenantId: 't_1'}))
    const repository = new EnrollmentTokenRepository(
      createDbClientStub({
        workload: {
          findUnique
        },
        enrollmentToken: {
          create
        }
      })
    )

    const record = await repository.issueEnrollmentToken({
      token_hash: 'a'.repeat(64),
      workload_id: 'w_1',
      tenant_id: 't_1',
      expires_at: '2026-02-10T00:00:00.000Z',
      created_at: '2026-02-09T00:00:00.000Z'
    })

    expect(record.token_hash).toBe('a'.repeat(64))
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(create).toHaveBeenCalledTimes(1)
  })

  it('rejects enrollment token issuance for tenant mismatch', async () => {
    const repository = new EnrollmentTokenRepository(
      createDbClientStub({
        workload: {
          findUnique: vi.fn(() => Promise.resolve({tenantId: 't_expected'}))
        },
        enrollmentToken: {
          create: vi.fn(() => Promise.resolve(createEnrollmentTokenRow()))
        }
      })
    )

    await expect(
      repository.issueEnrollmentToken({
        token_hash: 'a'.repeat(64),
        workload_id: 'w_1',
        tenant_id: 't_other',
        expires_at: '2026-02-10T00:00:00.000Z',
        created_at: '2026-02-09T00:00:00.000Z'
      })
    ).rejects.toMatchObject({
      code: 'conflict'
    })
  })

  it('rejects enrollment token issuance when expires_at is not after created_at', async () => {
    const repository = new EnrollmentTokenRepository(
      createDbClientStub({
        workload: {
          findUnique: vi.fn(() => Promise.resolve({tenantId: 't_1'}))
        },
        enrollmentToken: {
          create: vi.fn(() => Promise.resolve(createEnrollmentTokenRow()))
        }
      })
    )

    await expect(
      repository.issueEnrollmentToken({
        token_hash: 'a'.repeat(64),
        workload_id: 'w_1',
        tenant_id: 't_1',
        expires_at: '2026-02-10T00:00:00.000Z',
        created_at: '2026-02-10T00:00:00.000Z'
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('consumes enrollment tokens atomically', async () => {
    const updateMany = vi.fn(() => Promise.resolve({count: 1}))
    const findUnique = vi.fn(() =>
      Promise.resolve(
        createEnrollmentTokenRow({
          usedAt: new Date('2026-02-10T00:00:00.000Z')
        })
      )
    )
    const repository = new EnrollmentTokenRepository(
      createDbClientStub({
        enrollmentToken: {
          updateMany,
          findUnique
        }
      })
    )

    const record = await repository.consumeEnrollmentTokenOnce({
      token_hash: 'a'.repeat(64),
      now: '2026-02-10T00:00:00.000Z'
    })

    expect(record.used_at).toBe('2026-02-10T00:00:00.000Z')
    expect(updateMany).toHaveBeenCalledWith({
      where: {
        tokenHash: 'a'.repeat(64),
        usedAt: null,
        expiresAt: {
          gt: new Date('2026-02-10T00:00:00.000Z')
        }
      },
      data: {
        usedAt: new Date('2026-02-10T00:00:00.000Z')
      }
    })
    expect(updateMany).toHaveBeenCalledTimes(1)
    expect(findUnique).toHaveBeenCalledTimes(1)
  })

  it('fails closed when enrollment token is unavailable', async () => {
    const updateMany = vi.fn(() => Promise.resolve({count: 0}))
    const repository = new EnrollmentTokenRepository(
      createDbClientStub({
        enrollmentToken: {
          updateMany
        }
      })
    )

    await expect(
      repository.consumeEnrollmentTokenOnce({
        token_hash: 'a'.repeat(64),
        now: '2026-02-10T00:00:00.000Z'
      })
    ).rejects.toMatchObject({
      code: 'not_found'
    })
  })
})

describe('SecretRepository', () => {
  it('requires transactional support for versioned secret writes', async () => {
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
          wrapped_data_key_b64: Buffer.alloc(32, 1).toString('base64'),
          iv_b64: Buffer.alloc(12, 2).toString('base64'),
          ciphertext_b64: Buffer.alloc(64, 3).toString('base64'),
          auth_tag_b64: Buffer.alloc(16, 4).toString('base64')
        }
      })
    ).rejects.toMatchObject({
      code: 'dependency_missing'
    })
  })

  it('creates next secret version and updates active pointer inside transaction', async () => {
    const secretFindUnique = vi.fn(() => Promise.resolve(null))
    const secretCreate = vi.fn(() =>
      Promise.resolve({
        secretRef: 'sec_1',
        tenantId: 't_1',
        integrationId: 'int_1',
        type: 'api_key',
        activeVersion: 1
      })
    )
    const secretVersionFindFirst = vi.fn(() => Promise.resolve(null))
    const secretVersionCreate = vi.fn(() => Promise.resolve(createSecretVersionRow(1)))
    const secretUpdate = vi.fn(() =>
      Promise.resolve({
        secretRef: 'sec_1',
        tenantId: 't_1',
        integrationId: 'int_1',
        type: 'api_key',
        activeVersion: 1
      })
    )

    const transactionDb = createDbClientStub({
      secret: {
        findUnique: secretFindUnique,
        create: secretCreate,
        update: secretUpdate
      },
      secretVersion: {
        findFirst: secretVersionFindFirst,
        create: secretVersionCreate
      }
    })

    const repository = new SecretRepository(
      createDbClientStub({
        $transaction: async operation => operation(transactionDb)
      })
    )

    const created = await repository.createSecretEnvelopeVersion({
      secret_ref: 'sec_1',
      tenant_id: 't_1',
      integration_id: 'int_1',
      secret_type: 'api_key',
      envelope: {
        key_id: 'k_1',
        content_encryption_alg: 'A256GCM',
        key_encryption_alg: 'A256KW',
        wrapped_data_key_b64: Buffer.alloc(32, 1).toString('base64'),
        iv_b64: Buffer.alloc(12, 2).toString('base64'),
        ciphertext_b64: Buffer.alloc(64, 3).toString('base64'),
        auth_tag_b64: Buffer.alloc(16, 4).toString('base64')
      }
    })

    expect(created.version).toBe(1)
    expect(secretCreate).toHaveBeenCalledTimes(1)
    expect(secretUpdate).toHaveBeenCalledWith({
      where: {
        secretRef: 'sec_1'
      },
      data: {
        activeVersion: 1
      }
    })
  })

  it('rejects secret ownership mismatches during version writes', async () => {
    const transactionDb = createDbClientStub({
      secret: {
        findUnique: vi.fn(() =>
          Promise.resolve({
            secretRef: 'sec_1',
            tenantId: 't_other',
            integrationId: 'int_1',
            type: 'api_key',
            activeVersion: 1
          })
        )
      }
    })

    const repository = new SecretRepository(
      createDbClientStub({
        $transaction: async operation => operation(transactionDb)
      })
    )

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
          wrapped_data_key_b64: Buffer.alloc(32, 1).toString('base64'),
          iv_b64: Buffer.alloc(12, 2).toString('base64'),
          ciphertext_b64: Buffer.alloc(64, 3).toString('base64'),
          auth_tag_b64: Buffer.alloc(16, 4).toString('base64')
        }
      })
    ).rejects.toMatchObject({
      code: 'conflict'
    })
  })

  it('returns active manifest signing key record when available', async () => {
    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findFirst: vi.fn(() => Promise.resolve(createManifestSigningKeyRow()))
        }
      })
    )

    const key = await repository.getActiveManifestSigningKeyRecord()

    expect(key?.kid).toBe('manifest_v1')
    expect(key?.status).toBe('active')
    expect(key?.public_jwk.alg).toBe('EdDSA')
  })

  it('uses transaction context client for manifest verification key listing', async () => {
    const rootFindMany = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txFindMany = vi.fn(() =>
      Promise.resolve([
        createManifestSigningKeyRow(),
        createManifestSigningKeyRow({
          kid: 'manifest_v0',
          status: 'retired',
          activatedAt: new Date('2025-12-01T00:00:00.000Z'),
          retiredAt: new Date('2026-01-10T00:00:00.000Z')
        })
      ])
    )

    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findMany: rootFindMany
        }
      })
    )

    const keyset = await repository.listManifestVerificationKeysWithEtag({
      transaction_client: createDbClientStub({
        manifestSigningKey: {
          findMany: txFindMany
        },
        manifestKeysetMetadata: {
          findUnique: vi.fn(() =>
            Promise.resolve({
              keysetName: 'manifest_signing',
              etag: 'W/"etag_1"',
              generatedAt: new Date('2026-01-11T00:00:00.000Z'),
              maxAgeSeconds: 120,
              createdAt: new Date('2026-01-11T00:00:00.000Z'),
              updatedAt: new Date('2026-01-11T00:00:00.000Z')
            })
          )
        }
      })
    })

    expect(rootFindMany).not.toHaveBeenCalled()
    expect(txFindMany).toHaveBeenCalledTimes(1)
    expect(keyset?.etag).toBe('W/"etag_1"')
    expect(keyset?.manifest_keys.keys).toHaveLength(2)
  })

  it('rejects keyset metadata persistence when no verification keys exist', async () => {
    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findFirst: vi.fn(() => Promise.resolve(null))
        }
      })
    )

    await expect(
      repository.persistManifestKeysetMetadata({
        etag: 'W/"etag_1"',
        generated_at: '2026-01-11T00:00:00.000Z',
        max_age_seconds: 120
      })
    ).rejects.toMatchObject({
      code: 'not_found'
    })
  })

  it('upserts manifest keyset metadata once keys are present', async () => {
    const upsert = vi.fn(() =>
      Promise.resolve({
        keysetName: 'manifest_signing',
        etag: 'W/"etag_2"',
        generatedAt: new Date('2026-01-12T00:00:00.000Z'),
        maxAgeSeconds: 180,
        createdAt: new Date('2026-01-12T00:00:00.000Z'),
        updatedAt: new Date('2026-01-12T00:00:00.000Z')
      })
    )

    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findFirst: vi.fn(() => Promise.resolve(createManifestSigningKeyRow()))
        },
        manifestKeysetMetadata: {
          upsert
        }
      })
    )

    await repository.persistManifestKeysetMetadata({
      etag: 'W/"etag_2"',
      generated_at: '2026-01-12T00:00:00.000Z',
      max_age_seconds: 180
    })

    expect(upsert).toHaveBeenCalledWith({
      where: {
        keysetName: 'manifest_signing'
      },
      create: {
        keysetName: 'manifest_signing',
        etag: 'W/"etag_2"',
        generatedAt: new Date('2026-01-12T00:00:00.000Z'),
        maxAgeSeconds: 180
      },
      update: {
        etag: 'W/"etag_2"',
        generatedAt: new Date('2026-01-12T00:00:00.000Z'),
        maxAgeSeconds: 180
      }
    })
  })

  it('returns default crypto verification values when tenant override is missing', async () => {
    const repository = new SecretRepository(
      createDbClientStub({
        cryptoVerificationDefaults: {
          findUnique: vi.fn(() => Promise.resolve(null))
        }
      })
    )

    const defaults = await repository.getCryptoVerificationDefaultsByTenant({
      tenant_id: 't_1'
    })

    expect(defaults).toEqual({
      tenant_id: 't_1',
      require_temporal_validity: true,
      max_clock_skew_seconds: 0
    })
  })

  it('upserts crypto verification defaults with transaction context', async () => {
    const rootUpsert = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txUpsert = vi.fn(() =>
      Promise.resolve({
        tenantId: 't_1',
        requireTemporalValidity: false,
        maxClockSkewSeconds: 120,
        createdAt: new Date('2026-02-13T00:00:00.000Z'),
        updatedAt: new Date('2026-02-13T00:00:00.000Z')
      })
    )
    const repository = new SecretRepository(
      createDbClientStub({
        cryptoVerificationDefaults: {
          upsert: rootUpsert
        }
      })
    )

    const defaults = await repository.upsertCryptoVerificationDefaults(
      {
        tenant_id: 't_1',
        require_temporal_validity: false,
        max_clock_skew_seconds: 120
      },
      {
        transaction_client: createDbClientStub({
          cryptoVerificationDefaults: {
            upsert: txUpsert
          }
        })
      }
    )

    expect(defaults).toEqual({
      tenant_id: 't_1',
      require_temporal_validity: false,
      max_clock_skew_seconds: 120
    })
    expect(rootUpsert).not.toHaveBeenCalled()
    expect(txUpsert).toHaveBeenCalledTimes(1)
  })

  it('rejects invalid max_clock_skew_seconds for crypto verification defaults', async () => {
    const repository = new SecretRepository(createDbClientStub())

    await expect(
      repository.upsertCryptoVerificationDefaults({
        tenant_id: 't_1',
        require_temporal_validity: true,
        max_clock_skew_seconds: 301
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('creates manifest signing key records as retired by default', async () => {
    const create = vi.fn(() =>
      Promise.resolve(
        createManifestSigningKeyRow({
          status: 'retired',
          retiredAt: new Date('2026-02-10T00:00:00.000Z')
        })
      )
    )
    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          create
        }
      })
    )

    const baseKey = createManifestSigningKeyRow()
    const publicJwk = {
      ...baseKey.publicJwk,
      kid: 'manifest_v2'
    }

    const record = await repository.createManifestSigningKeyRecord({
      kid: 'manifest_v2',
      alg: 'EdDSA',
      public_jwk: publicJwk,
      private_key_ref: 'kms:key/manifest_v2',
      created_at: '2026-02-10T00:00:00.000Z'
    })

    expect(record.status).toBe('retired')
    expect(record.retired_at).toBeDefined()
    expect(create).toHaveBeenCalledTimes(1)
  })

  it('activates manifest signing keys that are not revoked', async () => {
    const update = vi.fn(() =>
      Promise.resolve(
        createManifestSigningKeyRow({
          status: 'active',
          activatedAt: new Date('2026-02-11T00:00:00.000Z'),
          retiredAt: null
        })
      )
    )
    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findUnique: vi.fn(() => Promise.resolve(createManifestSigningKeyRow({status: 'retired'}))),
          update
        }
      })
    )

    const record = await repository.setActiveManifestSigningKey({
      kid: 'manifest_v1',
      activated_at: '2026-02-11T00:00:00.000Z'
    })

    expect(record.status).toBe('active')
    expect(record.retired_at).toBeUndefined()
    expect(update).toHaveBeenCalledTimes(1)
  })

  it('retires manifest signing keys via explicit retire method', async () => {
    const update = vi.fn(() =>
      Promise.resolve(
        createManifestSigningKeyRow({
          status: 'retired',
          retiredAt: new Date('2026-02-12T00:00:00.000Z')
        })
      )
    )
    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findUnique: vi.fn(() => Promise.resolve(createManifestSigningKeyRow({status: 'active'}))),
          update
        }
      })
    )

    const record = await repository.retireManifestSigningKey({
      kid: 'manifest_v1',
      retired_at: '2026-02-12T00:00:00.000Z'
    })

    expect(record.status).toBe('retired')
    expect(record.retired_at).toBe('2026-02-12T00:00:00.000Z')
    expect(update).toHaveBeenCalledTimes(1)
  })

  it('revokes manifest signing keys via explicit revoke method', async () => {
    const update = vi.fn(() =>
      Promise.resolve(
        createManifestSigningKeyRow({
          status: 'revoked',
          revokedAt: new Date('2026-02-13T00:00:00.000Z')
        })
      )
    )
    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findUnique: vi.fn(() => Promise.resolve(createManifestSigningKeyRow({status: 'retired'}))),
          update
        }
      })
    )

    const record = await repository.revokeManifestSigningKey({
      kid: 'manifest_v1',
      revoked_at: '2026-02-13T00:00:00.000Z'
    })

    expect(record.status).toBe('revoked')
    expect(record.revoked_at).toBe('2026-02-13T00:00:00.000Z')
    expect(update).toHaveBeenCalledTimes(1)
  })

  it('rejects transitions away from revoked keys', async () => {
    const repository = new SecretRepository(
      createDbClientStub({
        manifestSigningKey: {
          findUnique: vi.fn(() => Promise.resolve(createManifestSigningKeyRow({status: 'revoked'})))
        }
      })
    )

    await expect(
      repository.transitionManifestSigningKeyStatus({
        kid: 'manifest_v1',
        status: 'retired',
        at: '2026-02-11T00:00:00.000Z'
      })
    ).rejects.toMatchObject({
      code: 'state_transition_invalid'
    })
  })
})

describe('AdminAuthRepository', () => {
  it('returns singleton signup policy from getAdminSignupPolicy', async () => {
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminSignupPolicy: {
          upsert: vi.fn(() =>
            Promise.resolve({
              id: 'default',
              newUserMode: 'blocked',
              requireVerifiedEmail: true,
              allowedEmailDomains: [],
              updatedBy: 'system',
              updatedAt: new Date('2026-02-14T00:00:00.000Z')
            })
          )
        }
      })
    )

    await expect(repository.getAdminSignupPolicy()).resolves.toMatchObject({
      new_user_mode: 'blocked',
      require_verified_email: true,
      updated_by: 'system'
    })
  })

  it('normalizes allowed_email_domains and actor in setAdminSignupPolicy', async () => {
    const upsert = vi.fn((args: Record<string, unknown>) => {
      void args
      return Promise.resolve({
        id: 'default',
        newUserMode: 'allowed',
        requireVerifiedEmail: true,
        allowedEmailDomains: ['corp.example.com', 'example.com'],
        updatedBy: 'owner_1',
        updatedAt: new Date('2026-02-14T01:00:00.000Z')
      })
    })
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminSignupPolicy: {
          upsert
        }
      })
    )

    const policy = await repository.setAdminSignupPolicy({
      actor: ' owner_1 ',
      policy: {
        new_user_mode: 'allowed',
        require_verified_email: true,
        allowed_email_domains: ['Example.com', 'corp.example.com']
      }
    })

    expect(policy.allowed_email_domains).toEqual(['corp.example.com', 'example.com'])
    expect(upsert).toHaveBeenCalledTimes(1)
    const [upsertCallArgs] = upsert.mock.calls
    const upsertCall = upsertCallArgs?.[0] as {
      update?: {
        allowedEmailDomains?: string[]
        updatedBy?: string
      }
    }
    expect(upsertCall?.update?.allowedEmailDomains).toEqual(['corp.example.com', 'example.com'])
    expect(upsertCall?.update?.updatedBy).toBe('owner_1')
  })

  it('lists admin identities with cursor pagination and normalized ordering', async () => {
    const createdAt1 = new Date('2026-02-15T00:00:00.000Z')
    const createdAt2 = new Date('2026-02-14T00:00:00.000Z')
    const findMany = vi.fn(() =>
      Promise.resolve([
        createAdminIdentityRow({
          identityId: 'adm_2',
          createdAt: createdAt1,
          roleBindings: [{role: 'owner'}, {role: 'admin'}],
          tenantScopes: [{tenantId: 't_2'}, {tenantId: 't_1'}]
        }),
        createAdminIdentityRow({
          identityId: 'adm_1',
          createdAt: createdAt2,
          roleBindings: [{role: 'admin'}],
          tenantScopes: [{tenantId: 't_1'}]
        })
      ])
    )
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminIdentity: {
          findMany
        }
      })
    )

    const result = await repository.listAdminIdentities({
      status: 'active',
      tenant_id: 't_1',
      role: 'admin',
      search: 'owner@example.com',
      limit: 1
    })

    expect(result.users).toHaveLength(1)
    expect(result.users[0]?.identity_id).toBe('adm_2')
    expect(result.users[0]?.roles).toEqual(['admin', 'owner'])
    expect(result.users[0]?.tenant_ids).toEqual(['t_1', 't_2'])
    expect(typeof result.next_cursor).toBe('string')
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        take: 2
      })
    )
  })

  it('fetches admin identity by id and returns null when missing', async () => {
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminIdentity: {
          findUnique: vi.fn(() => Promise.resolve(null))
        }
      })
    )

    await expect(repository.getAdminIdentityById({identity_id: 'adm_missing'})).resolves.toBeNull()
  })

  it('creates admin identity with normalized role and tenant bindings', async () => {
    const create = vi.fn((args: Record<string, unknown>) => {
      void args
      return Promise.resolve(
        createAdminIdentityRow({
          identityId: 'adm_1',
          roleBindings: [{role: 'admin'}, {role: 'owner'}],
          tenantScopes: [{tenantId: 't_1'}, {tenantId: 't_2'}]
        })
      )
    })
    const repository = new AdminAuthRepository(
      createDbClientStub({
        tenant: {
          findMany: vi.fn(() =>
            Promise.resolve([
              {
                tenantId: 't_1',
                name: 'Tenant 1',
                createdAt: new Date('2026-02-01T00:00:00.000Z')
              },
              {
                tenantId: 't_2',
                name: 'Tenant 2',
                createdAt: new Date('2026-02-01T00:00:00.000Z')
              }
            ])
          )
        },
        adminIdentity: {
          create
        }
      })
    )

    const result = await repository.createAdminIdentity({
      identity_id: 'adm_1',
      principal: createAdminPrincipal()
    })

    expect(result.roles).toEqual(['admin', 'owner'])
    expect(result.tenant_ids).toEqual(['t_1', 't_2'])
    expect(create).toHaveBeenCalledTimes(1)
  })

  it('uses context.transaction_client in findAdminIdentityByIssuerSubject', async () => {
    const rootFindUnique = vi.fn(() => Promise.reject(new Error('must_not_use_root_client')))
    const txFindUnique = vi.fn(() => Promise.resolve(createAdminIdentityRow()))
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminIdentity: {
          findUnique: rootFindUnique
        }
      })
    )

    const identity = await repository.findAdminIdentityByIssuerSubject({
      issuer: 'https://accounts.google.com',
      subject: 'admin-sub-1',
      context: {
        transaction_client: createDbClientStub({
          adminIdentity: {
            findUnique: txFindUnique
          }
        })
      }
    })

    expect(identity?.identity_id).toBe('adm_1')
    expect(rootFindUnique).not.toHaveBeenCalled()
    expect(txFindUnique).toHaveBeenCalledTimes(1)
  })

  it('rejects disabling the last active owner', async () => {
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminIdentity: {
          findUnique: vi.fn(() =>
            Promise.resolve(
              createAdminIdentityRow({
                identityId: 'adm_1',
                status: 'active',
                roleBindings: [{role: 'owner'}]
              })
            )
          ),
          count: vi.fn(() => Promise.resolve(0))
        }
      })
    )

    await expect(
      repository.updateAdminIdentityStatus({
        identity_id: 'adm_1',
        status: 'disabled'
      })
    ).rejects.toMatchObject({
      code: 'state_transition_invalid'
    })
  })

  it('validates tenant_ids when updating admin identity bindings', async () => {
    const repository = new AdminAuthRepository(
      createDbClientStub({
        tenant: {
          findMany: vi.fn(() => Promise.resolve([]))
        },
        adminIdentity: {
          findUnique: vi.fn(() => Promise.resolve(createAdminIdentityRow())),
          count: vi.fn(() => Promise.resolve(1))
        }
      })
    )

    await expect(
      repository.updateAdminIdentityBindings({
        identity_id: 'adm_1',
        patch: {
          tenant_ids: ['missing_tenant']
        }
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    })
  })

  it('updates role bindings without replacing tenant scope when tenant_ids are omitted', async () => {
    const update = vi.fn(() =>
      Promise.resolve(
        createAdminIdentityRow({
          identityId: 'adm_1',
          roleBindings: [{role: 'admin'}],
          tenantScopes: [{tenantId: 't_1'}]
        })
      )
    )
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminIdentity: {
          findUnique: vi.fn(() => Promise.resolve(createAdminIdentityRow({identityId: 'adm_1'}))),
          count: vi.fn(() => Promise.resolve(1)),
          update
        }
      })
    )

    await repository.updateAdminIdentityBindings({
      identity_id: 'adm_1',
      patch: {
        roles: ['admin']
      }
    })

    expect(update).toHaveBeenCalledTimes(1)
    const updateCallArgs = update.mock.calls[0] as unknown as [Record<string, unknown>]
    const updateCall = updateCallArgs[0] as {
      data?: Record<string, unknown>
    }
    expect(updateCall.data).not.toHaveProperty('tenantScopes')
  })

  it('creates admin access requests with normalized principal fields', async () => {
    const create = vi.fn((args: Record<string, unknown>) => {
      void args
      return Promise.resolve(
        createAdminAccessRequestRow({
          requestedRoles: ['admin', 'owner'],
          requestedTenantIds: ['t_1', 't_2'],
          email: 'owner@example.com'
        })
      )
    })
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminAccessRequest: {
          create
        }
      })
    )

    const request = await repository.createAdminAccessRequest({
      request_id: 'aar_1',
      principal: createAdminPrincipal({email: 'Owner@Example.com'}),
      reason: '  Please approve  '
    })

    expect(request.email).toBe('owner@example.com')
    expect(request.reason).toBe('Please approve')
    expect(create).toHaveBeenCalledTimes(1)
  })

  it('lists access requests with cursor pagination', async () => {
    const createdAt1 = new Date('2026-02-15T00:00:00.000Z')
    const createdAt2 = new Date('2026-02-14T00:00:00.000Z')
    const findMany = vi.fn(() =>
      Promise.resolve([
        createAdminAccessRequestRow({requestId: 'aar_2', createdAt: createdAt1, status: 'pending'}),
        createAdminAccessRequestRow({requestId: 'aar_1', createdAt: createdAt2, status: 'approved'})
      ])
    )
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminAccessRequest: {
          findMany
        }
      })
    )

    const result = await repository.listAdminAccessRequests({
      status: 'pending',
      role: 'owner',
      tenant_id: 't_1',
      search: 'owner@example.com',
      limit: 1
    })

    expect(result.requests).toHaveLength(1)
    expect(result.requests[0]?.request_id).toBe('aar_2')
    expect(typeof result.next_cursor).toBe('string')
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        take: 2
      })
    )
  })

  it('returns idempotent result for repeated access request approval', async () => {
    const updateMany = vi.fn(() => Promise.resolve({count: 0}))
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminAccessRequest: {
          updateMany,
          findUnique: vi.fn(() =>
            Promise.resolve(
              createAdminAccessRequestRow({
                status: 'approved',
                decisionReason: 'approved',
                decidedBy: 'owner_1',
                decidedAt: new Date('2026-02-14T01:00:00.000Z')
              })
            )
          )
        }
      })
    )

    const result = await repository.transitionAdminAccessRequestStatus({
      request_id: 'aar_1',
      status: 'approved',
      actor: 'owner_2'
    })

    expect(result.status).toBe('approved')
    expect(updateMany).toHaveBeenCalledTimes(1)
  })

  it('rejects admin access request transitions from terminal states', async () => {
    const updateMany = vi.fn(() => Promise.resolve({count: 0}))
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminAccessRequest: {
          updateMany,
          findUnique: vi.fn(() =>
            Promise.resolve(
              createAdminAccessRequestRow({
                status: 'approved',
                decisionReason: 'done',
                decidedBy: 'owner_1',
                decidedAt: new Date('2026-02-14T01:00:00.000Z')
              })
            )
          )
        }
      })
    )

    await expect(
      repository.transitionAdminAccessRequestStatus({
        request_id: 'aar_1',
        status: 'denied',
        actor: 'owner_2'
      })
    ).rejects.toMatchObject({
      code: 'state_transition_invalid'
    })
  })

  it('transitions pending admin access requests atomically', async () => {
    const updateMany = vi.fn(() => Promise.resolve({count: 1}))
    const repository = new AdminAuthRepository(
      createDbClientStub({
        adminAccessRequest: {
          updateMany,
          findUnique: vi.fn(() =>
            Promise.resolve(
              createAdminAccessRequestRow({
                status: 'approved',
                decisionReason: 'approved',
                decidedBy: 'owner_2',
                decidedAt: new Date('2026-02-14T02:00:00.000Z')
              })
            )
          )
        }
      })
    )

    const result = await repository.transitionAdminAccessRequestStatus({
      request_id: 'aar_1',
      status: 'approved',
      actor: 'owner_2',
      reason: 'approved',
      decided_at: '2026-02-14T02:00:00.000Z'
    })

    expect(result.status).toBe('approved')
    expect(result.decided_by).toBe('owner_2')
    expect(updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          requestId: 'aar_1',
          status: 'pending'
        }
      })
    )
  })
})

describe('module factory', () => {
  it('constructs all repository instances from injected db client', () => {
    const repositories = createDbRepositories(createDbClientStub())

    expect(repositories.adminAuthRepository).toBeInstanceOf(AdminAuthRepository)
    expect(repositories.tenantRepository).toBeInstanceOf(TenantRepository)
    expect(repositories.userRepository).toBeInstanceOf(UserRepository)
    expect(repositories.workloadRepository).toBeInstanceOf(WorkloadRepository)
    expect(repositories.enrollmentTokenRepository).toBeInstanceOf(EnrollmentTokenRepository)
    expect(repositories.sessionRepository).toBeInstanceOf(SessionRepository)
    expect(repositories.integrationRepository).toBeInstanceOf(IntegrationRepository)
    expect(repositories.secretRepository).toBeInstanceOf(SecretRepository)
    expect(repositories.templateRepository).toBeInstanceOf(TemplateRepository)
    expect(repositories.policyRuleRepository).toBeInstanceOf(PolicyRuleRepository)
    expect(repositories.approvalRequestRepository).toBeInstanceOf(ApprovalRequestRepository)
    expect(repositories.auditEventRepository).toBeInstanceOf(AuditEventRepository)
  })
})
