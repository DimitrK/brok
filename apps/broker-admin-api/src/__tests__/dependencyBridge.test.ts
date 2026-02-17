import * as dbPackage from '@broker-interceptor/db';
import {describe, expect, it, vi} from 'vitest';
import type {ExternalCaEnrollmentProvider} from '@broker-interceptor/auth';

import {AdminAuthenticator, type AdminPrincipal} from '../auth';
import {CertificateIssuer} from '../certificateIssuer';
import {DependencyBridge} from '../dependencyBridge';
import {conflict} from '../errors';
import type {ProcessInfrastructure} from '../infrastructure';
import {ControlPlaneRepository} from '../repository';

const encodeLength = (length: number) => {
  if (length < 0x80) {
    return Buffer.from([length]);
  }

  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }

  return Buffer.from([0x80 | bytes.length, ...bytes]);
};

const encodeNode = (tag: number, payload: Buffer) =>
  Buffer.concat([Buffer.from([tag]), encodeLength(payload.length), payload]);

const encodeOid = (oid: string) => {
  const parts = oid.split('.').map(part => Number.parseInt(part, 10));
  if (parts.length < 2) {
    throw new Error('invalid OID');
  }

  const first = parts[0] * 40 + parts[1];
  const tail = parts.slice(2).flatMap(part => {
    const encoded: number[] = [part & 0x7f];
    let value = part >> 7;
    while (value > 0) {
      encoded.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }
    return encoded;
  });

  return Buffer.from([first, ...tail]);
};

const toPem = (der: Buffer) => {
  const base64 = der.toString('base64');
  const wrapped = base64.match(/.{1,64}/gu)?.join('\n') ?? base64;
  return `-----BEGIN CERTIFICATE REQUEST-----\n${wrapped}\n-----END CERTIFICATE REQUEST-----`;
};

const buildCsrPem = ({sanUri, includeClientAuthEku}: {sanUri: string; includeClientAuthEku: boolean}) => {
  const extReqOid = encodeNode(0x06, encodeOid('1.2.840.113549.1.9.14'));
  const sanOid = encodeNode(0x06, encodeOid('2.5.29.17'));
  const ekuOid = encodeNode(0x06, encodeOid('2.5.29.37'));

  const sanValue = encodeNode(0x30, encodeNode(0x86, Buffer.from(sanUri, 'ascii')));
  const sanExtension = encodeNode(0x30, Buffer.concat([sanOid, encodeNode(0x04, sanValue)]));

  const ekuUsageOid = encodeNode(0x06, encodeOid(includeClientAuthEku ? '1.3.6.1.5.5.7.3.2' : '1.3.6.1.5.5.7.3.1'));
  const ekuValue = encodeNode(0x30, ekuUsageOid);
  const ekuExtension = encodeNode(0x30, Buffer.concat([ekuOid, encodeNode(0x04, ekuValue)]));

  const extensions = encodeNode(0x30, Buffer.concat([sanExtension, ekuExtension]));
  const attribute = encodeNode(0x30, Buffer.concat([extReqOid, encodeNode(0x31, extensions)]));
  const attributes = encodeNode(0xa0, attribute);

  const cri = encodeNode(
    0x30,
    Buffer.concat([
      encodeNode(0x02, Buffer.from([0x00])),
      encodeNode(0x30, Buffer.alloc(0)),
      encodeNode(0x30, Buffer.alloc(0)),
      attributes
    ])
  );

  const csr = encodeNode(
    0x30,
    Buffer.concat([cri, encodeNode(0x30, Buffer.alloc(0)), encodeNode(0x03, Buffer.from([0x00]))])
  );

  return toPem(csr);
};

const createBridgeFixture = async ({
  externalCaEnrollmentProvider
}: {
  externalCaEnrollmentProvider?: ExternalCaEnrollmentProvider;
} = {}) => {
  const repository = await ControlPlaneRepository.create({
    manifestKeys: {keys: []},
    enrollmentTokenTtlSeconds: 600
  });

  const bridge = new DependencyBridge({
    repository,
    authenticator: new AdminAuthenticator({
      mode: 'static',
      tokens: [
        {
          token: 'owner-token-0123456789abcdef',
          subject: 'owner-user',
          roles: ['owner']
        }
      ]
    }),
    certificateIssuer: new CertificateIssuer({
      mode: 'mock',
      mtlsCaPem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
    }),
    externalCaEnrollmentProvider
  });

  return {repository, bridge};
};

describe('dependency bridge', () => {
  it('lists required dependencies and proxies authentication/CA access', async () => {
    const {bridge} = await createBridgeFixture();

    const required = bridge.listRequiredDependencies();
    expect(required.some(item => item.packageName === '@broker-interceptor/db')).toBe(true);
    expect(required.some(item => item.packageName === '@broker-interceptor/crypto')).toBe(true);
    expect(bridge.getMtlsCaPemFromAuthPackage()).toContain('BEGIN CERTIFICATE');

    const principal = await bridge.authenticateAdminPrincipal({
      authorizationHeader: 'Bearer owner-token-0123456789abcdef'
    });
    expect(principal.subject).toBe('owner-user');
  });

  it('uses auth package external_ca handling with fail-closed defaults', async () => {
    const {bridge} = await createBridgeFixture();

    await expect(
      bridge.ensureEnrollmentModeSupported_INCOMPLETE({
        enrollmentMode: 'broker_ca',
        tenantId: 't_1',
        workloadName: 'workload-a'
      })
    ).resolves.toEqual({});

    await expect(
      bridge.ensureEnrollmentModeSupported_INCOMPLETE({
        enrollmentMode: 'external_ca',
        tenantId: 't_1',
        workloadName: 'workload-a'
      })
    ).rejects.toMatchObject({code: 'external_ca_not_configured'});
  });

  it('returns external_ca enrollment data when provider is configured', async () => {
    const {bridge} = await createBridgeFixture({
      externalCaEnrollmentProvider: {
        issueEnrollment: () => ({
          mtlsCaPem: '-----BEGIN CERTIFICATE-----\nEXTERNAL_CA\n-----END CERTIFICATE-----',
          enrollmentReference: 'ext-enr-1'
        })
      }
    });

    await expect(
      bridge.ensureEnrollmentModeSupported_INCOMPLETE({
        enrollmentMode: 'external_ca',
        tenantId: 't_1',
        workloadName: 'workload-external'
      })
    ).resolves.toEqual({
      mtlsCaPem: '-----BEGIN CERTIFICATE-----\nEXTERNAL_CA\n-----END CERTIFICATE-----',
      enrollmentReference: 'ext-enr-1'
    });
  });

  it('validates enrollment CSR and issues mock workload certificates', async () => {
    const {bridge} = await createBridgeFixture();
    const expectedSan = 'spiffe://broker/tenants/t_1/workloads/w_1';
    const csrPem = buildCsrPem({sanUri: expectedSan, includeClientAuthEku: true});

    await expect(
      bridge.validateEnrollmentCsrWithAuthPackage({
        csrPem,
        expectedSanUri: expectedSan,
        requireClientAuthEku: true
      })
    ).resolves.toBeUndefined();

    const issued = await bridge.issueWorkloadCertificateWithAuthPackage({
      input: {
        csrPem,
        workloadId: 'w_1',
        sanUri: expectedSan,
        ttlSeconds: 120
      }
    });

    expect(issued.clientCertPem).toContain('BEGIN CERTIFICATE');
    expect(issued.caChainPem).toContain('BEGIN CERTIFICATE');
    expect(new Date(issued.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  it('rejects malformed CSRs and invalid policies', async () => {
    const {bridge} = await createBridgeFixture();

    await expect(
      bridge.validateEnrollmentCsrWithAuthPackage({
        csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----',
        expectedSanUri: 'spiffe://broker/tenants/t_1/workloads/w_1',
        requireClientAuthEku: true
      })
    ).rejects.toMatchObject({code: 'csr_invalid'});

    expect(() =>
      bridge.validatePolicyRuleWithPolicyEngine({
        policy: {
          rule_type: 'allow',
          scope: {
            tenant_id: 't_1',
            integration_id: 'i_1',
            action_group: 'openai_responses',
            method: 'POST',
            host: 'api.openai.com'
          },
          rate_limit: null,
          unexpected: true
        } as never
      })
    ).toThrow();
  });

  it('validates policies, appends audit events, and rotates manifest keys via crypto package', async () => {
    const {bridge, repository} = await createBridgeFixture();

    const parsedPolicy = bridge.validatePolicyRuleWithPolicyEngine({
      policy: {
        rule_type: 'allow',
        scope: {
          tenant_id: 't_1',
          integration_id: 'i_1',
          action_group: 'openai_responses',
          method: 'POST',
          host: 'api.openai.com'
        },
        rate_limit: null
      }
    });
    expect(parsedPolicy.rule_type).toBe('allow');

    expect(parsedPolicy.scope.host).toBe('api.openai.com');

    expect(() =>
      bridge.validatePolicyRuleWithPolicyEngine({
        policy: {
          rule_type: 'allow',
          scope: {
            tenant_id: 't_1',
            integration_id: 'i_1',
            action_group: 'openai_responses',
            method: 'post',
            host: 'https://api.openai.com'
          },
          rate_limit: null
        }
      })
    ).toThrow();

    const event = repository.createAdminAuditEvent({
      actor: {
        subject: 'owner-user',
        issuer: 'https://broker-admin.local/static',
        email: 'owner-user@local.invalid',
        roles: ['owner'],
        authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
      },
      correlationId: 'corr_bridge_1',
      action: 'dependency_bridge.test',
      tenantId: 't_1'
    });

    await bridge.appendAuditEventWithAuditPackage({event});
    const events = await repository.listAuditEvents({filter: {tenantId: 't_1'}});
    expect(events).toHaveLength(1);
    expect(events[0].event_type).toBe('admin_action');

    const queriedEvents = await bridge.queryAuditEventsWithAuditPackage({
      query: {
        tenant_id: 't_1'
      }
    });
    expect(queriedEvents).toHaveLength(1);

    await expect(bridge.persistStateWithDbPackage()).resolves.toBeUndefined();

    const rotation = await bridge.rotateManifestSigningKeysWithCryptoPackage_INCOMPLETE();
    expect(rotation.rotatedManifestKeys.keys.length).toBe(1);
    expect(rotation.etag).toMatch(/^W\/"/u);

    await expect(
      bridge.rotateManifestSigningKeysWithCryptoPackage_INCOMPLETE({
        retainPreviousKeyCount: -1
      })
    ).rejects.toMatchObject({code: 'manifest_key_rotation_invalid'});
  });

  it('persists manifest key rotation using db repositories when infrastructure is enabled', async () => {
    const {repository} = await createBridgeFixture();

    const createManifestSigningKeyRecord = vi.fn(() => Promise.resolve(undefined));
    const setActiveManifestSigningKey = vi.fn(() => Promise.resolve(undefined));
    const transitionManifestSigningKeyStatus = vi.fn(() => Promise.resolve(undefined));
    const persistManifestKeysetMetadata = vi.fn(() => Promise.resolve(undefined));

    vi.spyOn(dbPackage, 'createDbRepositories').mockReturnValue({
      secretRepository: {
        createManifestSigningKeyRecord,
        setActiveManifestSigningKey,
        transitionManifestSigningKeyStatus,
        persistManifestKeysetMetadata
      }
    } as unknown as ReturnType<typeof dbPackage.createDbRepositories>);

    const findMany = vi
      .fn()
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{kid: 'kid_active'}]);
    const processInfrastructure = {
      enabled: true,
      prisma: {} as never,
      redis: null,
      redisKeyPrefix: 'broker-admin-api:test',
      withTransaction: async <T>(operation: (tx: unknown) => Promise<T>) =>
        operation({
          manifestSigningKey: {
            findMany
          }
        }),
      close: () => Promise.resolve()
    } as unknown as ProcessInfrastructure;

    const bridge = new DependencyBridge({
      repository,
      authenticator: new AdminAuthenticator({
        mode: 'static',
        tokens: [
          {
            token: 'owner-token-0123456789abcdef',
            subject: 'owner-user',
            roles: ['owner']
          }
        ]
      }),
      certificateIssuer: new CertificateIssuer({
        mode: 'mock',
        mtlsCaPem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
      }),
      processInfrastructure,
      manifestKeyEncryption: {
        key: Buffer.alloc(32, 2),
        keyId: 'manifest-kid'
      }
    });

    await bridge.persistManifestKeyRotationWithDbPackage_INCOMPLETE({
      activeSigningPrivateKey: {
        kid: 'kid_active',
        alg: 'EdDSA',
        private_jwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'AQ',
          d: 'AQ'
        }
      },
      rotatedManifestKeys: {
        keys: [
          {
            kid: 'kid_active',
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'AQ',
            use: 'sig',
            alg: 'EdDSA'
          }
        ]
      },
      etag: 'W/"etag-test"'
    });

    expect(createManifestSigningKeyRecord).toHaveBeenCalledTimes(1);
    expect(setActiveManifestSigningKey).toHaveBeenCalledTimes(1);
    expect(transitionManifestSigningKeyStatus).not.toHaveBeenCalled();
    expect(persistManifestKeysetMetadata).toHaveBeenCalledTimes(1);
  });

  it('fails closed when persisted manifest key material does not match rotated keyset', async () => {
    const {repository} = await createBridgeFixture();

    vi.spyOn(dbPackage, 'createDbRepositories').mockReturnValue({
      secretRepository: {
        createManifestSigningKeyRecord: vi.fn(() => Promise.resolve(undefined)),
        setActiveManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
        transitionManifestSigningKeyStatus: vi.fn(() => Promise.resolve(undefined)),
        persistManifestKeysetMetadata: vi.fn(() => Promise.resolve(undefined))
      }
    } as unknown as ReturnType<typeof dbPackage.createDbRepositories>);

    const processInfrastructure = {
      enabled: true,
      prisma: {} as never,
      redis: null,
      redisKeyPrefix: 'broker-admin-api:test',
      withTransaction: async <T>(operation: (tx: unknown) => Promise<T>) =>
        operation({
          manifestSigningKey: {
            findMany: vi.fn(() =>
              Promise.resolve([
              {
                kid: 'kid_active',
                alg: 'EdDSA',
                publicJwk: {
                  kid: 'kid_active',
                  kty: 'OKP',
                  crv: 'Ed25519',
                  x: 'BB',
                  use: 'sig',
                  alg: 'EdDSA'
                }
              }
            ])
            )
          }
        }),
      close: () => Promise.resolve()
    } as unknown as ProcessInfrastructure;

    const bridge = new DependencyBridge({
      repository,
      authenticator: new AdminAuthenticator({
        mode: 'static',
        tokens: [
          {
            token: 'owner-token-0123456789abcdef',
            subject: 'owner-user',
            roles: ['owner']
          }
        ]
      }),
      certificateIssuer: new CertificateIssuer({
        mode: 'mock',
        mtlsCaPem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
      }),
      processInfrastructure,
      manifestKeyEncryption: {
        key: Buffer.alloc(32, 2),
        keyId: 'manifest-kid'
      }
    });

    await expect(
      bridge.persistManifestKeyRotationWithDbPackage_INCOMPLETE({
        activeSigningPrivateKey: {
          kid: 'kid_active',
          alg: 'EdDSA',
          private_jwk: {
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'AQ',
            d: 'AQ'
          }
        },
        rotatedManifestKeys: {
          keys: [
            {
              kid: 'kid_active',
              kty: 'OKP',
              crv: 'Ed25519',
              x: 'AQ',
              use: 'sig',
              alg: 'EdDSA'
            }
          ]
        },
        etag: 'W/"etag-test"'
      })
    ).rejects.toMatchObject({code: 'manifest_key_conflict'});
  });

  it('updates non-active manifest key statuses in bulk inside the transaction', async () => {
    const {repository} = await createBridgeFixture();

    const createManifestSigningKeyRecord = vi.fn(() => Promise.resolve(undefined));
    const setActiveManifestSigningKey = vi.fn(() => Promise.resolve(undefined));
    const transitionManifestSigningKeyStatus = vi.fn(() => Promise.resolve(undefined));
    const persistManifestKeysetMetadata = vi.fn(() => Promise.resolve(undefined));
    const updateMany = vi.fn<
      (input: {
        where: {
          kid: {
            in: string[];
          };
        };
        data: {
          status: 'retired' | 'revoked';
          retiredAt?: Date;
          revokedAt?: Date;
        };
      }) => Promise<{count: number}>
    >(() => Promise.resolve({count: 1}));

    vi.spyOn(dbPackage, 'createDbRepositories').mockReturnValue({
      secretRepository: {
        createManifestSigningKeyRecord,
        setActiveManifestSigningKey,
        transitionManifestSigningKeyStatus,
        persistManifestKeysetMetadata
      }
    } as unknown as ReturnType<typeof dbPackage.createDbRepositories>);

    const findMany = vi
      .fn()
      .mockResolvedValueOnce([
        {
          kid: 'kid_active',
          alg: 'EdDSA',
          publicJwk: {
            kid: 'kid_active',
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'AQ',
            use: 'sig',
            alg: 'EdDSA'
          }
        },
        {
          kid: 'kid_retained',
          alg: 'EdDSA',
          publicJwk: {
            kid: 'kid_retained',
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'BQ',
            use: 'sig',
            alg: 'EdDSA'
          }
        }
      ])
      .mockResolvedValueOnce([
        {kid: 'kid_active', status: 'active'},
        {kid: 'kid_retained', status: 'active'},
        {kid: 'kid_revoked', status: 'retired'}
      ]);

    const processInfrastructure = {
      enabled: true,
      prisma: {} as never,
      redis: null,
      redisKeyPrefix: 'broker-admin-api:test',
      withTransaction: async <T>(operation: (tx: unknown) => Promise<T>) =>
        operation({
          manifestSigningKey: {
            findMany,
            updateMany
          }
        }),
      close: () => Promise.resolve()
    } as unknown as ProcessInfrastructure;

    const bridge = new DependencyBridge({
      repository,
      authenticator: new AdminAuthenticator({
        mode: 'static',
        tokens: [
          {
            token: 'owner-token-0123456789abcdef',
            subject: 'owner-user',
            roles: ['owner']
          }
        ]
      }),
      certificateIssuer: new CertificateIssuer({
        mode: 'mock',
        mtlsCaPem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
      }),
      processInfrastructure,
      manifestKeyEncryption: {
        key: Buffer.alloc(32, 2),
        keyId: 'manifest-kid'
      }
    });

    await bridge.persistManifestKeyRotationWithDbPackage_INCOMPLETE({
      activeSigningPrivateKey: {
        kid: 'kid_active',
        alg: 'EdDSA',
        private_jwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'AQ',
          d: 'AQ'
        }
      },
      rotatedManifestKeys: {
        keys: [
          {
            kid: 'kid_active',
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'AQ',
            use: 'sig',
            alg: 'EdDSA'
          },
          {
            kid: 'kid_retained',
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'BQ',
            use: 'sig',
            alg: 'EdDSA'
          }
        ]
      },
      etag: 'W/"etag-test-bulk"'
    });

    expect(updateMany).toHaveBeenCalledTimes(2);
    const updateManyCalls = updateMany.mock.calls;
    const firstCall = updateManyCalls[0]?.[0];
    const secondCall = updateManyCalls[1]?.[0];

    expect(firstCall).toBeDefined();
    expect(firstCall?.where.kid.in).toEqual(['kid_retained']);
    expect(firstCall?.data.status).toBe('retired');
    expect(firstCall?.data.retiredAt).toBeInstanceOf(Date);

    expect(secondCall).toBeDefined();
    expect(secondCall?.where.kid.in).toEqual(['kid_revoked']);
    expect(secondCall?.data.status).toBe('revoked');
    expect(secondCall?.data.revokedAt).toBeInstanceOf(Date);
    expect(transitionManifestSigningKeyStatus).not.toHaveBeenCalled();
  });

  describe('admin signup and access control wiring', () => {
    const makeOidcPrincipal = (): AdminPrincipal => ({
      subject: 'admin-sub-1',
      issuer: 'https://issuer.example',
      email: 'admin@example.com',
      roles: ['admin'],
      tenantIds: ['t_1'],
      emailVerified: true,
      authContext: {
        mode: 'oidc' as const,
        issuer: 'https://issuer.example'
      }
    });

    const makeBridgeWithRepository = ({
      repository
    }: {
      repository: ControlPlaneRepository;
    }) =>
      new DependencyBridge({
        repository,
        authenticator: new AdminAuthenticator({
          mode: 'static',
          tokens: [
            {
              token: 'owner-token-0123456789abcdef',
              subject: 'owner-user',
              roles: ['owner']
            }
          ]
        }),
        certificateIssuer: new CertificateIssuer({
          mode: 'mock',
          mtlsCaPem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
        })
      });

    it('auto-provisions active identity when signup mode is allowed', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue(null),
        getAdminSignupPolicy: vi.fn().mockResolvedValue({
          new_user_mode: 'allowed',
          require_verified_email: true,
          allowed_email_domains: ['example.com'],
          updated_at: '2026-02-14T00:00:00.000Z',
          updated_by: 'owner-user'
        }),
        createAdminIdentity: vi.fn().mockResolvedValue({
          identity_id: 'adm_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          status: 'active',
          roles: ['admin'],
          tenant_ids: ['t_1'],
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        })
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const resolved = await bridge.resolveAdminIdentityFromToken({
        principal: makeOidcPrincipal()
      });

      expect(resolved.roles).toEqual(['admin']);
      expect(resolved.tenantIds).toEqual(['t_1']);
    });

    it('creates deterministic access request and denies when signup mode is blocked', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue(null),
        getAdminSignupPolicy: vi.fn().mockResolvedValue({
          new_user_mode: 'blocked',
          require_verified_email: true,
          allowed_email_domains: [],
          updated_at: '2026-02-14T00:00:00.000Z',
          updated_by: 'owner-user'
        }),
        createAdminAccessRequest: vi.fn(({requestId}: {requestId: string}) => Promise.resolve({
          request_id: requestId
        }))
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await expect(
        bridge.resolveAdminIdentityFromToken({
          principal: makeOidcPrincipal()
        })
      ).rejects.toMatchObject({code: 'admin_access_request_pending'});
      expect((repository as unknown as {createAdminAccessRequest: ReturnType<typeof vi.fn>}).createAdminAccessRequest)
        .toHaveBeenCalledTimes(1);
    });

    it('approves admin access requests and creates active identity when missing', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        transitionAdminAccessRequestStatus: vi.fn().mockResolvedValue({
          request_id: 'aar_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          requested_roles: ['admin'],
          requested_tenant_ids: ['t_1'],
          status: 'approved',
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        }),
        findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue(null),
        createAdminIdentity: vi.fn().mockResolvedValue({
          identity_id: 'adm_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          status: 'active',
          roles: ['admin'],
          tenant_ids: ['t_1'],
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        })
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const approved = await bridge.approveAdminAccessRequest({
        requestId: 'aar_1',
        actor: {
          subject: 'owner-user',
          issuer: 'https://broker-admin.local/static',
          email: 'owner-user@local.invalid',
          roles: ['owner'],
          authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
        }
      });

      expect(approved.request_id).toBe('aar_1');
      expect(
        (repository as unknown as {createAdminIdentity: ReturnType<typeof vi.fn>}).createAdminIdentity
      ).toHaveBeenCalledTimes(1);
    });

    it('returns static principals without repository identity lookups', async () => {
      const findAdminIdentityByIssuerSubject = vi.fn().mockResolvedValue(null);
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        findAdminIdentityByIssuerSubject
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const staticPrincipal: AdminPrincipal = {
        subject: 'owner-user',
        issuer: 'https://broker-admin.local/static',
        email: 'owner-user@local.invalid',
        roles: ['owner'],
        authContext: {
          mode: 'static',
          issuer: 'https://broker-admin.local/static'
        }
      };

      const resolved = await bridge.resolveAdminIdentityFromToken({principal: staticPrincipal});
      expect(resolved).toEqual(staticPrincipal);
      expect(findAdminIdentityByIssuerSubject).not.toHaveBeenCalled();
    });

    it('uses persisted active identity roles and tenant bindings when present', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue({
          identity_id: 'adm_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          status: 'active',
          roles: ['auditor'],
          tenant_ids: ['t_2'],
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        })
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const resolved = await bridge.resolveAdminIdentityFromToken({
        principal: makeOidcPrincipal()
      });

      expect(resolved.roles).toEqual(['auditor']);
      expect(resolved.tenantIds).toEqual(['t_2']);
    });

    it('rejects sign-in for pending and disabled identities', async () => {
      const disabledLookup = vi.fn().mockResolvedValue({
        identity_id: 'adm_disabled',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'disabled',
        roles: ['admin'],
        tenant_ids: ['t_1'],
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const disabledBridge = makeBridgeWithRepository({
        repository: {
          appendAuditEvent: vi.fn().mockResolvedValue(undefined),
          listAuditEvents: vi.fn().mockResolvedValue([]),
          findAdminIdentityByIssuerSubject: disabledLookup
        } as unknown as ControlPlaneRepository
      });

      await expect(
        disabledBridge.resolveAdminIdentityFromToken({
          principal: makeOidcPrincipal()
        })
      ).rejects.toMatchObject({code: 'admin_identity_disabled'});

      const pendingBridge = makeBridgeWithRepository({
        repository: {
          appendAuditEvent: vi.fn().mockResolvedValue(undefined),
          listAuditEvents: vi.fn().mockResolvedValue([]),
          findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue({
            identity_id: 'adm_pending',
            issuer: 'https://issuer.example',
            subject: 'admin-sub-1',
            email: 'admin@example.com',
            status: 'pending',
            roles: ['admin'],
            tenant_ids: ['t_1'],
            created_at: '2026-02-14T00:00:00.000Z',
            updated_at: '2026-02-14T00:00:00.000Z'
          })
        } as unknown as ControlPlaneRepository
      });

      await expect(
        pendingBridge.resolveAdminIdentityFromToken({
          principal: makeOidcPrincipal()
        })
      ).rejects.toMatchObject({code: 'admin_access_request_pending'});
    });

    it('enforces verified email and domain allowlist in signup policy', async () => {
      const basePolicy = {
        new_user_mode: 'allowed' as const,
        require_verified_email: true,
        allowed_email_domains: ['example.com'],
        updated_at: '2026-02-14T00:00:00.000Z',
        updated_by: 'owner-user'
      };

      const unverifiedBridge = makeBridgeWithRepository({
        repository: {
          appendAuditEvent: vi.fn().mockResolvedValue(undefined),
          listAuditEvents: vi.fn().mockResolvedValue([]),
          getAdminSignupPolicy: vi.fn().mockResolvedValue(basePolicy)
        } as unknown as ControlPlaneRepository
      });
      await expect(
        unverifiedBridge.evaluateSignupPolicy({
          principal: {
            ...makeOidcPrincipal(),
            emailVerified: false
          }
        })
      ).rejects.toMatchObject({code: 'admin_signup_email_unverified'});

      const blockedDomainBridge = makeBridgeWithRepository({
        repository: {
          appendAuditEvent: vi.fn().mockResolvedValue(undefined),
          listAuditEvents: vi.fn().mockResolvedValue([]),
          getAdminSignupPolicy: vi.fn().mockResolvedValue(basePolicy)
        } as unknown as ControlPlaneRepository
      });
      await expect(
        blockedDomainBridge.evaluateSignupPolicy({
          principal: {
            ...makeOidcPrincipal(),
            email: 'admin@blocked.example'
          }
        })
      ).rejects.toMatchObject({code: 'admin_signup_domain_blocked'});
    });

    it('reuses existing identity after create conflict during allowed signup', async () => {
      const findAdminIdentityByIssuerSubject = vi
        .fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({
          identity_id: 'adm_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          status: 'active',
          roles: ['operator'],
          tenant_ids: ['t_9'],
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        });
      const createAdminIdentity = vi.fn(() => {
        throw conflict('db_conflict', 'identity already exists');
      });
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        findAdminIdentityByIssuerSubject,
        getAdminSignupPolicy: vi.fn().mockResolvedValue({
          new_user_mode: 'allowed',
          require_verified_email: true,
          allowed_email_domains: ['example.com'],
          updated_at: '2026-02-14T00:00:00.000Z',
          updated_by: 'owner-user'
        }),
        createAdminIdentity
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const resolved = await bridge.resolveAdminIdentityFromToken({
        principal: makeOidcPrincipal()
      });

      expect(resolved.roles).toEqual(['operator']);
      expect(resolved.tenantIds).toEqual(['t_9']);
    });

    it('returns synthetic pending request when deterministic request already exists', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        createAdminAccessRequest: vi.fn(() => {
          throw conflict('db_conflict', 'request already exists');
        })
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const request = await bridge.createAdminAccessRequest({
        principal: makeOidcPrincipal(),
        reason: 'manual approval'
      });

      expect(request.status).toBe('pending');
      expect(request.request_id.startsWith('aar_')).toBe(true);
      expect(request.reason).toBe('manual approval');
    });

    it('upserts role bindings when approving existing active identity', async () => {
      const upsertAdminRoleBindings = vi.fn().mockResolvedValue({
        identity_id: 'adm_1',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: ['admin'],
        tenant_ids: ['t_1'],
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const createAdminIdentity = vi.fn().mockResolvedValue({
        identity_id: 'adm_unexpected',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: ['admin'],
        tenant_ids: ['t_1'],
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        transitionAdminAccessRequestStatus: vi.fn().mockResolvedValue({
          request_id: 'aar_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          requested_roles: ['admin'],
          requested_tenant_ids: ['t_1'],
          status: 'approved',
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        }),
        findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue({
          identity_id: 'adm_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          status: 'active',
          roles: ['auditor'],
          tenant_ids: ['t_1'],
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        }),
        upsertAdminRoleBindings,
        createAdminIdentity
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await bridge.approveAdminAccessRequest({
        requestId: 'aar_1',
        actor: {
          subject: 'owner-user',
          issuer: 'https://broker-admin.local/static',
          email: 'owner-user@local.invalid',
          roles: ['owner'],
          authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
        }
      });

      expect(upsertAdminRoleBindings).toHaveBeenCalledTimes(1);
      expect(createAdminIdentity).not.toHaveBeenCalled();
    });

    it('rejects approval when existing identity is not active', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        transitionAdminAccessRequestStatus: vi.fn().mockResolvedValue({
          request_id: 'aar_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          requested_roles: ['admin'],
          requested_tenant_ids: ['t_1'],
          status: 'approved',
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        }),
        findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue({
          identity_id: 'adm_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          status: 'pending',
          roles: ['admin'],
          tenant_ids: ['t_1'],
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        })
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await expect(
        bridge.approveAdminAccessRequest({
          requestId: 'aar_1',
          actor: {
            subject: 'owner-user',
            issuer: 'https://broker-admin.local/static',
            email: 'owner-user@local.invalid',
            roles: ['owner'],
            authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
          }
        })
      ).rejects.toMatchObject({code: 'admin_identity_state_invalid'});
    });

    it('applies role and tenant overrides when approving admin access requests', async () => {
      const upsertAdminRoleBindings = vi.fn().mockResolvedValue({
        identity_id: 'adm_1',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: ['owner'],
        tenant_ids: ['t_2'],
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        transitionAdminAccessRequestStatus: vi.fn().mockResolvedValue({
          request_id: 'aar_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          requested_roles: ['admin'],
          requested_tenant_ids: ['t_1'],
          status: 'approved',
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        }),
        findAdminIdentityByIssuerSubject: vi.fn().mockResolvedValue({
          identity_id: 'adm_1',
          issuer: 'https://issuer.example',
          subject: 'admin-sub-1',
          email: 'admin@example.com',
          status: 'active',
          roles: ['admin'],
          tenant_ids: ['t_1'],
          created_at: '2026-02-14T00:00:00.000Z',
          updated_at: '2026-02-14T00:00:00.000Z'
        }),
        upsertAdminRoleBindings
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await bridge.approveAdminAccessRequestWithOverrides({
        requestId: 'aar_1',
        actor: {
          subject: 'owner-user',
          issuer: 'https://broker-admin.local/static',
          email: 'owner-user@local.invalid',
          roles: ['owner'],
          authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
        },
        roles: ['owner'],
        tenantIds: ['t_2'],
        reason: 'override approval'
      });

      expect(upsertAdminRoleBindings).toHaveBeenCalledWith({
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        roles: ['owner'],
        tenantIds: ['t_2']
      });
    });

    it('denies admin access requests through repository transition', async () => {
      const transitionAdminAccessRequestStatus = vi.fn().mockResolvedValue({
        request_id: 'aar_1',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        requested_roles: ['admin'],
        requested_tenant_ids: ['t_1'],
        status: 'denied',
        reason: 'denied',
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        transitionAdminAccessRequestStatus
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const denied = await bridge.denyAdminAccessRequest({
        requestId: 'aar_1',
        actor: {
          subject: 'owner-user',
          issuer: 'https://broker-admin.local/static',
          email: 'owner-user@local.invalid',
          roles: ['owner'],
          authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
        },
        reason: 'denied'
      });

      expect(denied.status).toBe('denied');
      expect(transitionAdminAccessRequestStatus).toHaveBeenCalledWith({
        requestId: 'aar_1',
        status: 'denied',
        actor: 'owner-user',
        reason: 'denied'
      });
    });

    it('rejects admin user-management actions for non-owner principals', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        listAdminUsers: vi.fn().mockResolvedValue({users: []})
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await expect(
        bridge.listAdminUsers({
          actor: {
            subject: 'tenant-admin',
            issuer: 'https://broker-admin.local/static',
            email: 'tenant-admin@local.invalid',
            roles: ['admin'],
            tenantIds: ['t_1'],
            authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
          }
        })
      ).rejects.toMatchObject({code: 'admin_forbidden'});
    });

    it('passes admin user listing filters to repository for owner principals', async () => {
      const listAdminUsers = vi.fn().mockResolvedValue({users: [], next_cursor: null});
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        listAdminUsers
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await bridge.listAdminUsers({
        actor: {
          subject: 'owner-user',
          issuer: 'https://broker-admin.local/static',
          email: 'owner-user@local.invalid',
          roles: ['owner'],
          authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
        },
        status: 'active',
        tenantId: 't_1',
        role: 'admin',
        search: 'owner',
        limit: 25,
        cursor: 'cursor_1'
      });

      expect(listAdminUsers).toHaveBeenCalledWith({
        status: 'active',
        tenantId: 't_1',
        role: 'admin',
        search: 'owner',
        limit: 25,
        cursor: 'cursor_1'
      });
    });

    it('requires at least one binding field when updating admin roles and tenants', async () => {
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        updateAdminUserRolesAndTenants: vi.fn()
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await expect(
        bridge.updateAdminUserRolesAndTenants({
          identityId: 'adm_1',
          actor: {
            subject: 'owner-user',
            issuer: 'https://broker-admin.local/static',
            email: 'owner-user@local.invalid',
            roles: ['owner'],
            authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
          }
        })
      ).rejects.toMatchObject({code: 'admin_user_update_invalid'});
    });

    it('updates admin users atomically through repository orchestration', async () => {
      const updateAdminUser = vi.fn().mockResolvedValue({
        identity_id: 'adm_1',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: ['admin'],
        tenant_ids: ['t_2'],
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        updateAdminUser
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      await bridge.updateAdminUser({
        identityId: 'adm_1',
        actor: {
          subject: 'owner-user',
          issuer: 'https://broker-admin.local/static',
          email: 'owner-user@local.invalid',
          roles: ['owner'],
          authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
        },
        status: 'active',
        roles: ['admin'],
        tenantIds: ['t_2']
      });

      expect(updateAdminUser).toHaveBeenCalledWith({
        identityId: 'adm_1',
        status: 'active',
        roles: ['admin'],
        tenantIds: ['t_2']
      });
    });

    it('updates admin user bindings, status, and access request list for owner principals', async () => {
      const updateAdminUserRolesAndTenants = vi.fn().mockResolvedValue({
        identity_id: 'adm_1',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'active',
        roles: ['admin'],
        tenant_ids: ['t_2'],
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const setAdminUserStatus = vi.fn().mockResolvedValue({
        identity_id: 'adm_1',
        issuer: 'https://issuer.example',
        subject: 'admin-sub-1',
        email: 'admin@example.com',
        status: 'disabled',
        roles: ['admin'],
        tenant_ids: ['t_2'],
        created_at: '2026-02-14T00:00:00.000Z',
        updated_at: '2026-02-14T00:00:00.000Z'
      });
      const listAdminAccessRequests = vi.fn().mockResolvedValue({requests: [], next_cursor: 'cursor_2'});
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        updateAdminUserRolesAndTenants,
        setAdminUserStatus,
        listAdminAccessRequests
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const actor: AdminPrincipal = {
        subject: 'owner-user',
        issuer: 'https://broker-admin.local/static',
        email: 'owner-user@local.invalid',
        roles: ['owner'],
        authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
      };

      await bridge.updateAdminUserRolesAndTenants({
        identityId: 'adm_1',
        actor,
        roles: ['admin'],
        tenantIds: ['t_2']
      });
      await bridge.setAdminUserStatus({
        identityId: 'adm_1',
        actor,
        status: 'disabled'
      });
      await bridge.listAdminAccessRequests({
        actor,
        status: 'pending',
        tenantId: 't_2',
        role: 'admin',
        search: 'admin@example.com',
        limit: 10,
        cursor: 'cursor_1'
      });

      expect(updateAdminUserRolesAndTenants).toHaveBeenCalledWith({
        identityId: 'adm_1',
        roles: ['admin'],
        tenantIds: ['t_2']
      });
      expect(setAdminUserStatus).toHaveBeenCalledWith({
        identityId: 'adm_1',
        status: 'disabled'
      });
      expect(listAdminAccessRequests).toHaveBeenCalledWith({
        status: 'pending',
        tenantId: 't_2',
        role: 'admin',
        search: 'admin@example.com',
        limit: 10,
        cursor: 'cursor_1'
      });
    });

    it('maps signup mode updates to repository policy updates', async () => {
      const setAdminSignupPolicy = vi.fn().mockResolvedValue({
        new_user_mode: 'blocked',
        require_verified_email: true,
        allowed_email_domains: ['example.com'],
        updated_at: '2026-02-14T00:00:00.000Z',
        updated_by: 'owner-user'
      });
      const repository = {
        appendAuditEvent: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue([]),
        setAdminSignupPolicy
      } as unknown as ControlPlaneRepository;

      const bridge = makeBridgeWithRepository({repository});
      const updated = await bridge.setAdminSignupMode({
        mode: 'blocked',
        actor: {
          subject: 'owner-user',
          issuer: 'https://broker-admin.local/static',
          email: 'owner-user@local.invalid',
          roles: ['owner'],
          authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'}
        }
      });

      expect(updated.new_user_mode).toBe('blocked');
      expect(setAdminSignupPolicy).toHaveBeenCalledWith({
        policy: {
          new_user_mode: 'blocked'
        },
        actor: 'owner-user'
      });
    });
  });
});
