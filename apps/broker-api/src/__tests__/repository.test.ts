import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';

import {generateManifestSigningKeyPair} from '@broker-interceptor/crypto';
import {OpenApiTemplateSchema} from '@broker-interceptor/schemas';
import {afterEach, describe, expect, it, vi} from 'vitest';

import {DataPlaneRepository} from '../repository';
import type {ProcessInfrastructure} from '../infrastructure';

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
  const directory = await mkdtemp(path.join(tmpdir(), 'broker-api-repo-test-'));
  tempDirs.push(directory);
  return path.join(directory, 'state.json');
};

const descriptor = {
  tenant_id: 't_1',
  workload_id: 'w_1',
  integration_id: 'i_1',
  template_id: 'tpl_openai_safe',
  template_version: 2,
  method: 'POST' as const,
  canonical_url: 'https://api.openai.com/v1/responses',
  matched_path_group_id: 'openai_responses',
  normalized_headers: [{name: 'content-type', value: 'application/json'}],
  query_keys: []
};

const summary = {
  integration_id: 'i_1',
  action_group: 'openai_responses',
  risk_tier: 'medium' as const,
  destination_host: 'api.openai.com',
  method: 'POST',
  path: '/v1/responses'
};

const createRepositoryState = () => ({
  version: 1,
  workloads: [
    {
      workload_id: 'w_1',
      tenant_id: 't_1',
      name: 'workload-one',
      mtls_san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1',
      enabled: true,
      ip_allowlist: ['203.0.113.0/24']
    }
  ],
  integrations: [
    {
      integration_id: 'i_1',
      tenant_id: 't_1',
      provider: 'openai',
      name: 'OpenAI Integration',
      template_id: 'tpl_openai_safe',
      enabled: true
    },
    {
      integration_id: 'i_missing_tpl',
      tenant_id: 't_1',
      provider: 'openai',
      name: 'Missing template integration',
      template_id: 'tpl_missing',
      enabled: true
    },
    {
      integration_id: 'i_disabled',
      tenant_id: 't_1',
      provider: 'openai',
      name: 'Disabled integration',
      template_id: 'tpl_openai_safe',
      enabled: false
    }
  ],
  templates: [
    {
      template_id: 'tpl_openai_safe',
      version: 1,
      provider: 'openai',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['api.openai.com'],
      redirect_policy: {mode: 'deny'},
      path_groups: [
        {
          group_id: 'openai_chat',
          risk_tier: 'low',
          approval_mode: 'none',
          methods: ['POST'],
          path_patterns: ['^/v1/chat/completions$'],
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
    },
    {
      template_id: 'tpl_openai_safe',
      version: 2,
      provider: 'openai',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['api.openai.com'],
      redirect_policy: {mode: 'deny'},
      path_groups: [
        {
          group_id: 'openai_responses',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['POST'],
          path_patterns: ['^/v1/responses$'],
          query_allowlist: [],
          header_forward_allowlist: ['content-type'],
          body_policy: {
            max_bytes: 8192,
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
    }
  ],
  policies: [],
  approvals: [],
  sessions: [],
  integration_secret_headers: {
    i_1: [
      {name: 'authorization', value: 'Bearer secret-1'},
      {name: 'x-extra', value: 'value'}
    ]
  },
  dpop_required_workload_ids: ['w_1']
});

describe('data plane repository', () => {
  it('initializes from missing state file and persists writes atomically', async () => {
    const statePath = await makeTempStatePath();
    const repository = await DataPlaneRepository.create({
      statePath,
      approvalTtlSeconds: 2,
      manifestTtlSeconds: 30
    });

    expect(repository.getWorkloadBySanUri({sanUri: 'missing'})).toBeNull();
    expect(repository.getManifestVerificationKeys().keys.length).toBeGreaterThan(0);

    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    await repository.saveSession({
      session: {
        sessionId: 's_1',
        workloadId: 'w_1',
        tenantId: 't_1',
        certFingerprint256: 'AA:BB:CC',
        tokenHash: 'token_hash_1',
        expiresAt
      },
      scopes: ['execute']
    });

    const storedSession = repository.getSessionByTokenHash({tokenHash: 'token_hash_1'});
    expect(storedSession?.session_id).toBe('s_1');

    const expiredLookup = repository.getSessionByTokenHash({
      tokenHash: 'token_hash_1',
      now: new Date(Date.now() + 120_000)
    });
    expect(expiredLookup).toBeNull();

    // eslint-disable-next-line security/detect-non-literal-fs-filename -- The state path is generated by the test helper into a temp directory.
    const persistedState = JSON.parse(await readFile(statePath, 'utf8')) as {
      sessions: Array<{session_id: string}>;
      manifest_signing_private_key?: {kid: string};
    };
    expect(persistedState.sessions).toHaveLength(1);
    expect(persistedState.manifest_signing_private_key?.kid).toContain('manifest_');
  });

  it('supports lookup helpers, approval lifecycle, and bounded counters', async () => {
    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 1,
      manifestTtlSeconds: 120
    });

    expect(repository.getWorkloadBySanUri({sanUri: 'spiffe://broker/tenants/t_1/workloads/w_1'})?.workload_id).toBe(
      'w_1'
    );
    expect(repository.getWorkloadById({workloadId: 'w_1'})?.tenant_id).toBe('t_1');
    expect(repository.getWorkloadById({workloadId: 'unknown'})).toBeNull();
    expect(repository.isWorkloadDpopRequired({workloadId: 'w_1'})).toBe(true);
    expect(repository.getIntegrationByTenantAndId({tenantId: 't_1', integrationId: 'missing'})).toBeNull();
    expect(repository.getLatestTemplateById({templateId: 'missing'})).toBeNull();
    expect(repository.getLatestTemplateById({templateId: 'tpl_openai_safe'})?.version).toBe(2);

    const approvalNow = new Date('2026-02-01T00:00:00.000Z');
    const approvalFirst = await repository.createOrReuseApprovalRequest({
      descriptor,
      summary,
      correlationId: 'corr_1',
      now: approvalNow
    });
    const approvalReused = await repository.createOrReuseApprovalRequest({
      descriptor,
      summary,
      correlationId: 'corr_2',
      now: new Date(approvalNow.getTime() + 500)
    });
    expect(approvalReused.approval_id).toBe(approvalFirst.approval_id);

    const approvalAfterExpiry = await repository.createOrReuseApprovalRequest({
      descriptor,
      summary,
      correlationId: 'corr_3',
      now: new Date(approvalNow.getTime() + 2_000)
    });
    expect(approvalAfterExpiry.approval_id).not.toBe(approvalFirst.approval_id);

    const validHeaders = repository.getInjectedHeadersForIntegration({integrationId: 'i_1'});
    expect(validHeaders).toHaveLength(2);
    const mutableRepository = repository as unknown as {
      state: {integration_secret_headers: Record<string, unknown>};
    };
    mutableRepository.state.integration_secret_headers.i_1 = [{name: 'broken'}];
    expect(repository.getInjectedHeadersForIntegration({integrationId: 'i_1'})).toEqual([]);

    const now = new Date('2026-02-01T00:00:00.000Z');
    const firstCount = repository.incrementRateLimitCounter({
      key: 'tenant:t_1/workload:w_1/int:i_1/group:openai_responses',
      intervalSeconds: 30,
      maxRequests: 2,
      now
    });
    expect(firstCount).toMatchObject({allowed: true, remaining: 1});

    const secondCount = repository.incrementRateLimitCounter({
      key: 'tenant:t_1/workload:w_1/int:i_1/group:openai_responses',
      intervalSeconds: 30,
      maxRequests: 2,
      now: new Date(now.getTime() + 1_000)
    });
    expect(secondCount).toMatchObject({allowed: true, remaining: 0});

    const throttled = repository.incrementRateLimitCounter({
      key: 'tenant:t_1/workload:w_1/int:i_1/group:openai_responses',
      intervalSeconds: 30,
      maxRequests: 2,
      now: new Date(now.getTime() + 2_000)
    });
    expect(throttled).toMatchObject({allowed: false, remaining: 0});

    const replayFirst = repository.checkAndStoreDpopReplayJti({
      key: 'dpop-jti-1',
      expiresAt: new Date(now.getTime() + 10_000),
      now
    });
    const replaySecond = repository.checkAndStoreDpopReplayJti({
      key: 'dpop-jti-1',
      expiresAt: new Date(now.getTime() + 10_000),
      now: new Date(now.getTime() + 1_000)
    });
    const replayAfterExpiry = repository.checkAndStoreDpopReplayJti({
      key: 'dpop-jti-1',
      expiresAt: new Date(now.getTime() + 40_000),
      now: new Date(now.getTime() + 20_000)
    });
    expect(replayFirst).toBe(true);
    expect(replaySecond).toBe(false);
    expect(replayAfterExpiry).toBe(true);

    const store = repository.getDpopReplayStore();
    const storeExpiresAt = new Date(Date.now() + 60_000);
    expect(await store.checkAndStore('store-jti-1', storeExpiresAt)).toBe(true);
    expect(await store.checkAndStore('store-jti-1', storeExpiresAt)).toBe(false);

    const manifestRules = repository.listManifestTemplateRulesForTenant({tenantId: 't_1'});
    expect(manifestRules).toHaveLength(1);
    expect(manifestRules.every(rule => rule.path_groups.length > 0)).toBe(true);

    const approvalSummary = repository.buildApprovalSummary({
      descriptor: {
        ...descriptor,
        canonical_url: 'https://API.OpenAI.com/v1/responses?foo=bar'
      },
      actionGroup: 'openai_responses',
      riskTier: 'high',
      integrationId: 'i_1'
    });
    expect(approvalSummary).toEqual({
      integration_id: 'i_1',
      action_group: 'openai_responses',
      risk_tier: 'high',
      destination_host: 'api.openai.com',
      method: 'POST',
      path: '/v1/responses'
    });

    expect(repository.buildSessionScopes({requestedScopes: undefined})).toEqual(['execute', 'manifest.read']);
    expect(repository.buildSessionScopes({requestedScopes: [' execute ', '', 'execute', 'manifest.read']})).toEqual([
      'execute',
      'manifest.read'
    ]);

    expect(repository.getManifestTtlSeconds()).toBe(120);
    expect(repository.createEventId()).toContain('evt_');
    expect(new Date(repository.getNowIso()).toString()).not.toBe('Invalid Date');
  });

  it('accepts ES256 manifest signing keys and can recover from corrupted in-memory key state', async () => {
    const generated = await generateManifestSigningKeyPair({
      alg: 'ES256',
      kid: 'manifest_es256_test'
    });
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: generated.value.private_key,
        manifest_keys: {keys: []}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 90
    });

    const keys = repository.getManifestVerificationKeys();
    expect(keys.keys.some(key => key.kid === 'manifest_es256_test' && key.kty === 'EC')).toBe(true);
    expect(repository.getManifestSigningPrivateKey().kid).toBe('manifest_es256_test');

    const mutableRepository = repository as unknown as {
      state: {
        manifest_signing_private_key?: unknown;
        manifest_signing_private_keys: unknown[];
        manifest_signing_active_private_key_ref?: string;
      };
    };
    mutableRepository.state.manifest_signing_private_key = undefined;
    mutableRepository.state.manifest_signing_private_keys = [];
    mutableRepository.state.manifest_signing_active_private_key_ref = undefined;
    expect(() => repository.getManifestSigningPrivateKey()).toThrow('Manifest signing key is not configured');
  });

  it('normalizes legacy manifest signing keys into private_key_ref state entries', async () => {
    const generated = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_reference_normalization'
    });
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: generated.value.private_key,
        manifest_keys: {keys: [generated.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120
    });

    const mutableRepository = repository as unknown as {
      state: {
        manifest_signing_private_keys: Array<{
          private_key_ref: string;
          private_key: {kid: string};
          status: 'active' | 'retired';
        }>;
        manifest_signing_active_private_key_ref?: string;
      };
    };

    expect(mutableRepository.state.manifest_signing_private_keys).toHaveLength(1);
    expect(mutableRepository.state.manifest_signing_private_keys[0]?.private_key_ref).toBe(
      'state://manifest-signing-key/manifest_reference_normalization'
    );
    expect(mutableRepository.state.manifest_signing_private_keys[0]?.private_key.kid).toBe(
      'manifest_reference_normalization'
    );
    expect(mutableRepository.state.manifest_signing_private_keys[0]?.status).toBe('active');
    expect(mutableRepository.state.manifest_signing_active_private_key_ref).toBe(
      'state://manifest-signing-key/manifest_reference_normalization'
    );
  });

  it('syncs local manifest signing key to shared store when active private_key_ref cannot be resolved locally', async () => {
    const localKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_local_reference_rotation'
    });
    const remoteActiveKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_remote_reference_rotation'
    });
    expect(localKey.ok).toBe(true);
    expect(remoteActiveKey.ok).toBe(true);
    if (!localKey.ok || !remoteActiveKey.ok) {
      return;
    }

    type StoredManifestRecord = {
      kid: string;
      alg: 'EdDSA' | 'ES256';
      public_jwk: unknown;
      private_key_ref: string;
      status: 'active' | 'retired' | 'revoked';
      created_at: string;
      activated_at?: string;
      retired_at?: string;
      revoked_at?: string;
    };

    const records = new Map<string, StoredManifestRecord>();
    records.set(remoteActiveKey.value.private_key.kid, {
      kid: remoteActiveKey.value.private_key.kid,
      alg: remoteActiveKey.value.private_key.alg,
      public_jwk: remoteActiveKey.value.public_key,
      private_key_ref: `state://manifest-signing-key/${remoteActiveKey.value.private_key.kid}`,
      status: 'active',
      created_at: '2026-02-01T00:00:00.000Z',
      activated_at: '2026-02-01T00:00:10.000Z'
    });

    const keysetMetadata = {
      etag: 'W/"initial"',
      generated_at: '2026-02-01T00:00:00.000Z',
      max_age_seconds: 120
    };

    const createManifestSigningKeyRecord = vi.fn(
      (input: {
        kid: string;
        alg: 'EdDSA' | 'ES256';
        public_jwk: unknown;
        private_key_ref: string;
        created_at: string;
      }) => {
        records.set(input.kid, {
          kid: input.kid,
          alg: input.alg,
          public_jwk: input.public_jwk,
          private_key_ref: input.private_key_ref,
          status: 'retired',
          created_at: input.created_at,
          retired_at: input.created_at
        });
        return Promise.resolve(records.get(input.kid) as StoredManifestRecord);
      }
    );

    const setActiveManifestSigningKey = vi.fn((input: {kid: string; activated_at: string}) => {
      for (const [kid, record] of records.entries()) {
        if (record.status === 'active' && kid !== input.kid) {
          records.set(kid, {
            ...record,
            status: 'retired',
            retired_at: input.activated_at
          });
        }
      }
      const target = records.get(input.kid);
      if (!target) {
        return Promise.reject(Object.assign(new Error('missing key'), {code: 'not_found'}));
      }
      const updated = {
        ...target,
        status: 'active' as const,
        activated_at: input.activated_at,
        retired_at: undefined,
        revoked_at: undefined
      };
      records.set(input.kid, updated);
      return Promise.resolve(updated);
    });

    const retireManifestSigningKey = vi.fn((input: {kid: string; retired_at: string}) => {
      const target = records.get(input.kid);
      if (!target) {
        return Promise.reject(Object.assign(new Error('missing key'), {code: 'not_found'}));
      }
      records.set(input.kid, {
        ...target,
        status: 'retired',
        retired_at: input.retired_at
      });
      return Promise.resolve(records.get(input.kid) as StoredManifestRecord);
    });

    const persistManifestKeysetMetadata = vi.fn(
      (input: {etag: string; generated_at: string; max_age_seconds: number}) => {
        keysetMetadata.etag = input.etag;
        keysetMetadata.generated_at = input.generated_at;
        keysetMetadata.max_age_seconds = input.max_age_seconds;
        return Promise.resolve(undefined);
      }
    );

    const getActiveManifestSigningKeyRecord = vi.fn(() =>
      Promise.resolve(Array.from(records.values()).find(record => record.status === 'active') ?? null)
    );

    const listManifestVerificationKeysWithEtag = vi.fn(() =>
      Promise.resolve({
        manifest_keys: {
          keys: Array.from(records.values())
            .filter(record => record.status === 'active' || record.status === 'retired')
            .map(record => record.public_jwk)
        },
        etag: keysetMetadata.etag,
        generated_at: keysetMetadata.generated_at,
        max_age_seconds: keysetMetadata.max_age_seconds
      })
    );

    const redisSet = vi.fn(() => Promise.resolve('OK'));
    const redisEval = vi.fn(() => Promise.resolve(1));

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: localKey.value.private_key,
        manifest_keys: {keys: [localKey.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          set: redisSet,
          eval: redisEval
        } as never,
        dbRepositories: {
          secretRepository: {
            createManifestSigningKeyRecord,
            getActiveManifestSigningKeyRecord,
            setActiveManifestSigningKey,
            retireManifestSigningKey,
            revokeManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
            listManifestVerificationKeysWithEtag,
            persistManifestKeysetMetadata,
            getCryptoVerificationDefaultsByTenant: vi.fn(() =>
              Promise.resolve({
                tenant_id: 't_1',
                require_temporal_validity: true,
                max_clock_skew_seconds: 0
              })
            ),
            upsertCryptoVerificationDefaults: vi.fn(() =>
              Promise.resolve({
                tenant_id: 't_1',
                require_temporal_validity: true,
                max_clock_skew_seconds: 0
              })
            )
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const syncedKey = await repository.getManifestSigningPrivateKeyShared();
    // Sync behavior: uses the LOCAL key (not a new one)
    expect(syncedKey.kid).toBe(localKey.value.private_key.kid);
    expect(syncedKey.kid).not.toBe(remoteActiveKey.value.private_key.kid);

    const mutableRepository = repository as unknown as {
      state: {
        manifest_signing_active_private_key_ref?: string;
      };
    };
    expect(mutableRepository.state.manifest_signing_active_private_key_ref).toBe(
      `state://manifest-signing-key/${syncedKey.kid}`
    );
    const syncedKeySet = repository.getManifestVerificationKeys();
    expect(syncedKeySet.keys.some(key => key.kid === syncedKey.kid)).toBe(true);
    // Note: remote key is NOT in local state after sync (sync doesn't merge remote keys)

    expect(createManifestSigningKeyRecord).toHaveBeenCalledTimes(1);
    expect(setActiveManifestSigningKey).toHaveBeenCalledTimes(1);
    // Sync retires the previous active key first (DB unique constraint: only one active key allowed)
    expect(retireManifestSigningKey).toHaveBeenCalledTimes(1);
  });

  it('supports shared redis counters/replay and transaction pass-through', async () => {
    const counters = new Map<string, number>();
    const ttlByKey = new Map<string, number>();
    const replayKeys = new Set<string>();

    const fakeRedis = {
      incr: (key: string) => {
        const next = (counters.get(key) ?? 0) + 1;
        counters.set(key, next);
        return Promise.resolve(next);
      },
      pTTL: (key: string) => Promise.resolve(ttlByKey.get(key) ?? -1),
      pExpire: (key: string, ttlMs: number) => {
        ttlByKey.set(key, ttlMs);
        return Promise.resolve(1);
      },
      set: (key: string, _value: string, options: {NX?: boolean; PX?: number}) => {
        if (options.NX && replayKeys.has(key)) {
          return Promise.resolve(null);
        }
        replayKeys.add(key);
        return Promise.resolve('OK');
      }
    };

    const withTransaction = vi.fn(<T>(operation: (_client: unknown) => Promise<T>) => operation({}));

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: fakeRedis as never,
        dbRepositories: null,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: withTransaction as never,
        close: () => Promise.resolve()
      }
    });

    expect(repository.isSharedInfrastructureEnabled()).toBe(true);

    const firstSharedCount = await repository.incrementRateLimitCounterShared({
      key: 'tenant:t_1|workload:w_1',
      intervalSeconds: 60,
      maxRequests: 1
    });
    const secondSharedCount = await repository.incrementRateLimitCounterShared({
      key: 'tenant:t_1|workload:w_1',
      intervalSeconds: 60,
      maxRequests: 1
    });

    expect(firstSharedCount.allowed).toBe(true);
    expect(secondSharedCount.allowed).toBe(false);

    const replayStore = repository.getDpopReplayStore();
    const replayExpiry = new Date(Date.now() + 60_000);
    expect(await replayStore.checkAndStore('shared-jti-1', replayExpiry)).toBe(true);
    expect(await replayStore.checkAndStore('shared-jti-1', replayExpiry)).toBe(false);
    expect(await replayStore.checkAndStore('shared-expired-jti', new Date(Date.now() - 1_000))).toBe(false);

    const transactionResult = await repository.withSharedTransaction(() => Promise.resolve('ok'));
    expect(transactionResult).toBe('ok');
    expect(withTransaction).toHaveBeenCalledTimes(1);
  });

  it('wires auth storage scope adapters for local session/workload/replay paths when redis is available', async () => {
    const replayKeys = new Set<string>();
    const redisSet = vi.fn((key: string, _value: string, options: {NX?: boolean; PX?: number}) => {
      if (options.NX && replayKeys.has(key)) {
        return Promise.resolve(null);
      }
      replayKeys.add(key);
      return Promise.resolve('OK');
    });

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          set: redisSet,
          get: vi.fn(() => Promise.resolve(null)),
          del: vi.fn(() => Promise.resolve(0))
        } as never,
        dbRepositories: null,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const authStorageScope = (
      repository as unknown as {
        authStorageScope: {
          persistSessionRecord: (input: {
            session: {
              sessionId: string;
              workloadId: string;
              tenantId: string;
              certFingerprint256: string;
              tokenHash: string;
              expiresAt: string;
              dpopKeyThumbprint?: string;
              scopes?: string[];
            };
          }) => Promise<void>;
          getSessionRecordByTokenHash: (input: {tokenHash: string}) => Promise<{
            sessionId: string;
            workloadId: string;
            tenantId: string;
            certFingerprint256: string;
            tokenHash: string;
            expiresAt: string;
            dpopKeyThumbprint?: string;
            scopes?: string[];
          } | null>;
          loadWorkloadRecordBySanUri: (input: {sanUri: string}) => Promise<{
            workloadId: string;
            tenantId: string;
            enabled: boolean;
            ipAllowlist?: string[];
          } | null>;
          createDpopReplayJtiStore: () => {
            checkAndStore: (jti: string, expiresAt: Date) => Promise<boolean>;
          };
        } | null;
      }
    ).authStorageScope;
    expect(authStorageScope).not.toBeNull();
    if (!authStorageScope) {
      return;
    }

    await authStorageScope.persistSessionRecord({
      session: {
        sessionId: 'session_auth_scope_local',
        workloadId: 'w_1',
        tenantId: 't_1',
        certFingerprint256: 'AA:BB:CC',
        tokenHash: 'a'.repeat(64),
        expiresAt: '2030-02-01T00:10:00.000Z',
        scopes: ['execute']
      }
    });
    const session = await authStorageScope.getSessionRecordByTokenHash({
      tokenHash: 'a'.repeat(64)
    });
    expect(session?.sessionId).toBe('session_auth_scope_local');
    expect(session?.scopes).toEqual(['execute']);

    const workload = await authStorageScope.loadWorkloadRecordBySanUri({
      sanUri: 'spiffe://broker/tenants/t_1/workloads/w_1'
    });
    expect(workload?.workloadId).toBe('w_1');
    expect(workload?.tenantId).toBe('t_1');

    const replayStore = authStorageScope.createDpopReplayJtiStore();
    const replayExpiry = new Date(Date.now() + 60_000);
    expect(await replayStore.checkAndStore('tenant-1:session-1:jti-1', replayExpiry)).toBe(true);
    expect(await replayStore.checkAndStore('tenant-1:session-1:jti-1', replayExpiry)).toBe(false);
    expect(await replayStore.checkAndStore('tenant-1:session-1:jti-expired', new Date(Date.now() - 1_000))).toBe(false);
  });

  it('wires auth storage scope adapters through shared repositories when available', async () => {
    const sessionRepository = {
      upsertSession: vi.fn(() =>
        Promise.resolve({
          sessionId: 'session_auth_scope_shared',
          workloadId: 'w_1',
          tenantId: 't_1',
          certFingerprint256: 'AA:BB:CC',
          tokenHash: 'b'.repeat(64),
          expiresAt: '2030-02-01T00:10:00.000Z',
          scopes: ['execute']
        })
      ),
      getSessionByTokenHash: vi.fn(() =>
        Promise.resolve({
          sessionId: 'session_auth_scope_shared',
          workloadId: 'w_1',
          tenantId: 't_1',
          certFingerprint256: 'AA:BB:CC',
          tokenHash: 'b'.repeat(64),
          expiresAt: '2030-02-01T00:10:00.000Z',
          scopes: ['execute']
        })
      ),
      revokeSessionById: vi.fn(() => Promise.resolve())
    };
    const workloadRepository = {
      getBySanUri: vi.fn(() =>
        Promise.resolve({
          workload_id: 'w_1',
          tenant_id: 't_1',
          name: 'workload-one',
          mtls_san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1',
          enabled: true,
          ip_allowlist: ['203.0.113.0/24'],
          created_at: '2026-02-01T00:00:00.000Z'
        })
      )
    };

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          set: vi.fn(() => Promise.resolve('OK')),
          get: vi.fn(() => Promise.resolve(null)),
          del: vi.fn(() => Promise.resolve(0))
        } as never,
        dbRepositories: {
          sessionRepository,
          workloadRepository
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    await repository.saveSession({
      session: {
        sessionId: 'session_auth_scope_shared',
        workloadId: 'w_1',
        tenantId: 't_1',
        certFingerprint256: 'AA:BB:CC',
        tokenHash: 'b'.repeat(64),
        expiresAt: '2030-02-01T00:10:00.000Z'
      },
      scopes: ['execute']
    });
    const sharedSession = await repository.getSessionByTokenHashShared({
      tokenHash: 'b'.repeat(64)
    });
    expect(sharedSession?.session_id).toBe('session_auth_scope_shared');
    expect(sharedSession?.scopes).toEqual(['execute']);
    expect(sessionRepository.upsertSession).toHaveBeenCalledTimes(1);
    expect(sessionRepository.getSessionByTokenHash).toHaveBeenCalledTimes(1);

    const authStorageScope = (
      repository as unknown as {
        authStorageScope: {
          loadWorkloadRecordBySanUri: (input: {sanUri: string}) => Promise<{workloadId: string} | null>;
        } | null;
      }
    ).authStorageScope;
    expect(authStorageScope).not.toBeNull();
    if (!authStorageScope) {
      return;
    }
    const workload = await authStorageScope.loadWorkloadRecordBySanUri({
      sanUri: 'spiffe://broker/tenants/t_1/workloads/w_1'
    });
    expect(workload?.workloadId).toBe('w_1');
    expect(workloadRepository.getBySanUri).toHaveBeenCalledTimes(1);
  });

  it('uses shared db repositories for session, policy, approval, and manifest rule paths', async () => {
    const workloadFromDb = {
      workload_id: 'w_1',
      tenant_id: 't_1',
      name: 'workload-one',
      mtls_san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1',
      enabled: true,
      ip_allowlist: ['203.0.113.0/24'],
      created_at: '2026-02-01T00:00:00.000Z'
    };

    const integrationFromDb = {
      integration_id: 'i_1',
      tenant_id: 't_1',
      provider: 'openai',
      name: 'OpenAI Integration',
      template_id: 'tpl_openai_safe',
      enabled: true
    };

    const templateFromDb = {
      template_id: 'tpl_openai_safe',
      version: 2,
      provider: 'openai',
      allowed_schemes: ['https'] as const,
      allowed_ports: [443],
      allowed_hosts: ['api.openai.com'],
      redirect_policy: {mode: 'deny'} as const,
      path_groups: [
        {
          group_id: 'openai_responses',
          risk_tier: 'medium' as const,
          approval_mode: 'none' as const,
          methods: ['POST'] as Array<'POST'>,
          path_patterns: ['^/v1/responses$'],
          query_allowlist: [],
          header_forward_allowlist: ['content-type'],
          body_policy: {
            max_bytes: 8_192,
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
    };

    const dbRepositories = {
      workloadRepository: {
        getBySanUri: vi.fn(() => Promise.resolve(workloadFromDb))
      },
      integrationRepository: {
        getById: vi.fn(() => Promise.resolve(integrationFromDb)),
        listByTenant: vi.fn(() =>
          Promise.resolve([
            integrationFromDb,
            {
              ...integrationFromDb,
              integration_id: 'i_missing_template',
              template_id: 'tpl_missing'
            }
          ])
        )
      },
      templateRepository: {
        listLatestTemplatesByTenant: vi.fn(() => Promise.resolve([templateFromDb])),
        getLatestTemplateByTenantTemplateId: vi.fn(({template_id}: {template_id: string}) =>
          Promise.resolve(template_id === 'tpl_missing' ? null : templateFromDb)
        )
      },
      policyRuleRepository: {
        listPolicyRulesForDescriptorScope: vi.fn(() =>
          Promise.resolve([
            {
              policy_id: 'pol_allow',
              rule_type: 'allow',
              scope: {
                tenant_id: 't_1',
                workload_id: 'w_1',
                integration_id: 'i_1',
                template_id: 'tpl_openai_safe',
                template_version: 2,
                action_group: 'openai_responses',
                method: 'POST',
                host: 'api.openai.com',
                query_keys: []
              }
            }
          ])
        )
      },
      sessionRepository: {
        upsertSession: vi.fn(() =>
          Promise.resolve({
            sessionId: 'sess_1',
            workloadId: 'w_1',
            tenantId: 't_1',
            certFingerprint256: 'AA:BB:CC',
            tokenHash: 'f'.repeat(64),
            expiresAt: '2026-02-01T00:10:00.000Z',
            scopes: ['execute', 'manifest.read']
          })
        ),
        getSessionByTokenHash: vi.fn(() =>
          Promise.resolve({
            sessionId: 'sess_1',
            workloadId: 'w_1',
            tenantId: 't_1',
            certFingerprint256: 'AA:BB:CC',
            tokenHash: 'f'.repeat(64),
            expiresAt: '2026-02-01T00:10:00.000Z',
            scopes: ['execute', 'manifest.read']
          })
        )
      },
      approvalRequestRepository: {
        findOpenApprovalByCanonicalDescriptor: vi.fn(() => Promise.resolve(null)),
        createApprovalRequestFromCanonicalDescriptor: vi.fn(() =>
          Promise.resolve({
            approval_id: 'apr_1',
            status: 'pending',
            expires_at: '2026-02-01T00:05:00.000Z',
            correlation_id: 'corr_1',
            summary,
            canonical_descriptor: descriptor
          })
        )
      }
    };

    const processInfrastructure: ProcessInfrastructure = {
      enabled: true,
      prisma: {} as never,
      redis: null,
      dbRepositories: dbRepositories as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
      redisKeyPrefix: 'broker-api:test',
      withTransaction: async operation => operation({} as never),
      close: () => Promise.resolve()
    };

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 300,
      manifestTtlSeconds: 600,
      processInfrastructure
    });

    const savedSession = await repository.saveSession({
      session: {
        sessionId: 'sess_1',
        workloadId: 'w_1',
        tenantId: 't_1',
        certFingerprint256: 'AA:BB:CC',
        tokenHash: 'f'.repeat(64),
        expiresAt: '2026-02-01T00:10:00.000Z'
      },
      scopes: ['execute', 'manifest.read']
    });
    expect(savedSession.session_id).toBe('sess_1');

    const sessionLookup = await repository.getSessionByTokenHashShared({
      tokenHash: 'f'.repeat(64)
    });
    expect(sessionLookup?.workload_id).toBe('w_1');
    (
      dbRepositories.sessionRepository.getSessionByTokenHash as unknown as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(null);
    const missingSession = await repository.getSessionByTokenHashShared({
      tokenHash: 'missing'
    });
    expect(missingSession).toBeNull();

    const workloadLookup = await repository.getWorkloadBySanUriShared({
      sanUri: 'spiffe://broker/tenants/t_1/workloads/w_1'
    });
    expect(workloadLookup?.workload_id).toBe('w_1');

    const integrationLookup = await repository.getIntegrationByTenantAndIdShared({
      tenantId: 't_1',
      integrationId: 'i_1'
    });
    expect(integrationLookup?.integration_id).toBe('i_1');

    const templateLookup = await repository.getLatestTemplateByIdShared({
      tenantId: 't_1',
      templateId: 'tpl_openai_safe'
    });
    expect(templateLookup?.template_id).toBe('tpl_openai_safe');

    const scopedPolicies = await repository.listPolicyRulesForDescriptorShared({
      descriptor
    });
    expect(scopedPolicies).toHaveLength(1);

    const approval = await repository.createOrReuseApprovalRequest({
      descriptor,
      summary,
      correlationId: 'corr_1',
      now: new Date('2026-02-01T00:00:00.000Z')
    });
    expect(approval.approval_id).toBe('apr_1');
    (
      dbRepositories.approvalRequestRepository.findOpenApprovalByCanonicalDescriptor as unknown as ReturnType<
        typeof vi.fn
      >
    ).mockResolvedValueOnce(approval);
    const reusedApproval = await repository.createOrReuseApprovalRequest({
      descriptor,
      summary,
      correlationId: 'corr_2',
      now: new Date('2026-02-01T00:00:01.000Z')
    });
    expect(reusedApproval.approval_id).toBe('apr_1');

    const manifestRules = await repository.listManifestTemplateRulesForTenantShared({
      tenantId: 't_1'
    });
    expect(manifestRules).toHaveLength(1);
    expect(manifestRules[0]?.integration_id).toBe('i_1');
  });

  it('loads shared manifest templates once per tenant and reuses them across integrations', async () => {
    const template = createRepositoryState().templates[0];
    const integrations = [
      {
        integration_id: 'i_1',
        tenant_id: 't_1',
        provider: 'openai',
        name: 'Integration 1',
        template_id: template.template_id,
        enabled: true
      },
      {
        integration_id: 'i_2',
        tenant_id: 't_1',
        provider: 'openai',
        name: 'Integration 2',
        template_id: template.template_id,
        enabled: true
      },
      {
        integration_id: 'i_disabled',
        tenant_id: 't_1',
        provider: 'openai',
        name: 'Integration disabled',
        template_id: template.template_id,
        enabled: false
      }
    ];
    const listLatestTemplatesByTenant = vi.fn(() => Promise.resolve([template]));

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 300,
      manifestTtlSeconds: 600,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            listByTenant: vi.fn(() => Promise.resolve(integrations))
          },
          templateRepository: {
            listLatestTemplatesByTenant
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const rules = await repository.listManifestTemplateRulesForTenantShared({
      tenantId: 't_1'
    });

    expect(listLatestTemplatesByTenant).toHaveBeenCalledTimes(2);
    expect(listLatestTemplatesByTenant).toHaveBeenCalledWith({tenant_id: 't_1'});
    expect(listLatestTemplatesByTenant).toHaveBeenCalledWith({tenant_id: 'global'});
    expect(rules).toHaveLength(2);
    expect(rules.map(rule => rule.integration_id)).toEqual(['i_1', 'i_2']);
  });

  it('returns no shared manifest rules when tenant has no enabled integrations', async () => {
    const listLatestTemplatesByTenant = vi.fn(() =>
      Promise.resolve([OpenApiTemplateSchema.parse(createRepositoryState().templates[0])])
    );

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 300,
      manifestTtlSeconds: 600,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            listByTenant: vi.fn(() =>
              Promise.resolve([
                {
                  integration_id: 'i_disabled',
                  tenant_id: 't_1',
                  provider: 'openai',
                  name: 'Disabled integration',
                  template_id: 'tpl_openai_safe',
                  enabled: false
                }
              ])
            )
          },
          templateRepository: {
            listLatestTemplatesByTenant
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const rules = await repository.listManifestTemplateRulesForTenantShared({
      tenantId: 't_1'
    });
    expect(rules).toEqual([]);
    expect(listLatestTemplatesByTenant).toHaveBeenCalledTimes(2);
    expect(listLatestTemplatesByTenant).toHaveBeenCalledWith({tenant_id: 't_1'});
    expect(listLatestTemplatesByTenant).toHaveBeenCalledWith({tenant_id: 'global'});
  });

  it('bootstraps shared manifest key metadata from local signing material when store is empty', async () => {
    const generated = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_bootstrap_test'
    });
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    const createdAtIso = '2026-02-01T00:00:00.000Z';
    const activeAtIso = '2026-02-01T00:01:00.000Z';

    const secretRepository = {
      createManifestSigningKeyRecord: vi.fn(() =>
        Promise.resolve({
          kid: generated.value.private_key.kid,
          alg: generated.value.private_key.alg,
          public_jwk: generated.value.public_key,
          private_key_ref: `state://manifest-signing-key/${generated.value.private_key.kid}`,
          status: 'retired' as const,
          created_at: createdAtIso,
          retired_at: createdAtIso
        })
      ),
      getActiveManifestSigningKeyRecord: vi
        .fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValue({
          kid: generated.value.private_key.kid,
          alg: generated.value.private_key.alg,
          public_jwk: generated.value.public_key,
          private_key_ref: `state://manifest-signing-key/${generated.value.private_key.kid}`,
          status: 'active' as const,
          created_at: createdAtIso,
          activated_at: activeAtIso
        }),
      setActiveManifestSigningKey: vi.fn(() =>
        Promise.resolve({
          kid: generated.value.private_key.kid,
          alg: generated.value.private_key.alg,
          public_jwk: generated.value.public_key,
          private_key_ref: `state://manifest-signing-key/${generated.value.private_key.kid}`,
          status: 'active' as const,
          created_at: createdAtIso,
          activated_at: activeAtIso
        })
      ),
      listManifestVerificationKeysWithEtag: vi.fn(() => Promise.resolve(null)),
      persistManifestKeysetMetadata: vi.fn(() => Promise.resolve(undefined)),
      getCryptoVerificationDefaultsByTenant: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      upsertCryptoVerificationDefaults: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      retireManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
      revokeManifestSigningKey: vi.fn(() => Promise.resolve(undefined))
    };

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: generated.value.private_key,
        manifest_keys: {keys: [generated.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          secretRepository
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const manifestSigningKey = await repository.getManifestSigningPrivateKeyShared();
    expect(manifestSigningKey.kid).toBe('manifest_bootstrap_test');
    expect(secretRepository.createManifestSigningKeyRecord).toHaveBeenCalledTimes(1);
    expect(secretRepository.setActiveManifestSigningKey).toHaveBeenCalledTimes(1);
    expect(secretRepository.persistManifestKeysetMetadata).toHaveBeenCalledTimes(1);
  });

  it('fails closed when shared active manifest key does not match local signing material', async () => {
    const localKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_local_key'
    });
    const remoteKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_remote_key'
    });
    expect(localKey.ok).toBe(true);
    expect(remoteKey.ok).toBe(true);
    if (!localKey.ok || !remoteKey.ok) {
      return;
    }

    const secretRepository = {
      getActiveManifestSigningKeyRecord: vi.fn(() =>
        Promise.resolve({
          kid: remoteKey.value.private_key.kid,
          alg: remoteKey.value.private_key.alg,
          public_jwk: remoteKey.value.public_key,
          private_key_ref: `state://manifest-signing-key/${remoteKey.value.private_key.kid}`,
          status: 'active' as const,
          created_at: '2026-02-01T00:00:00.000Z',
          activated_at: '2026-02-01T00:00:10.000Z'
        })
      ),
      listManifestVerificationKeysWithEtag: vi.fn(() =>
        Promise.resolve({
          manifest_keys: {keys: [remoteKey.value.public_key]},
          etag: 'W/"etag"',
          generated_at: '2026-02-01T00:00:00.000Z',
          max_age_seconds: 120
        })
      ),
      createManifestSigningKeyRecord: vi.fn(() => Promise.resolve(undefined)),
      setActiveManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
      persistManifestKeysetMetadata: vi.fn(() => Promise.resolve(undefined)),
      getCryptoVerificationDefaultsByTenant: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      upsertCryptoVerificationDefaults: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      retireManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
      revokeManifestSigningKey: vi.fn(() => Promise.resolve(undefined))
    };

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: localKey.value.private_key,
        manifest_keys: {keys: [localKey.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          secretRepository
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    await expect(repository.getManifestSigningPrivateKeyShared()).rejects.toThrow(
      'Manifest signing key mismatch between broker-api state'
    );
  });

  it('fails closed when shared active manifest key has matching kid but different public key material', async () => {
    const localKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_same_kid'
    });
    const remoteKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_same_kid'
    });
    expect(localKey.ok).toBe(true);
    expect(remoteKey.ok).toBe(true);
    if (!localKey.ok || !remoteKey.ok) {
      return;
    }

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: localKey.value.private_key,
        manifest_keys: {keys: [localKey.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          secretRepository: {
            getActiveManifestSigningKeyRecord: vi.fn(() =>
              Promise.resolve({
                kid: remoteKey.value.private_key.kid,
                alg: remoteKey.value.private_key.alg,
                public_jwk: remoteKey.value.public_key,
                private_key_ref: `state://manifest-signing-key/${remoteKey.value.private_key.kid}`,
                status: 'active' as const,
                created_at: '2026-02-01T00:00:00.000Z',
                activated_at: '2026-02-01T00:00:10.000Z'
              })
            ),
            listManifestVerificationKeysWithEtag: vi.fn(() =>
              Promise.resolve({
                manifest_keys: {keys: [remoteKey.value.public_key]},
                etag: 'W/"etag"',
                generated_at: '2026-02-01T00:00:00.000Z',
                max_age_seconds: 120
              })
            )
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    await expect(repository.getManifestSigningPrivateKeyShared()).rejects.toThrow(
      'Manifest signing public key mismatch for kid'
    );
  });

  it('fails bootstrap when tolerated rotation conflicts do not converge to local signing key', async () => {
    const localKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_bootstrap_conflict'
    });
    const conflictingKey = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_bootstrap_conflict'
    });
    expect(localKey.ok).toBe(true);
    expect(conflictingKey.ok).toBe(true);
    if (!localKey.ok || !conflictingKey.ok) {
      return;
    }

    const secretRepository = {
      getActiveManifestSigningKeyRecord: vi
        .fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValue({
          kid: conflictingKey.value.private_key.kid,
          alg: conflictingKey.value.private_key.alg,
          public_jwk: conflictingKey.value.public_key,
          private_key_ref: `state://manifest-signing-key/${conflictingKey.value.private_key.kid}`,
          status: 'active' as const,
          created_at: '2026-02-01T00:00:00.000Z',
          activated_at: '2026-02-01T00:00:10.000Z'
        }),
      createManifestSigningKeyRecord: vi.fn(() =>
        Promise.reject(Object.assign(new Error('key already exists'), {code: 'conflict'}))
      ),
      setActiveManifestSigningKey: vi.fn(() =>
        Promise.reject(Object.assign(new Error('invalid activation transition'), {code: 'state_transition_invalid'}))
      ),
      listManifestVerificationKeysWithEtag: vi.fn(() =>
        Promise.resolve({
          manifest_keys: {keys: [conflictingKey.value.public_key]},
          etag: 'W/"etag"',
          generated_at: '2026-02-01T00:00:00.000Z',
          max_age_seconds: 120
        })
      ),
      persistManifestKeysetMetadata: vi.fn(() => Promise.resolve(undefined)),
      getCryptoVerificationDefaultsByTenant: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      upsertCryptoVerificationDefaults: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      retireManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
      revokeManifestSigningKey: vi.fn(() => Promise.resolve(undefined))
    };

    await expect(
      DataPlaneRepository.create({
        initialState: {
          ...createRepositoryState(),
          manifest_signing_private_key: localKey.value.private_key,
          manifest_keys: {keys: [localKey.value.public_key]}
        },
        approvalTtlSeconds: 10,
        manifestTtlSeconds: 120,
        processInfrastructure: {
          enabled: true,
          prisma: {} as never,
          redis: null,
          dbRepositories: {
            secretRepository
          } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
          redisKeyPrefix: 'broker-api:test',
          withTransaction: async operation => operation({} as never),
          close: () => Promise.resolve()
        }
      })
    ).rejects.toThrow('Bootstrap manifest signing key metadata does not match local signing key material');
  });

  it('maps shared crypto storage repository failures and missing redis lock dependencies to fail-closed results', async () => {
    const generated = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_crypto_failures'
    });
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    const activeRecord = {
      kid: generated.value.private_key.kid,
      alg: generated.value.private_key.alg,
      public_jwk: generated.value.public_key,
      private_key_ref: `state://manifest-signing-key/${generated.value.private_key.kid}`,
      status: 'active' as const,
      created_at: '2026-02-01T00:00:00.000Z',
      activated_at: '2026-02-01T00:00:10.000Z'
    };

    const secretRepository = {
      createManifestSigningKeyRecord: vi.fn(() => Promise.resolve({...activeRecord, status: 'retired' as const})),
      getActiveManifestSigningKeyRecord: vi.fn(() => Promise.resolve(activeRecord)),
      setActiveManifestSigningKey: vi.fn(() => Promise.resolve(activeRecord)),
      listManifestVerificationKeysWithEtag: vi.fn(() =>
        Promise.resolve({
          manifest_keys: {keys: [generated.value.public_key]},
          etag: 'W/"etag_1"',
          generated_at: '2026-02-01T00:00:00.000Z',
          max_age_seconds: 120
        })
      ),
      persistManifestKeysetMetadata: vi.fn(() => Promise.resolve(undefined)),
      getCryptoVerificationDefaultsByTenant: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      upsertCryptoVerificationDefaults: vi.fn(() =>
        Promise.resolve({
          tenant_id: 't_1',
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      ),
      retireManifestSigningKey: vi.fn(() => Promise.resolve(undefined)),
      revokeManifestSigningKey: vi.fn(() => Promise.resolve(undefined))
    };

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: generated.value.private_key,
        manifest_keys: {keys: [generated.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          secretRepository
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const internals = repository as unknown as {
      cryptoStorageService: {
        createManifestSigningKeyRecord_INCOMPLETE: (input: {
          kid: string;
          alg: 'EdDSA' | 'ES256';
          public_jwk: unknown;
          private_key_ref: string;
          created_at: string;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        getActiveManifestSigningKeyRecord_INCOMPLETE: () => Promise<{ok: boolean; error?: {code: string}}>;
        setActiveManifestSigningKey_INCOMPLETE: (input: {
          kid: string;
          activated_at: string;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        retireManifestSigningKey_INCOMPLETE: (input: {
          kid: string;
          retired_at: string;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        revokeManifestSigningKey_INCOMPLETE: (input: {
          kid: string;
          revoked_at: string;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        listManifestVerificationKeysWithEtag_INCOMPLETE: () => Promise<{ok: boolean; error?: {code: string}}>;
        persistManifestKeysetMetadata_INCOMPLETE: (input: {
          etag: string;
          generated_at: string;
          max_age_seconds: number;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        getCryptoVerificationDefaultsByTenant_INCOMPLETE: (input: {
          tenant_id: string;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        upsertCryptoVerificationDefaults_INCOMPLETE: (input: {
          tenant_id: string;
          require_temporal_validity: boolean;
          max_clock_skew_seconds: number;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        acquireCryptoRotationLock_INCOMPLETE: (input: {
          lock_name: string;
          ttl_ms: number;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
        releaseCryptoRotationLock_INCOMPLETE: (input: {
          lock_name: string;
          token: string;
        }) => Promise<{ok: boolean; error?: {code: string}}>;
      } | null;
    };
    const storage = internals.cryptoStorageService;
    expect(storage).not.toBeNull();
    if (!storage) {
      return;
    }

    secretRepository.createManifestSigningKeyRecord.mockRejectedValueOnce({
      code: 'unique_violation',
      message: 'duplicate key'
    });
    const createFailure = await storage.createManifestSigningKeyRecord_INCOMPLETE({
      kid: 'manifest_x',
      alg: 'EdDSA',
      public_jwk: generated.value.public_key,
      private_key_ref: 'state://manifest-signing-key/manifest_x',
      created_at: '2026-02-01T00:00:00.000Z'
    });
    expect(createFailure.ok).toBe(false);
    expect(createFailure.error?.code).toBe('manifest_key_rotation_invalid');

    secretRepository.getActiveManifestSigningKeyRecord.mockRejectedValueOnce({
      code: 'not_found',
      message: 'missing active key'
    });
    const activeFailure = await storage.getActiveManifestSigningKeyRecord_INCOMPLETE();
    expect(activeFailure.ok).toBe(false);
    expect(activeFailure.error?.code).toBe('manifest_key_not_found');

    secretRepository.setActiveManifestSigningKey.mockRejectedValueOnce({
      code: 'state_transition_invalid',
      message: 'revoked key'
    });
    const activateFailure = await storage.setActiveManifestSigningKey_INCOMPLETE({
      kid: generated.value.private_key.kid,
      activated_at: '2026-02-01T00:00:00.000Z'
    });
    expect(activateFailure.ok).toBe(false);
    expect(activateFailure.error?.code).toBe('manifest_key_rotation_invalid');

    secretRepository.retireManifestSigningKey.mockRejectedValueOnce(new Error('retire failed'));
    const retireFailure = await storage.retireManifestSigningKey_INCOMPLETE({
      kid: generated.value.private_key.kid,
      retired_at: '2026-02-01T00:00:00.000Z'
    });
    expect(retireFailure.ok).toBe(false);
    expect(retireFailure.error?.code).toBe('invalid_input');

    secretRepository.revokeManifestSigningKey.mockRejectedValueOnce(new Error('revoke failed'));
    const revokeFailure = await storage.revokeManifestSigningKey_INCOMPLETE({
      kid: generated.value.private_key.kid,
      revoked_at: '2026-02-01T00:00:00.000Z'
    });
    expect(revokeFailure.ok).toBe(false);
    expect(revokeFailure.error?.code).toBe('invalid_input');

    secretRepository.listManifestVerificationKeysWithEtag.mockRejectedValueOnce(new Error('keyset failed'));
    const keysetFailure = await storage.listManifestVerificationKeysWithEtag_INCOMPLETE();
    expect(keysetFailure.ok).toBe(false);
    expect(keysetFailure.error?.code).toBe('invalid_input');

    secretRepository.persistManifestKeysetMetadata.mockRejectedValueOnce(new Error('persist failed'));
    const persistFailure = await storage.persistManifestKeysetMetadata_INCOMPLETE({
      etag: 'W/"etag_2"',
      generated_at: '2026-02-01T00:00:00.000Z',
      max_age_seconds: 120
    });
    expect(persistFailure.ok).toBe(false);
    expect(persistFailure.error?.code).toBe('invalid_input');

    secretRepository.getCryptoVerificationDefaultsByTenant.mockRejectedValueOnce(new Error('defaults failed'));
    const defaultsFailure = await storage.getCryptoVerificationDefaultsByTenant_INCOMPLETE({
      tenant_id: 't_1'
    });
    expect(defaultsFailure.ok).toBe(false);
    expect(defaultsFailure.error?.code).toBe('invalid_input');

    secretRepository.upsertCryptoVerificationDefaults.mockRejectedValueOnce(new Error('upsert defaults failed'));
    const upsertDefaultsFailure = await storage.upsertCryptoVerificationDefaults_INCOMPLETE({
      tenant_id: 't_1',
      require_temporal_validity: true,
      max_clock_skew_seconds: 0
    });
    expect(upsertDefaultsFailure.ok).toBe(false);
    expect(upsertDefaultsFailure.error?.code).toBe('invalid_input');

    const acquireWithoutRedis = await storage.acquireCryptoRotationLock_INCOMPLETE({
      lock_name: 'manifest-rotation',
      ttl_ms: 10_000
    });
    expect(acquireWithoutRedis.ok).toBe(false);
    expect(acquireWithoutRedis.error?.code).toBe('invalid_input');

    const releaseWithoutRedis = await storage.releaseCryptoRotationLock_INCOMPLETE({
      lock_name: 'manifest-rotation',
      token: 'f73918ce-2fca-4b57-8cfc-f4fe37e2f9b4'
    });
    expect(releaseWithoutRedis.ok).toBe(false);
    expect(releaseWithoutRedis.error?.code).toBe('invalid_input');
  });

  it('uses redis-backed crypto rotation lock adapter when redis is available', async () => {
    const generated = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_crypto_lock'
    });
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    const activeRecord = {
      kid: generated.value.private_key.kid,
      alg: generated.value.private_key.alg,
      public_jwk: generated.value.public_key,
      private_key_ref: `state://manifest-signing-key/${generated.value.private_key.kid}`,
      status: 'active' as const,
      created_at: '2026-02-01T00:00:00.000Z',
      activated_at: '2026-02-01T00:00:10.000Z'
    };

    const redisSet = vi.fn(() => Promise.resolve('OK'));
    const redisEval = vi.fn(() => Promise.resolve(1));

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: generated.value.private_key,
        manifest_keys: {keys: [generated.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          set: redisSet,
          eval: redisEval
        } as never,
        dbRepositories: {
          secretRepository: {
            getActiveManifestSigningKeyRecord: vi.fn(() => Promise.resolve(activeRecord)),
            listManifestVerificationKeysWithEtag: vi.fn(() =>
              Promise.resolve({
                manifest_keys: {keys: [generated.value.public_key]},
                etag: 'W/"etag_1"',
                generated_at: '2026-02-01T00:00:00.000Z',
                max_age_seconds: 120
              })
            )
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const storage = (
      repository as unknown as {
        cryptoStorageService: {
          acquireCryptoRotationLock_INCOMPLETE: (input: {
            lock_name: string;
            ttl_ms: number;
          }) => Promise<{ok: boolean; value?: {token: string}}>;
          releaseCryptoRotationLock_INCOMPLETE: (input: {
            lock_name: string;
            token: string;
          }) => Promise<{ok: boolean; value?: {released: boolean}}>;
        } | null;
      }
    ).cryptoStorageService;
    expect(storage).not.toBeNull();
    if (!storage) {
      return;
    }

    const lock = await storage.acquireCryptoRotationLock_INCOMPLETE({
      lock_name: 'manifest-rotation',
      ttl_ms: 30_000
    });
    expect(lock.ok).toBe(true);
    if (!lock.ok) {
      return;
    }
    expect(redisSet).toHaveBeenCalled();

    const release = await storage.releaseCryptoRotationLock_INCOMPLETE({
      lock_name: 'manifest-rotation',
      token: lock.value?.token ?? ''
    });
    expect(release.ok).toBe(true);
    expect(release.value?.released).toBe(true);
    expect(redisEval).toHaveBeenCalled();
  });

  it('throws when shared manifest keyset lookup returns a hard failure', async () => {
    const generated = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_keyset_failure'
    });
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: generated.value.private_key,
        manifest_keys: {keys: [generated.value.public_key]}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          secretRepository: {
            getActiveManifestSigningKeyRecord: vi.fn(() =>
              Promise.resolve({
                kid: generated.value.private_key.kid,
                alg: generated.value.private_key.alg,
                public_jwk: generated.value.public_key,
                private_key_ref: `state://manifest-signing-key/${generated.value.private_key.kid}`,
                status: 'active' as const,
                created_at: '2026-02-01T00:00:00.000Z',
                activated_at: '2026-02-01T00:00:10.000Z'
              })
            ),
            listManifestVerificationKeysWithEtag: vi.fn(() =>
              Promise.resolve({
                manifest_keys: {keys: [generated.value.public_key]},
                etag: 'W/"etag_1"',
                generated_at: '2026-02-01T00:00:00.000Z',
                max_age_seconds: 120
              })
            )
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const secretRepository = (
      (repository as unknown as {processInfrastructure?: ProcessInfrastructure}).processInfrastructure
        ?.dbRepositories as
        | {secretRepository?: {listManifestVerificationKeysWithEtag?: ReturnType<typeof vi.fn>}}
        | undefined
    )?.secretRepository;
    secretRepository?.listManifestVerificationKeysWithEtag?.mockRejectedValueOnce(new Error('downstream unavailable'));

    await expect(repository.getManifestVerificationKeysShared()).rejects.toThrow(
      'Unable to load manifest verification keys'
    );
  });

  it('returns shared manifest verification keys when store lookup succeeds', async () => {
    const generated = await generateManifestSigningKeyPair({
      alg: 'EdDSA',
      kid: 'manifest_keyset_success'
    });
    expect(generated.ok).toBe(true);
    if (!generated.ok) {
      return;
    }

    const repository = await DataPlaneRepository.create({
      initialState: {
        ...createRepositoryState(),
        manifest_signing_private_key: generated.value.private_key,
        manifest_keys: {keys: []}
      },
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          secretRepository: {
            getActiveManifestSigningKeyRecord: vi.fn(() =>
              Promise.resolve({
                kid: generated.value.private_key.kid,
                alg: generated.value.private_key.alg,
                public_jwk: generated.value.public_key,
                private_key_ref: `state://manifest-signing-key/${generated.value.private_key.kid}`,
                status: 'active' as const,
                created_at: '2026-02-01T00:00:00.000Z',
                activated_at: '2026-02-01T00:00:10.000Z'
              })
            ),
            listManifestVerificationKeysWithEtag: vi.fn(() =>
              Promise.resolve({
                manifest_keys: {keys: [generated.value.public_key]},
                etag: 'W/"etag_success"',
                generated_at: '2026-02-01T00:00:00.000Z',
                max_age_seconds: 120
              })
            )
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const keys = await repository.getManifestVerificationKeysShared();
    expect(keys.keys).toHaveLength(1);
    expect(keys.keys[0]?.kid).toBe('manifest_keyset_success');
  });

  it('wires SSRF storage bridge cache/rebinding/projection and template invalidation signals', async () => {
    const redisStrings = new Map<string, string>();
    const redisLists = new Map<string, string[]>();
    const redisSet = vi.fn((key: string, value: string) => {
      redisStrings.set(key, value);
      return Promise.resolve('OK');
    });
    const redisGet = vi.fn((key: string) => Promise.resolve(redisStrings.get(key) ?? null));
    const redisRPush = vi.fn((key: string, value: string) => {
      const list = redisLists.get(key) ?? [];
      list.push(value);
      redisLists.set(key, list);
      return Promise.resolve(list.length);
    });
    const redisLTrim = vi.fn((key: string, start: number, end: number) => {
      const list = redisLists.get(key) ?? [];
      const normalizedStart = start < 0 ? Math.max(0, list.length + start) : Math.max(0, start);
      const normalizedEnd = end < 0 ? list.length + end : end;
      redisLists.set(key, list.slice(normalizedStart, normalizedEnd + 1));
      return Promise.resolve('OK');
    });
    const redisPublish = vi.fn(() => Promise.resolve(1));

    const templateFromExecuteLookup = OpenApiTemplateSchema.parse({
      template_id: 'tpl_openai_safe',
      version: 2,
      provider: 'openai',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['api.openai.com'],
      redirect_policy: {mode: 'deny'},
      path_groups: [
        {
          group_id: 'openai_responses',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['POST'],
          path_patterns: ['^/v1/responses$'],
          query_allowlist: [],
          header_forward_allowlist: ['content-type'],
          body_policy: {
            max_bytes: 8192,
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

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          set: redisSet,
          get: redisGet,
          rPush: redisRPush,
          lTrim: redisLTrim,
          publish: redisPublish
        } as never,
        dbRepositories: {
          integrationRepository: {
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: templateFromExecuteLookup,
                template_id: templateFromExecuteLookup.template_id,
                template_version: templateFromExecuteLookup.version
              })
            )
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const scope = {
      tenant_id: 't_1',
      workload_id: 'w_1',
      integration_id: 'i_1'
    };

    const loadedTemplate = await repository.loadSsrfActiveTemplateForExecuteShared({
      scope
    });
    expect(loadedTemplate?.template_id).toBe('tpl_openai_safe');

    const cacheWriteAt = new Date('2026-02-01T00:00:00.000Z');
    await repository.writeSsrfDnsResolutionCacheShared({
      normalizedHost: 'api.openai.com',
      resolvedIps: ['198.51.100.10'],
      now: cacheWriteAt,
      ttlSeconds: 60
    });

    const cacheHit = await repository.readSsrfDnsResolutionCacheShared({
      normalizedHost: 'api.openai.com',
      now: new Date('2026-02-01T00:00:10.000Z')
    });
    expect(cacheHit?.resolved_ips).toEqual(['198.51.100.10']);

    const cacheExpired = await repository.readSsrfDnsResolutionCacheShared({
      normalizedHost: 'api.openai.com',
      now: new Date('2026-02-01T00:01:10.000Z')
    });
    expect(cacheExpired).toBeNull();

    await repository.appendSsrfDnsRebindingObservationShared({
      normalizedHost: 'api.openai.com',
      resolvedIps: ['198.51.100.11', '198.51.100.10'],
      now: new Date('2026-02-01T00:00:20.000Z')
    });

    await repository.appendSsrfDecisionProjectionShared({
      projection: {
        event_id: 'ssrf_evt_1',
        timestamp: '2026-02-01T00:00:30.000Z',
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'i_1',
        template_id: 'tpl_openai_safe',
        template_version: 2,
        destination_host: 'api.openai.com',
        destination_port: 443,
        resolved_ips: ['198.51.100.10'],
        decision: 'denied',
        reason_code: 'resolved_ip_denied_private_range',
        correlation_id: 'corr_ssrf_1'
      }
    });

    const firstTemplateBinding = await repository.syncSsrfTemplateBindingShared({
      scope,
      template: templateFromExecuteLookup,
      now: new Date('2026-02-01T00:00:40.000Z')
    });
    expect(firstTemplateBinding).toBe(false);
    const secondTemplateBinding = await repository.syncSsrfTemplateBindingShared({
      scope,
      template: {
        ...templateFromExecuteLookup,
        version: 3
      },
      now: new Date('2026-02-01T00:00:50.000Z')
    });
    expect(secondTemplateBinding).toBe(true);
    expect(redisPublish).toHaveBeenCalledTimes(1);
    expect(redisRPush).toHaveBeenCalled();
  });

  it('uses db-native SSRF projection and invalidation outbox hooks when available', async () => {
    const appendSsrfGuardDecisionProjection = vi.fn((input: {projection: unknown}) =>
      Promise.resolve(input.projection)
    );
    const persistTemplateInvalidationOutbox = vi.fn(() => Promise.resolve());
    const redisPublish = vi.fn(() => Promise.resolve(1));
    const templateFromExecuteLookup = OpenApiTemplateSchema.parse({
      template_id: 'tpl_openai_safe',
      version: 2,
      provider: 'openai',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['api.openai.com'],
      redirect_policy: {mode: 'deny'},
      path_groups: [
        {
          group_id: 'openai_responses',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['POST'],
          path_patterns: ['^/v1/responses$'],
          query_allowlist: [],
          header_forward_allowlist: ['content-type'],
          body_policy: {
            max_bytes: 8192,
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

    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: {
          publish: redisPublish,
          set: vi.fn(() => Promise.resolve('OK')),
          get: vi.fn(() => Promise.resolve(null)),
          del: vi.fn(() => Promise.resolve(0))
        } as never,
        dbRepositories: {
          integrationRepository: {
            getIntegrationTemplateForExecute: vi.fn(() =>
              Promise.resolve({
                workload_enabled: true,
                integration_enabled: true,
                executable: true,
                execution_status: 'executable',
                template: templateFromExecuteLookup,
                template_id: templateFromExecuteLookup.template_id,
                template_version: templateFromExecuteLookup.version
              })
            )
          },
          auditEventRepository: {
            appendSsrfGuardDecisionProjection
          },
          templateRepository: {
            persistTemplateInvalidationOutbox
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    await repository.appendSsrfDecisionProjectionShared({
      projection: {
        event_id: 'ssrf_evt_db_1',
        timestamp: '2026-02-01T00:00:30.000Z',
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'i_1',
        template_id: 'tpl_openai_safe',
        template_version: 2,
        destination_host: 'api.openai.com',
        destination_port: 443,
        resolved_ips: ['198.51.100.10'],
        decision: 'allowed',
        reason_code: 'dns_resolution_required',
        correlation_id: 'corr_ssrf_db_1'
      }
    });
    expect(appendSsrfGuardDecisionProjection).toHaveBeenCalledTimes(1);

    const scope = {
      tenant_id: 't_1',
      workload_id: 'w_1',
      integration_id: 'i_1'
    };
    await repository.syncSsrfTemplateBindingShared({
      scope,
      template: templateFromExecuteLookup,
      now: new Date('2026-02-01T00:00:40.000Z')
    });
    const changedBinding = await repository.syncSsrfTemplateBindingShared({
      scope,
      template: {
        ...templateFromExecuteLookup,
        version: 3
      },
      now: new Date('2026-02-01T00:00:50.000Z')
    });

    expect(changedBinding).toBe(true);
    expect(persistTemplateInvalidationOutbox).toHaveBeenCalledTimes(1);
    expect(redisPublish).toHaveBeenCalledTimes(1);
  });

  it('maps shared SSRF template lookup not_found errors to null instead of throwing', async () => {
    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120,
      processInfrastructure: {
        enabled: true,
        prisma: {} as never,
        redis: null,
        dbRepositories: {
          integrationRepository: {
            getIntegrationTemplateForExecute: vi.fn(() => {
              const error = new Error('not found');
              Object.assign(error, {code: 'not_found'});
              return Promise.reject(error);
            })
          }
        } as unknown as NonNullable<ProcessInfrastructure['dbRepositories']>,
        redisKeyPrefix: 'broker-api:test',
        withTransaction: async operation => operation({} as never),
        close: () => Promise.resolve()
      }
    });

    const template = await repository.loadSsrfActiveTemplateForExecuteShared({
      scope: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'i_1'
      }
    });

    expect(template).toBeNull();
  });

  it('fails transaction access when shared infrastructure is disabled', async () => {
    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 10,
      manifestTtlSeconds: 120
    });

    await expect(repository.withSharedTransaction(() => Promise.resolve('never'))).rejects.toThrow(
      'Shared transaction requested while infrastructure is disabled'
    );
  });
});
