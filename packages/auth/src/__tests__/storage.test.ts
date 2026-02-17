import {describe, expect, it, vi} from 'vitest';

import {
  AuthStorageIntegrationError,
  consumeEnrollmentTokenRecordByHash,
  createAuthStorageScope,
  createDpopReplayJtiStore,
  getSessionRecordByTokenHash,
  issueEnrollmentTokenRecord,
  loadWorkloadRecordBySanUri,
  persistSessionRecord
} from '../storage';
import type {
  AuthEnrollmentTokenStoreAdapter,
  AuthPostgresClient,
  AuthReplayStoreAdapter,
  AuthRedisClient,
  AuthSessionStoreAdapter,
  AuthStorageClients,
  AuthWorkloadStoreAdapter,
  AuthTransactionClient
} from '../storage';
import type {EnrollmentTokenRecord, SessionRecord, WorkloadRecord} from '../types';

const createSessionRecord = (): SessionRecord => ({
  sessionId: '6c6cfce4-df4f-4cae-a58e-0414403bbd20',
  workloadId: 'workload-1',
  tenantId: 'tenant-1',
  certFingerprint256: 'AA:BB',
  tokenHash: 'a'.repeat(64),
  expiresAt: new Date('2030-01-01T00:00:00.000Z').toISOString()
});

const createEnrollmentRecord = (): EnrollmentTokenRecord => ({
  tokenHash: 'b'.repeat(64),
  workloadId: 'workload-1',
  expiresAt: new Date('2030-01-01T00:00:00.000Z').toISOString()
});

const createWorkloadRecord = (): WorkloadRecord => ({
  workloadId: 'workload-1',
  tenantId: 'tenant-1',
  enabled: true,
  ipAllowlist: []
});

const createRedisClient = (): AuthRedisClient => ({
  get: vi.fn(),
  set: vi.fn(),
  del: vi.fn()
});

const createPostgresClient = (): AuthPostgresClient => ({workload: {}});

const createStorageClients = ({
  includeRedis = true,
  includePostgres = true
}: {
  includeRedis?: boolean;
  includePostgres?: boolean;
} = {}): AuthStorageClients => ({
  ...(includeRedis ? {redis: createRedisClient()} : {}),
  ...(includePostgres ? {postgres: createPostgresClient()} : {})
});

describe('storage', () => {
  it('delegates session persistence and lookup to injected session store adapter', async () => {
    const session = createSessionRecord();
    const clients = createStorageClients();
    const redisClient = clients.redis!;
    const transactionClient: AuthTransactionClient = {tx: true};

    const sessionStore: AuthSessionStoreAdapter = {
      upsertSession: vi.fn(() => undefined),
      getSessionByTokenHash: vi.fn(() => session),
      revokeSessionById: vi.fn(() => undefined)
    };

    await persistSessionRecord({
      sessionStore,
      clients,
      transactionClient,
      session
    });
    expect(sessionStore.upsertSession).toHaveBeenCalledTimes(1);
    expect(sessionStore.upsertSession).toHaveBeenCalledWith({
      session,
      redisClient,
      transactionClient
    });

    const found = await getSessionRecordByTokenHash({
      sessionStore,
      clients,
      transactionClient,
      tokenHash: session.tokenHash
    });
    expect(found).toEqual(session);
    expect(sessionStore.getSessionByTokenHash).toHaveBeenCalledWith({
      tokenHash: session.tokenHash,
      redisClient,
      transactionClient
    });
  });

  it('delegates enrollment persistence and consume calls to injected store adapter', async () => {
    const record = createEnrollmentRecord();
    const clients = createStorageClients();
    const redisClient = clients.redis!;
    const transactionClient: AuthTransactionClient = {tx: true};

    const enrollmentTokenStore: AuthEnrollmentTokenStoreAdapter = {
      issueEnrollmentToken: vi.fn(() => undefined),
      consumeEnrollmentTokenByHash: vi.fn(() => record)
    };

    await issueEnrollmentTokenRecord({
      enrollmentTokenStore,
      clients,
      transactionClient,
      record
    });
    expect(enrollmentTokenStore.issueEnrollmentToken).toHaveBeenCalledWith({
      record,
      redisClient,
      transactionClient
    });

    const consumed = await consumeEnrollmentTokenRecordByHash({
      enrollmentTokenStore,
      clients,
      transactionClient,
      tokenHash: record.tokenHash
    });
    expect(consumed).toEqual(record);
    expect(enrollmentTokenStore.consumeEnrollmentTokenByHash).toHaveBeenCalledWith({
      tokenHash: record.tokenHash,
      redisClient,
      transactionClient
    });
  });

  it('delegates workload lookup to injected workload store and supports transaction override', async () => {
    const workload = createWorkloadRecord();
    const sanUri = 'spiffe://tenant-1/worker';
    const workloadStore: AuthWorkloadStoreAdapter = {
      getWorkloadBySanUri: vi.fn(() => workload)
    };

    const transactionClient: AuthTransactionClient = {workload: {findUnique: vi.fn()}};
    const byTransaction = await loadWorkloadRecordBySanUri({
      workloadStore,
      clients: createStorageClients({includePostgres: false}),
      transactionClient,
      sanUri
    });
    expect(byTransaction).toEqual(workload);
    expect(workloadStore.getWorkloadBySanUri).toHaveBeenCalledWith({
      sanUri,
      postgresClient: transactionClient,
      transactionClient
    });

    const clients = createStorageClients({includePostgres: true});
    const postgresClient = clients.postgres!;
    await loadWorkloadRecordBySanUri({
      workloadStore,
      clients,
      sanUri
    });
    expect(workloadStore.getWorkloadBySanUri).toHaveBeenLastCalledWith({
      sanUri,
      postgresClient,
      transactionClient: undefined
    });
  });

  it('creates JtiStore delegating replay reservations to injected replay adapter', async () => {
    let capturedReplayInput: Parameters<AuthReplayStoreAdapter['reserveDpopJti']>[0] | undefined;
    const reserveDpopJti = vi.fn((input: Parameters<AuthReplayStoreAdapter['reserveDpopJti']>[0]) => {
      capturedReplayInput = input;
      return true;
    });
    const replayStore: AuthReplayStoreAdapter = {reserveDpopJti};
    const clients = createStorageClients();
    const redisClient = clients.redis!;

    const store = createDpopReplayJtiStore({
      replayStore,
      clients
    });

    const accepted = await store.checkAndStore('tenant-1:session-1:jti-1', new Date('2030-01-01T00:00:00.000Z'));
    expect(accepted).toBe(true);
    expect(capturedReplayInput).toEqual({
      replayScope: 'tenant-1:session-1',
      jti: 'jti-1',
      expiresAt: new Date('2030-01-01T00:00:00.000Z'),
      redisClient,
      transactionClient: undefined
    });
  });

  it('hashes replay keys when they cannot be represented as replayScope+jti limits', async () => {
    let capturedReplayInput: Parameters<AuthReplayStoreAdapter['reserveDpopJti']>[0] | undefined;
    const reserveDpopJti = vi.fn((input: Parameters<AuthReplayStoreAdapter['reserveDpopJti']>[0]) => {
      capturedReplayInput = input;
      return true;
    });
    const replayStore: AuthReplayStoreAdapter = {reserveDpopJti};
    const store = createDpopReplayJtiStore({
      replayStore,
      clients: createStorageClients()
    });

    const rawReplayKey = 'x'.repeat(700);
    const accepted = await store.checkAndStore(rawReplayKey, new Date('2030-01-01T00:00:00.000Z'));
    expect(accepted).toBe(true);
    expect(capturedReplayInput?.replayScope).toBe('auth');
    expect(capturedReplayInput?.jti).toMatch(/^[a-f0-9]{64}$/u);
  });

  it('throws dependency errors for missing repositories or clients in scope', () => {
    const scope = createAuthStorageScope({});
    expect(() =>
      scope.persistSessionRecord({
        session: createSessionRecord()
      })
    ).toThrowError(new AuthStorageIntegrationError('auth_session_store_dependency_missing'));

    const scopeMissingClients = createAuthStorageScope({
      repositories: {
        sessionStore: {
          upsertSession: vi.fn(),
          getSessionByTokenHash: vi.fn(),
          revokeSessionById: vi.fn()
        }
      }
    });
    expect(() =>
      scopeMissingClients.getSessionRecordByTokenHash({
        tokenHash: 'a'.repeat(64)
      })
    ).toThrowError(new AuthStorageIntegrationError('auth_storage_clients_dependency_missing'));
  });

  it('delegates through scope with default and per-call transaction client overrides', async () => {
    let capturedUpsertInput: Parameters<AuthSessionStoreAdapter['upsertSession']>[0] | undefined;
    const sessionStore: AuthSessionStoreAdapter = {
      upsertSession: vi.fn((input: Parameters<AuthSessionStoreAdapter['upsertSession']>[0]) => {
        capturedUpsertInput = input;
        return undefined;
      }),
      getSessionByTokenHash: vi.fn(() => null),
      revokeSessionById: vi.fn(() => undefined)
    };
    const workloadStore: AuthWorkloadStoreAdapter = {
      getWorkloadBySanUri: vi.fn(() => null)
    };

    const defaultTransactionClient: AuthTransactionClient = {tx: 'default'};
    const overrideTransactionClient: AuthTransactionClient = {tx: 'override'};

    const scope = createAuthStorageScope({
      clients: createStorageClients(),
      repositories: {
        sessionStore,
        workloadStore
      },
      transactionClient: defaultTransactionClient
    });

    const session = createSessionRecord();
    await scope.persistSessionRecord({session});
    expect(capturedUpsertInput?.session).toEqual(session);
    expect(capturedUpsertInput?.redisClient).toBeDefined();
    expect(capturedUpsertInput?.transactionClient).toEqual(defaultTransactionClient);

    await scope.loadWorkloadRecordBySanUri({
      sanUri: 'spiffe://tenant-1/worker',
      transactionClient: overrideTransactionClient
    });
    expect(workloadStore.getWorkloadBySanUri).toHaveBeenCalledWith({
      sanUri: 'spiffe://tenant-1/worker',
      postgresClient: overrideTransactionClient,
      transactionClient: overrideTransactionClient
    });
  });
});
