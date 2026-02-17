import crypto from 'crypto';

import type {EnrollmentTokenRecord, JtiStore, SessionRecord, WorkloadRecord} from './types';

export class AuthStorageIntegrationError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.name = 'AuthStorageIntegrationError';
    this.code = code;
  }
}

export type AuthPostgresClient = {
  [key: string]: unknown;
};

export type AuthTransactionClient = AuthPostgresClient;

export type AuthRedisClient = {
  get: (...args: unknown[]) => unknown;
  set: (...args: unknown[]) => unknown;
  del: (...args: unknown[]) => unknown;
};

export type AuthStorageClients = {
  redis?: AuthRedisClient;
  postgres?: AuthPostgresClient;
};

export type AuthSessionStoreAdapter = {
  upsertSession: (input: {
    session: SessionRecord;
    redisClient: AuthRedisClient;
    transactionClient?: AuthTransactionClient;
  }) => Promise<void> | void;
  getSessionByTokenHash: (input: {
    tokenHash: string;
    redisClient: AuthRedisClient;
    transactionClient?: AuthTransactionClient;
  }) => Promise<SessionRecord | null> | SessionRecord | null;
  revokeSessionById: (input: {
    sessionId: string;
    redisClient: AuthRedisClient;
    transactionClient?: AuthTransactionClient;
  }) => Promise<void> | void;
};

export type AuthEnrollmentTokenStoreAdapter = {
  issueEnrollmentToken: (input: {
    record: EnrollmentTokenRecord;
    redisClient: AuthRedisClient;
    transactionClient?: AuthTransactionClient;
  }) => Promise<void> | void;
  consumeEnrollmentTokenByHash: (input: {
    tokenHash: string;
    redisClient: AuthRedisClient;
    transactionClient?: AuthTransactionClient;
  }) => Promise<EnrollmentTokenRecord | null> | EnrollmentTokenRecord | null;
};

export type AuthWorkloadStoreAdapter = {
  getWorkloadBySanUri: (input: {
    sanUri: string;
    postgresClient: AuthPostgresClient;
    transactionClient?: AuthTransactionClient;
  }) => Promise<WorkloadRecord | null> | WorkloadRecord | null;
};

export type AuthReplayStoreAdapter = {
  reserveDpopJti: (input: {
    replayScope: string;
    jti: string;
    expiresAt: Date;
    redisClient: AuthRedisClient;
    transactionClient?: AuthTransactionClient;
  }) => Promise<boolean> | boolean;
};

export type AuthStorageRepositories = {
  sessionStore?: AuthSessionStoreAdapter;
  enrollmentTokenStore?: AuthEnrollmentTokenStoreAdapter;
  workloadStore?: AuthWorkloadStoreAdapter;
  replayStore?: AuthReplayStoreAdapter;
};

export type AuthStorageDependencies = {
  clients?: AuthStorageClients;
  repositories?: AuthStorageRepositories;
  transactionClient?: AuthTransactionClient;
  // Backward compatibility while callers migrate to `repositories`.
  sessionStore?: AuthSessionStoreAdapter;
  enrollmentTokenStore?: AuthEnrollmentTokenStoreAdapter;
  workloadStore?: AuthWorkloadStoreAdapter;
  replayStore?: AuthReplayStoreAdapter;
};

export type AuthStorageScope = {
  persistSessionRecord: (input: {
    session: SessionRecord;
    transactionClient?: AuthTransactionClient;
  }) => Promise<void> | void;
  getSessionRecordByTokenHash: (input: {
    tokenHash: string;
    transactionClient?: AuthTransactionClient;
  }) => Promise<SessionRecord | null> | SessionRecord | null;
  issueEnrollmentTokenRecord: (input: {
    record: EnrollmentTokenRecord;
    transactionClient?: AuthTransactionClient;
  }) => Promise<void> | void;
  consumeEnrollmentTokenRecordByHash: (input: {
    tokenHash: string;
    transactionClient?: AuthTransactionClient;
  }) => Promise<EnrollmentTokenRecord | null> | EnrollmentTokenRecord | null;
  loadWorkloadRecordBySanUri: (input: {
    sanUri: string;
    transactionClient?: AuthTransactionClient;
  }) => Promise<WorkloadRecord | null> | WorkloadRecord | null;
  createDpopReplayJtiStore: (input?: {
    transactionClient?: AuthTransactionClient;
  }) => JtiStore;
};

const requireDependency = <T>(dependency: T | undefined, code: string): T => {
  if (!dependency) {
    throw new AuthStorageIntegrationError(code);
  }

  return dependency;
};

const requireRedisClient = (
  clients: AuthStorageClients
): AuthRedisClient =>
  requireDependency(clients.redis, 'auth_redis_client_dependency_missing');

const resolvePostgresClient = ({
  clients,
  transactionClient
}: {
  clients: AuthStorageClients;
  transactionClient?: AuthTransactionClient;
}): AuthPostgresClient => {
  if (transactionClient) {
    return transactionClient;
  }

  return requireDependency(clients.postgres, 'auth_postgres_client_dependency_missing');
};

const resolveScopedRepositories = (
  dependencies: AuthStorageDependencies
): AuthStorageRepositories => ({
  sessionStore: dependencies.repositories?.sessionStore ?? dependencies.sessionStore,
  enrollmentTokenStore: dependencies.repositories?.enrollmentTokenStore ?? dependencies.enrollmentTokenStore,
  workloadStore: dependencies.repositories?.workloadStore ?? dependencies.workloadStore,
  replayStore: dependencies.repositories?.replayStore ?? dependencies.replayStore
});

const resolveScopedTransactionClient = ({
  callTransactionClient,
  scopeTransactionClient
}: {
  callTransactionClient?: AuthTransactionClient;
  scopeTransactionClient?: AuthTransactionClient;
}) => callTransactionClient ?? scopeTransactionClient;

const sha256Hex = (value: string) => crypto.createHash('sha256').update(value, 'utf8').digest('hex');

const buildReplayReservationInput = (replayKey: string): {replayScope: string; jti: string} => {
  const separatorIndex = replayKey.lastIndexOf(':');
  if (separatorIndex > 0 && separatorIndex < replayKey.length - 1) {
    const replayScope = replayKey.slice(0, separatorIndex);
    const jti = replayKey.slice(separatorIndex + 1);

    if (replayScope.length <= 256 && jti.length <= 512) {
      return {replayScope, jti};
    }
  }

  // Keep replay guarantees when caller-provided key shape exceeds adapter limits.
  return {
    replayScope: 'auth',
    jti: sha256Hex(replayKey)
  };
};

export const persistSessionRecord = ({
  sessionStore,
  clients,
  transactionClient,
  session
}: {
  sessionStore: AuthSessionStoreAdapter;
  clients: AuthStorageClients;
  transactionClient?: AuthTransactionClient;
  session: SessionRecord;
}) => {
  const redisClient = requireRedisClient(clients);
  return sessionStore.upsertSession({
    session,
    redisClient,
    transactionClient
  });
};

export const getSessionRecordByTokenHash = ({
  sessionStore,
  clients,
  transactionClient,
  tokenHash
}: {
  sessionStore: AuthSessionStoreAdapter;
  clients: AuthStorageClients;
  transactionClient?: AuthTransactionClient;
  tokenHash: string;
}) => {
  const redisClient = requireRedisClient(clients);
  return sessionStore.getSessionByTokenHash({
    tokenHash,
    redisClient,
    transactionClient
  });
};

export const issueEnrollmentTokenRecord = ({
  enrollmentTokenStore,
  clients,
  transactionClient,
  record
}: {
  enrollmentTokenStore: AuthEnrollmentTokenStoreAdapter;
  clients: AuthStorageClients;
  transactionClient?: AuthTransactionClient;
  record: EnrollmentTokenRecord;
}) => {
  const redisClient = requireRedisClient(clients);
  return enrollmentTokenStore.issueEnrollmentToken({
    record,
    redisClient,
    transactionClient
  });
};

export const consumeEnrollmentTokenRecordByHash = ({
  enrollmentTokenStore,
  clients,
  transactionClient,
  tokenHash
}: {
  enrollmentTokenStore: AuthEnrollmentTokenStoreAdapter;
  clients: AuthStorageClients;
  transactionClient?: AuthTransactionClient;
  tokenHash: string;
}) => {
  const redisClient = requireRedisClient(clients);
  return enrollmentTokenStore.consumeEnrollmentTokenByHash({
    tokenHash,
    redisClient,
    transactionClient
  });
};

export const loadWorkloadRecordBySanUri = ({
  workloadStore,
  clients,
  transactionClient,
  sanUri
}: {
  workloadStore: AuthWorkloadStoreAdapter;
  clients: AuthStorageClients;
  transactionClient?: AuthTransactionClient;
  sanUri: string;
}) => {
  const postgresClient = resolvePostgresClient({clients, transactionClient});
  return workloadStore.getWorkloadBySanUri({
    sanUri,
    postgresClient,
    transactionClient
  });
};

export const createDpopReplayJtiStore = ({
  replayStore,
  clients,
  transactionClient
}: {
  replayStore: AuthReplayStoreAdapter;
  clients: AuthStorageClients;
  transactionClient?: AuthTransactionClient;
}): JtiStore => ({
  checkAndStore: (jti, expiresAt) => {
    const redisClient = requireRedisClient(clients);
    const replayInput = buildReplayReservationInput(jti);

    return replayStore.reserveDpopJti({
      replayScope: replayInput.replayScope,
      jti: replayInput.jti,
      expiresAt,
      redisClient,
      transactionClient
    });
  }
});

export const createAuthStorageScope = (
  dependencies: AuthStorageDependencies
): AuthStorageScope => {
  const requireScopedClients = (): AuthStorageClients =>
    requireDependency(dependencies.clients, 'auth_storage_clients_dependency_missing');
  const repositories = resolveScopedRepositories(dependencies);

  return {
    persistSessionRecord: ({session, transactionClient}) =>
      persistSessionRecord({
        sessionStore: requireDependency(repositories.sessionStore, 'auth_session_store_dependency_missing'),
        clients: requireScopedClients(),
        transactionClient: resolveScopedTransactionClient({
          callTransactionClient: transactionClient,
          scopeTransactionClient: dependencies.transactionClient
        }),
        session
      }),
    getSessionRecordByTokenHash: ({tokenHash, transactionClient}) =>
      getSessionRecordByTokenHash({
        sessionStore: requireDependency(repositories.sessionStore, 'auth_session_store_dependency_missing'),
        clients: requireScopedClients(),
        transactionClient: resolveScopedTransactionClient({
          callTransactionClient: transactionClient,
          scopeTransactionClient: dependencies.transactionClient
        }),
        tokenHash
      }),
    issueEnrollmentTokenRecord: ({record, transactionClient}) =>
      issueEnrollmentTokenRecord({
        enrollmentTokenStore: requireDependency(
          repositories.enrollmentTokenStore,
          'auth_enrollment_token_store_dependency_missing'
        ),
        clients: requireScopedClients(),
        transactionClient: resolveScopedTransactionClient({
          callTransactionClient: transactionClient,
          scopeTransactionClient: dependencies.transactionClient
        }),
        record
      }),
    consumeEnrollmentTokenRecordByHash: ({tokenHash, transactionClient}) =>
      consumeEnrollmentTokenRecordByHash({
        enrollmentTokenStore: requireDependency(
          repositories.enrollmentTokenStore,
          'auth_enrollment_token_store_dependency_missing'
        ),
        clients: requireScopedClients(),
        transactionClient: resolveScopedTransactionClient({
          callTransactionClient: transactionClient,
          scopeTransactionClient: dependencies.transactionClient
        }),
        tokenHash
      }),
    loadWorkloadRecordBySanUri: ({sanUri, transactionClient}) =>
      loadWorkloadRecordBySanUri({
        workloadStore: requireDependency(repositories.workloadStore, 'auth_workload_store_dependency_missing'),
        clients: requireScopedClients(),
        transactionClient: resolveScopedTransactionClient({
          callTransactionClient: transactionClient,
          scopeTransactionClient: dependencies.transactionClient
        }),
        sanUri
      }),
    createDpopReplayJtiStore: input =>
      createDpopReplayJtiStore({
        replayStore: requireDependency(repositories.replayStore, 'auth_dpop_replay_store_dependency_missing'),
        clients: requireScopedClients(),
        transactionClient: resolveScopedTransactionClient({
          callTransactionClient: input?.transactionClient,
          scopeTransactionClient: dependencies.transactionClient
        })
      })
  };
};
