import {isIP} from 'node:net';

import {TemplateSchema, type Template} from '@broker-interceptor/schemas';
import {z} from 'zod';

import {ssrfGuardErrorCodes} from './errors';

const NonEmptyStringSchema = z.string().trim().min(1);
const UnixEpochMsSchema = z.number().int().gte(0);
const IpLiteralSchema = z.string().trim().refine((value) => isIP(value) > 0, {
  message: 'Invalid IP literal'
});

export const StorageScopeSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema
  })
  .strict();

export const DnsResolutionCacheEntrySchema = z
  .object({
    resolved_ips: z.array(IpLiteralSchema).min(1),
    resolved_at_epoch_ms: UnixEpochMsSchema,
    ttl_seconds: z.number().int().gte(1).lte(60)
  })
  .strict();

export const DnsRebindingObservationSchema = z
  .object({
    ip_set_hash: NonEmptyStringSchema,
    resolved_ips: z.array(IpLiteralSchema).min(1),
    observed_at_epoch_ms: UnixEpochMsSchema
  })
  .strict();

export const SsrfDecisionProjectionSchema = z
  .object({
    event_id: NonEmptyStringSchema,
    timestamp: z.string().datetime({offset: true}),
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    template_id: NonEmptyStringSchema,
    template_version: z.number().int().gte(1),
    destination_host: NonEmptyStringSchema,
    destination_port: z.number().int().min(1).max(65_535),
    resolved_ips: z.array(IpLiteralSchema).min(1).max(32),
    decision: z.enum(['allowed', 'denied']),
    reason_code: z.enum(ssrfGuardErrorCodes),
    correlation_id: NonEmptyStringSchema
  })
  .strict();

export const TemplateInvalidationSignalSchema = z
  .object({
    template_id: NonEmptyStringSchema,
    version: z.number().int().gte(1),
    tenant_id: NonEmptyStringSchema,
    updated_at: z.string().datetime({offset: true})
  })
  .strict();

const IntegrationTemplateExecutionStatusSchema = z.enum([
  'executable',
  'workload_disabled',
  'integration_disabled'
]);

const IntegrationTemplateForExecuteSchema = z
  .object({
    workload_enabled: z.boolean(),
    integration_enabled: z.boolean(),
    executable: z.boolean(),
    execution_status: IntegrationTemplateExecutionStatusSchema,
    template: TemplateSchema,
    template_id: NonEmptyStringSchema,
    template_version: z.number().int().gte(1)
  })
  .strict();

export type StorageScope = z.infer<typeof StorageScopeSchema>;
export type DnsResolutionCacheEntry = z.infer<typeof DnsResolutionCacheEntrySchema>;
export type DnsRebindingObservation = z.infer<typeof DnsRebindingObservationSchema>;
export type SsrfDecisionProjection = z.infer<typeof SsrfDecisionProjectionSchema>;
export type TemplateInvalidationSignal = z.infer<typeof TemplateInvalidationSignalSchema>;
export type IntegrationTemplateForExecute = z.infer<typeof IntegrationTemplateForExecuteSchema>;
export type TemplateContract = Template;
export type TransactionClient = unknown;
export type MaybePromise<T> = T | Promise<T>;

export type RequiredDependency = {
  packageName: '@broker-interceptor/db';
  requiredMethods: string[];
  integrationStatus: 'mocked';
};

type StorageOperationContext = {
  transaction_client?: TransactionClient;
};

type LoadActiveTemplateForExecuteFromDbMethod_INCOMPLETE = (
  input: {scope: StorageScope} & StorageOperationContext
) => MaybePromise<TemplateContract | null>;

type PersistActiveTemplateForExecuteInDbMethod_INCOMPLETE = (
  input: {scope: StorageScope; template: TemplateContract} & StorageOperationContext
) => MaybePromise<TemplateContract>;

type ReadDnsResolutionCacheFromRedisMethod_INCOMPLETE = (
  input: {normalized_host: string} & StorageOperationContext
) => MaybePromise<DnsResolutionCacheEntry | null>;

type WriteDnsResolutionCacheToRedisMethod_INCOMPLETE = (
  input: {normalized_host: string; entry: DnsResolutionCacheEntry} & StorageOperationContext
) => MaybePromise<DnsResolutionCacheEntry>;

type AppendDnsRebindingObservationToRedisMethod_INCOMPLETE = (
  input: {normalized_host: string; observation: DnsRebindingObservation} & StorageOperationContext
) => MaybePromise<DnsRebindingObservation>;

type AppendSsrfDecisionProjectionToPostgresMethod_INCOMPLETE = (
  input: {projection: SsrfDecisionProjection} & StorageOperationContext
) => MaybePromise<SsrfDecisionProjection>;

type PublishTemplateInvalidationSignalToRedisMethod_INCOMPLETE = (
  input: {signal: TemplateInvalidationSignal} & StorageOperationContext
) => MaybePromise<TemplateInvalidationSignal>;

type DnsCacheWriteOutcome = 'applied' | 'skipped_stale';

const DnsCacheUpsertResultSchema = z
  .object({
    outcome: z.enum(['applied', 'skipped_stale']),
    applied: z.boolean(),
    entry: DnsResolutionCacheEntrySchema
  })
  .strict();

type RedisClientContext = {
  clients: {
    redis?: unknown;
  };
};

type GetIntegrationTemplateForExecuteMethod = (
  input: {
    tenant_id: string;
    workload_id: string;
    integration_id: string;
    transaction_client?: TransactionClient;
  }
) => MaybePromise<IntegrationTemplateForExecute>;

type ReadDnsResolutionCacheMethod = (
  input: {normalized_host: string; context: RedisClientContext}
) => MaybePromise<DnsResolutionCacheEntry | null>;

type UpsertDnsResolutionCacheMethod = (
  input: {normalized_host: string; entry: DnsResolutionCacheEntry; context: RedisClientContext}
) => MaybePromise<{outcome: DnsCacheWriteOutcome; applied: boolean; entry: DnsResolutionCacheEntry}>;

type AppendDnsRebindingObservationMethod = (
  input: {normalized_host: string; observation: DnsRebindingObservation; context: RedisClientContext}
) => MaybePromise<{observation: DnsRebindingObservation; history_size: number}>;

type AppendSsrfGuardDecisionProjectionMethod = (
  input: {projection: SsrfDecisionProjection} & StorageOperationContext
) => MaybePromise<SsrfDecisionProjection>;

type PublishTemplateInvalidationSignalMethod = (
  input: {signal: TemplateInvalidationSignal; context: RedisClientContext}
) => MaybePromise<void>;

type PersistTemplateInvalidationOutboxMethod = (
  input: {signal: TemplateInvalidationSignal} & StorageOperationContext
) => MaybePromise<void>;

export type SsrfGuardStorageRepositories_INCOMPLETE = {
  loadActiveTemplateForExecuteFromDb_INCOMPLETE?: LoadActiveTemplateForExecuteFromDbMethod_INCOMPLETE;
  getIntegrationTemplateForExecute?: GetIntegrationTemplateForExecuteMethod;
  readDnsResolutionCache?: ReadDnsResolutionCacheMethod;
  upsertDnsResolutionCache?: UpsertDnsResolutionCacheMethod;
  appendDnsRebindingObservation?: AppendDnsRebindingObservationMethod;
  appendSsrfGuardDecisionProjection?: AppendSsrfGuardDecisionProjectionMethod;
  publishTemplateInvalidationSignal?: PublishTemplateInvalidationSignalMethod;
  persistTemplateInvalidationOutbox?: PersistTemplateInvalidationOutboxMethod;
  persistActiveTemplateForExecuteInDbMock_INCOMPLETE?: PersistActiveTemplateForExecuteInDbMethod_INCOMPLETE;
  readDnsResolutionCacheFromRedis_INCOMPLETE?: ReadDnsResolutionCacheFromRedisMethod_INCOMPLETE;
  writeDnsResolutionCacheToRedisMock_INCOMPLETE?: WriteDnsResolutionCacheToRedisMethod_INCOMPLETE;
  appendDnsRebindingObservationToRedisMock_INCOMPLETE?: AppendDnsRebindingObservationToRedisMethod_INCOMPLETE;
  appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE?: AppendSsrfDecisionProjectionToPostgresMethod_INCOMPLETE;
  publishTemplateInvalidationSignalToRedisMock_INCOMPLETE?: PublishTemplateInvalidationSignalToRedisMethod_INCOMPLETE;
};

const REQUIRED_DEPENDENCIES: ReadonlyArray<RequiredDependency> = [
  {
    packageName: '@broker-interceptor/db',
    requiredMethods: [
      'getIntegrationTemplateForExecute',
      'getTemplateByIdVersion',
      'readDnsResolutionCache',
      'upsertDnsResolutionCache',
      'appendDnsRebindingObservation',
      'appendSsrfGuardDecisionProjection',
      'publishTemplateInvalidationSignal',
      'persistTemplateInvalidationOutbox',
      'runInTransaction'
    ],
    integrationStatus: 'mocked'
  }
] as const;

const buildScopeKey = (scope: StorageScope) =>
  `${scope.tenant_id}:${scope.workload_id}:${scope.integration_id}`;

const buildHostCacheKey = (normalizedHost: string) => normalizedHost.trim().toLowerCase();

const resolveMaybePromise = async <T>(value: MaybePromise<T>): Promise<T> => value;
const getErrorCode = (error: unknown): string | undefined => {
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }

  const withCode = error as {
    code?: unknown;
  };

  return typeof withCode.code === 'string' ? withCode.code : undefined;
};

type BridgeState = {
  activeTemplatesByScope: Map<string, TemplateContract>;
  dnsCacheByHost: Map<string, DnsResolutionCacheEntry>;
  dnsRebindingObservationsByHost: Map<string, DnsRebindingObservation[]>;
  ssrfDecisionProjections: SsrfDecisionProjection[];
  templateInvalidationSignals: TemplateInvalidationSignal[];
};

type BridgeClients = {
  redis?: unknown;
};

const createEmptyState = (): BridgeState => ({
  activeTemplatesByScope: new Map<string, TemplateContract>(),
  dnsCacheByHost: new Map<string, DnsResolutionCacheEntry>(),
  dnsRebindingObservationsByHost: new Map<string, DnsRebindingObservation[]>(),
  ssrfDecisionProjections: [],
  templateInvalidationSignals: []
});

export type SsrfGuardStorageBridgeDependencies_INCOMPLETE = {
  repositories?: SsrfGuardStorageRepositories_INCOMPLETE;
  clients?: BridgeClients;
  initial_state?: Partial<BridgeState>;
};

export class SsrfGuardStorageBridge {
  private readonly state: BridgeState;
  private readonly repositories: SsrfGuardStorageRepositories_INCOMPLETE;
  private readonly clients: BridgeClients;

  public constructor(dependencies?: SsrfGuardStorageBridgeDependencies_INCOMPLETE) {
    const emptyState = createEmptyState();
    const initialState = dependencies?.initial_state;
    this.repositories = dependencies?.repositories ?? {};
    this.clients = dependencies?.clients ?? {};
    this.state = {
      activeTemplatesByScope: initialState?.activeTemplatesByScope ?? emptyState.activeTemplatesByScope,
      dnsCacheByHost: initialState?.dnsCacheByHost ?? emptyState.dnsCacheByHost,
      dnsRebindingObservationsByHost:
        initialState?.dnsRebindingObservationsByHost ?? emptyState.dnsRebindingObservationsByHost,
      ssrfDecisionProjections:
        initialState?.ssrfDecisionProjections ?? emptyState.ssrfDecisionProjections,
      templateInvalidationSignals:
        initialState?.templateInvalidationSignals ?? emptyState.templateInvalidationSignals
    };
  }

  private getRedisContextOrThrow() {
    if (this.clients.redis === undefined) {
      throw new Error(
        'SsrfGuardStorageBridge requires dependencies.clients.redis when db readDnsResolutionCache/upsertDnsResolutionCache/appendDnsRebindingObservation/publishTemplateInvalidationSignal methods are injected'
      );
    }

    return {
      clients: {
        redis: this.clients.redis
      }
    } satisfies RedisClientContext;
  }

  public listRequiredDependencies_INCOMPLETE() {
    return [...REQUIRED_DEPENDENCIES];
  }

  public async loadActiveTemplateForExecuteFromDb_INCOMPLETE({
    scope,
    transaction_client
  }: {
    scope: StorageScope;
    transaction_client?: TransactionClient;
  }): Promise<TemplateContract | null> {
    const parsedScope = StorageScopeSchema.parse(scope);
    const repositoryMethod = this.repositories.loadActiveTemplateForExecuteFromDb_INCOMPLETE;
    if (repositoryMethod) {
      const loaded = await resolveMaybePromise(
        repositoryMethod({
          scope: parsedScope,
          transaction_client
        })
      );
      return loaded === null ? null : TemplateSchema.parse(loaded);
    }

    const dbIntegrationMethod = this.repositories.getIntegrationTemplateForExecute;
    if (dbIntegrationMethod) {
      try {
        const loaded = await resolveMaybePromise(
          dbIntegrationMethod({
            tenant_id: parsedScope.tenant_id,
            workload_id: parsedScope.workload_id,
            integration_id: parsedScope.integration_id,
            transaction_client
          })
        );
        const parsed = IntegrationTemplateForExecuteSchema.parse(loaded);
        return parsed.executable ? TemplateSchema.parse(parsed.template) : null;
      } catch (error) {
        if (getErrorCode(error) === 'not_found') {
          return null;
        }
        throw error;
      }
    }

    const key = buildScopeKey(parsedScope);
    const loaded = this.state.activeTemplatesByScope.get(key) ?? null;
    return loaded === null ? null : TemplateSchema.parse(loaded);
  }

  public async persistActiveTemplateForExecuteInDbMock_INCOMPLETE({
    scope,
    template,
    transaction_client
  }: {
    scope: StorageScope;
    template: TemplateContract;
    transaction_client?: TransactionClient;
  }): Promise<TemplateContract> {
    const parsedScope = StorageScopeSchema.parse(scope);
    const parsedTemplate = TemplateSchema.parse(template);
    const repositoryMethod = this.repositories.persistActiveTemplateForExecuteInDbMock_INCOMPLETE;
    if (repositoryMethod) {
      const persisted = await resolveMaybePromise(
        repositoryMethod({
          scope: parsedScope,
          template: parsedTemplate,
          transaction_client
        })
      );
      return TemplateSchema.parse(persisted);
    }

    const key = buildScopeKey(parsedScope);
    this.state.activeTemplatesByScope.set(key, parsedTemplate);
    return parsedTemplate;
  }

  public async readDnsResolutionCacheFromRedis_INCOMPLETE({
    normalized_host,
    transaction_client
  }: {
    normalized_host: string;
    transaction_client?: TransactionClient;
  }): Promise<DnsResolutionCacheEntry | null> {
    const parsedHost = NonEmptyStringSchema.parse(normalized_host);
    const repositoryMethod = this.repositories.readDnsResolutionCacheFromRedis_INCOMPLETE;
    if (repositoryMethod) {
      const cachedEntry = await resolveMaybePromise(
        repositoryMethod({
          normalized_host: parsedHost,
          transaction_client
        })
      );
      return cachedEntry === null ? null : DnsResolutionCacheEntrySchema.parse(cachedEntry);
    }

    const dbRepositoryMethod = this.repositories.readDnsResolutionCache;
    if (dbRepositoryMethod) {
      const cachedEntry = await resolveMaybePromise(
        dbRepositoryMethod({
          normalized_host: parsedHost,
          context: this.getRedisContextOrThrow()
        })
      );
      return cachedEntry === null ? null : DnsResolutionCacheEntrySchema.parse(cachedEntry);
    }

    const cacheKey = buildHostCacheKey(parsedHost);
    const cachedEntry = this.state.dnsCacheByHost.get(cacheKey) ?? null;
    return cachedEntry === null ? null : DnsResolutionCacheEntrySchema.parse(cachedEntry);
  }

  public async writeDnsResolutionCacheToRedisMock_INCOMPLETE({
    normalized_host,
    entry,
    transaction_client
  }: {
    normalized_host: string;
    entry: DnsResolutionCacheEntry;
    transaction_client?: TransactionClient;
  }): Promise<DnsResolutionCacheEntry> {
    const parsedHost = NonEmptyStringSchema.parse(normalized_host);
    const parsedEntry = DnsResolutionCacheEntrySchema.parse(entry);
    const repositoryMethod = this.repositories.writeDnsResolutionCacheToRedisMock_INCOMPLETE;
    if (repositoryMethod) {
      const persisted = await resolveMaybePromise(
        repositoryMethod({
          normalized_host: parsedHost,
          entry: parsedEntry,
          transaction_client
        })
      );
      return DnsResolutionCacheEntrySchema.parse(persisted);
    }

    const dbRepositoryMethod = this.repositories.upsertDnsResolutionCache;
    if (dbRepositoryMethod) {
      const persisted = await resolveMaybePromise(
        dbRepositoryMethod({
          normalized_host: parsedHost,
          entry: parsedEntry,
          context: this.getRedisContextOrThrow()
        })
      );
      const parsedPersisted = DnsCacheUpsertResultSchema.parse(persisted);
      return parsedPersisted.entry;
    }

    const cacheKey = buildHostCacheKey(parsedHost);
    this.state.dnsCacheByHost.set(cacheKey, parsedEntry);
    return parsedEntry;
  }

  public async appendDnsRebindingObservationToRedisMock_INCOMPLETE({
    normalized_host,
    observation,
    transaction_client
  }: {
    normalized_host: string;
    observation: DnsRebindingObservation;
    transaction_client?: TransactionClient;
  }): Promise<DnsRebindingObservation> {
    const parsedHost = NonEmptyStringSchema.parse(normalized_host);
    const parsedObservation = DnsRebindingObservationSchema.parse(observation);
    const repositoryMethod = this.repositories.appendDnsRebindingObservationToRedisMock_INCOMPLETE;
    if (repositoryMethod) {
      const persisted = await resolveMaybePromise(
        repositoryMethod({
          normalized_host: parsedHost,
          observation: parsedObservation,
          transaction_client
        })
      );
      return DnsRebindingObservationSchema.parse(persisted);
    }

    const dbRepositoryMethod = this.repositories.appendDnsRebindingObservation;
    if (dbRepositoryMethod) {
      const persisted = await resolveMaybePromise(
        dbRepositoryMethod({
          normalized_host: parsedHost,
          observation: parsedObservation,
          context: this.getRedisContextOrThrow()
        })
      );
      return DnsRebindingObservationSchema.parse(persisted.observation);
    }

    const cacheKey = buildHostCacheKey(parsedHost);
    const existing = this.state.dnsRebindingObservationsByHost.get(cacheKey) ?? [];
    this.state.dnsRebindingObservationsByHost.set(cacheKey, [...existing, parsedObservation]);
    return parsedObservation;
  }

  public async appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE({
    projection,
    transaction_client
  }: {
    projection: SsrfDecisionProjection;
    transaction_client?: TransactionClient;
  }): Promise<SsrfDecisionProjection> {
    const parsedProjection = SsrfDecisionProjectionSchema.parse(projection);
    const repositoryMethod = this.repositories.appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE;
    if (repositoryMethod) {
      const persisted = await resolveMaybePromise(
        repositoryMethod({
          projection: parsedProjection,
          transaction_client
        })
      );
      return SsrfDecisionProjectionSchema.parse(persisted);
    }

    const dbRepositoryMethod = this.repositories.appendSsrfGuardDecisionProjection;
    if (dbRepositoryMethod) {
      const persisted = await resolveMaybePromise(
        dbRepositoryMethod({
          projection: parsedProjection,
          transaction_client
        })
      );
      return SsrfDecisionProjectionSchema.parse(persisted);
    }

    this.state.ssrfDecisionProjections.push(parsedProjection);
    return parsedProjection;
  }

  public async publishTemplateInvalidationSignalToRedisMock_INCOMPLETE({
    signal,
    transaction_client
  }: {
    signal: TemplateInvalidationSignal;
    transaction_client?: TransactionClient;
  }): Promise<TemplateInvalidationSignal> {
    const parsedSignal = TemplateInvalidationSignalSchema.parse(signal);
    const repositoryMethod = this.repositories.publishTemplateInvalidationSignalToRedisMock_INCOMPLETE;
    if (repositoryMethod) {
      const persisted = await resolveMaybePromise(
        repositoryMethod({
          signal: parsedSignal,
          transaction_client
        })
      );
      return TemplateInvalidationSignalSchema.parse(persisted);
    }

    const persistOutboxMethod = this.repositories.persistTemplateInvalidationOutbox;
    if (persistOutboxMethod) {
      await resolveMaybePromise(
        persistOutboxMethod({
          signal: parsedSignal,
          transaction_client
        })
      );
    }

    const dbRepositoryMethod = this.repositories.publishTemplateInvalidationSignal;
    if (dbRepositoryMethod) {
      await resolveMaybePromise(
        dbRepositoryMethod({
          signal: parsedSignal,
          context: this.getRedisContextOrThrow()
        })
      );
      return parsedSignal;
    }

    this.state.templateInvalidationSignals.push(parsedSignal);
    return parsedSignal;
  }
}

export const createSsrfGuardStorageBridge_INCOMPLETE = (
  dependencies?: SsrfGuardStorageBridgeDependencies_INCOMPLETE
) => new SsrfGuardStorageBridge(dependencies);
