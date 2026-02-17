import {z} from 'zod';

const NonEmptyStringSchema = z.string().trim().min(1);
const IdempotencyKeySchema = z.string().trim().regex(/^[A-Za-z0-9._:-]{1,128}$/u);

const ForwarderScopeSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    action_group: NonEmptyStringSchema
  })
  .strict();

const ForwarderIdempotencyScopeSchema = ForwarderScopeSchema.extend({
  idempotency_key: IdempotencyKeySchema
}).strict();

const ForwarderFingerprintSchema = z.string().trim().min(32);

const ForwarderExecutionLockAcquireInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    ttl_ms: z.number().int().min(1_000).max(60_000)
  })
  .strict();

const ForwarderExecutionLockReleaseInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    lock_token: NonEmptyStringSchema
  })
  .strict();

const ForwarderIdempotencyRecordInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    request_fingerprint_sha256: ForwarderFingerprintSchema,
    correlation_id: NonEmptyStringSchema,
    expires_at: z.string().datetime({offset: true})
  })
  .strict();

const ForwarderIdempotencyLookupInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema
  })
  .strict();

const ForwarderIdempotencyCompleteInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    correlation_id: NonEmptyStringSchema,
    upstream_status_code: z.number().int().min(100).max(599),
    response_bytes: z.number().int().min(0)
  })
  .strict();

const ForwarderIdempotencyFailInputSchema = z
  .object({
    scope: ForwarderIdempotencyScopeSchema,
    correlation_id: NonEmptyStringSchema,
    error_code: NonEmptyStringSchema
  })
  .strict();

const ForwarderHostFailureIncrementInputSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    host: NonEmptyStringSchema
  })
  .strict();

const ForwarderHostCircuitLookupInputSchema = ForwarderHostFailureIncrementInputSchema;

const ForwarderInflightExecutionMarkerInputSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    correlation_id: NonEmptyStringSchema,
    request_fingerprint_sha256: ForwarderFingerprintSchema,
    matched_path_group_id: NonEmptyStringSchema,
    upstream_host: NonEmptyStringSchema,
    timeout_ms: z.number().int().min(100).max(120_000),
    max_response_bytes: z.number().int().min(1).max(10 * 1024 * 1024)
  })
  .strict();

const ForwarderInflightExecutionDeleteInputSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    correlation_id: NonEmptyStringSchema
  })
  .strict();

const ForwarderHostCooldownSetInputSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    host: NonEmptyStringSchema,
    reason: z.enum(['network_error', 'oversized_response', 'timeout']),
    cooldown_seconds: z.number().int().min(1).max(300),
    failure_count_window: z.number().int().min(0)
  })
  .strict();

const ForwarderHostCooldownLookupInputSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema,
    host: NonEmptyStringSchema
  })
  .strict();

const ForwarderIdempotencyConflictInsertInputSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema.optional(),
    integration_id: NonEmptyStringSchema,
    action_group: NonEmptyStringSchema,
    idempotency_key: IdempotencyKeySchema,
    existing_request_fingerprint_sha256: ForwarderFingerprintSchema,
    incoming_request_fingerprint_sha256: ForwarderFingerprintSchema,
    correlation_id: NonEmptyStringSchema
  })
  .strict();

const ForwarderExecutionSnapshotInsertInputSchema = z
  .object({
    correlation_id: NonEmptyStringSchema,
    tenant_id: NonEmptyStringSchema,
    workload_id: NonEmptyStringSchema.optional(),
    integration_id: NonEmptyStringSchema,
    action_group: NonEmptyStringSchema,
    request_fingerprint_sha256: ForwarderFingerprintSchema,
    upstream_host: NonEmptyStringSchema,
    decision: z.enum(['executed', 'blocked', 'failed']),
    error_code: NonEmptyStringSchema.optional(),
    latency_ms: z.number().int().min(0).optional(),
    request_bytes: z.number().int().min(0).optional(),
    response_bytes: z.number().int().min(0).optional()
  })
  .strict();

const ForwarderExecutionSnapshotQueryInputSchema = z
  .object({
    tenant_id: NonEmptyStringSchema,
    integration_id: NonEmptyStringSchema.optional(),
    limit: z.number().int().min(1).max(200).default(50)
  })
  .strict();

type MaybePromise<T> = T | Promise<T>;

export type ForwarderExecutionLockAcquireInput_INCOMPLETE = z.infer<
  typeof ForwarderExecutionLockAcquireInputSchema
>;
export type ForwarderExecutionLockReleaseInput_INCOMPLETE = z.infer<
  typeof ForwarderExecutionLockReleaseInputSchema
>;
export type ForwarderIdempotencyRecordInput_INCOMPLETE = z.infer<
  typeof ForwarderIdempotencyRecordInputSchema
>;
export type ForwarderIdempotencyLookupInput_INCOMPLETE = z.infer<typeof ForwarderIdempotencyLookupInputSchema>;
export type ForwarderIdempotencyCompleteInput_INCOMPLETE = z.infer<
  typeof ForwarderIdempotencyCompleteInputSchema
>;
export type ForwarderIdempotencyFailInput_INCOMPLETE = z.infer<typeof ForwarderIdempotencyFailInputSchema>;
export type ForwarderHostFailureIncrementInput_INCOMPLETE = z.infer<
  typeof ForwarderHostFailureIncrementInputSchema
>;
export type ForwarderHostCircuitLookupInput_INCOMPLETE = z.infer<typeof ForwarderHostCircuitLookupInputSchema>;
export type ForwarderInflightExecutionMarkerInput_INCOMPLETE = z.infer<
  typeof ForwarderInflightExecutionMarkerInputSchema
>;
export type ForwarderInflightExecutionDeleteInput_INCOMPLETE = z.infer<
  typeof ForwarderInflightExecutionDeleteInputSchema
>;
export type ForwarderHostCooldownSetInput_INCOMPLETE = z.infer<typeof ForwarderHostCooldownSetInputSchema>;
export type ForwarderHostCooldownLookupInput_INCOMPLETE = z.infer<
  typeof ForwarderHostCooldownLookupInputSchema
>;
export type ForwarderIdempotencyConflictInsertInput_INCOMPLETE = z.infer<
  typeof ForwarderIdempotencyConflictInsertInputSchema
>;
export type ForwarderExecutionSnapshotInsertInput_INCOMPLETE = z.infer<
  typeof ForwarderExecutionSnapshotInsertInputSchema
>;
export type ForwarderExecutionSnapshotQueryInput_INCOMPLETE = z.infer<
  typeof ForwarderExecutionSnapshotQueryInputSchema
>;

export type ForwarderExecutionLockAcquireOutput_INCOMPLETE = {
  acquired: boolean;
  lock_token: string;
};

export type ForwarderExecutionLockReleaseOutput_INCOMPLETE = {
  released: boolean;
};

export type ForwarderIdempotencyRecordCreateOutput_INCOMPLETE = {
  created: boolean;
  conflict: null | 'key_exists' | 'fingerprint_mismatch';
};

export type ForwarderIdempotencyRecordView_INCOMPLETE = Record<string, unknown> | null;

export type ForwarderIdempotencyRecordUpdateOutput_INCOMPLETE = {
  updated: boolean;
};

export type ForwarderHostFailureIncrementOutput_INCOMPLETE = {
  consecutive_failures: number;
};

export type ForwarderHostCircuitLookupOutput_INCOMPLETE = {
  is_open: boolean;
  open_until: string | null;
};

export type ForwarderInflightExecutionMarkerCreateOutput_INCOMPLETE = {
  created: boolean;
};

export type ForwarderInflightExecutionMarkerDeleteOutput_INCOMPLETE = {
  deleted: boolean;
};

export type ForwarderHostCooldownUpdateOutput_INCOMPLETE = {
  updated: boolean;
};

export type ForwarderHostCooldownState_INCOMPLETE = Record<string, unknown> | null;

export type ForwarderIdempotencyConflictInsertOutput_INCOMPLETE = {
  inserted: boolean;
};

export type ForwarderExecutionSnapshotInsertOutput_INCOMPLETE = {
  inserted: boolean;
};

export type ForwarderExecutionSnapshotQueryOutput_INCOMPLETE = {
  items: Array<Record<string, unknown>>;
};

export type ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient = unknown> = {
  transactionClient?: TTransactionClient;
};

export type ForwarderDbRepositories_INCOMPLETE<TTransactionClient = unknown> = {
  acquireForwarderExecutionLock: (
    input: ForwarderExecutionLockAcquireInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderExecutionLockAcquireOutput_INCOMPLETE>;
  releaseForwarderExecutionLock: (
    input: ForwarderExecutionLockReleaseInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderExecutionLockReleaseOutput_INCOMPLETE>;
  createForwarderIdempotencyRecord: (
    input: ForwarderIdempotencyRecordInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderIdempotencyRecordCreateOutput_INCOMPLETE>;
  getForwarderIdempotencyRecord: (
    input: ForwarderIdempotencyLookupInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderIdempotencyRecordView_INCOMPLETE>;
  completeForwarderIdempotencyRecord: (
    input: ForwarderIdempotencyCompleteInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderIdempotencyRecordUpdateOutput_INCOMPLETE>;
  failForwarderIdempotencyRecord: (
    input: ForwarderIdempotencyFailInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderIdempotencyRecordUpdateOutput_INCOMPLETE>;
  incrementForwarderHostFailureCounter: (
    input: ForwarderHostFailureIncrementInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderHostFailureIncrementOutput_INCOMPLETE>;
  getForwarderHostCircuitState: (
    input: ForwarderHostCircuitLookupInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderHostCircuitLookupOutput_INCOMPLETE>;
  createForwarderInflightExecutionMarker: (
    input: ForwarderInflightExecutionMarkerInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderInflightExecutionMarkerCreateOutput_INCOMPLETE>;
  deleteForwarderInflightExecutionMarker: (
    input: ForwarderInflightExecutionDeleteInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderInflightExecutionMarkerDeleteOutput_INCOMPLETE>;
  setForwarderHostCooldownState: (
    input: ForwarderHostCooldownSetInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderHostCooldownUpdateOutput_INCOMPLETE>;
  getForwarderHostCooldownState: (
    input: ForwarderHostCooldownLookupInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderHostCooldownState_INCOMPLETE>;
  insertForwarderIdempotencyConflict: (
    input: ForwarderIdempotencyConflictInsertInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderIdempotencyConflictInsertOutput_INCOMPLETE>;
  insertForwarderExecutionSnapshot: (
    input: ForwarderExecutionSnapshotInsertInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderExecutionSnapshotInsertOutput_INCOMPLETE>;
  queryForwarderExecutionSnapshots: (
    input: ForwarderExecutionSnapshotQueryInput_INCOMPLETE,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) => MaybePromise<ForwarderExecutionSnapshotQueryOutput_INCOMPLETE>;
};

export type ForwarderDbDependencyBridgeDependencies_INCOMPLETE<TTransactionClient = unknown> = {
  repositories: Partial<ForwarderDbRepositories_INCOMPLETE<TTransactionClient>>;
};

export class ForwarderDbDependencyBridgeError extends Error {
  public readonly code: 'forwarder_db_dependency_missing';
  public readonly dependencyMethod: string;

  public constructor(dependencyMethod: string) {
    super(
      `ForwarderDbDependencyBridge requires app-injected repository method: @broker-interceptor/db.${dependencyMethod}`
    );
    this.name = 'ForwarderDbDependencyBridgeError';
    this.code = 'forwarder_db_dependency_missing';
    this.dependencyMethod = dependencyMethod;
  }
}

export type RequiredDependency = {
  packageName: '@broker-interceptor/db';
  requiredMethods: string[];
  deferredMethods?: string[];
  integrationStatus: 'mocked';
};

const FORWARDER_DB_MVP_REQUIRED_METHODS = [
  'acquireForwarderExecutionLock',
  'releaseForwarderExecutionLock',
  'createForwarderIdempotencyRecord',
  'getForwarderIdempotencyRecord',
  'completeForwarderIdempotencyRecord',
  'failForwarderIdempotencyRecord'
] as const;

const FORWARDER_DB_POST_MVP_DEFERRED_METHODS = [
  'incrementForwarderHostFailureCounter',
  'getForwarderHostCircuitState',
  'createForwarderInflightExecutionMarker',
  'deleteForwarderInflightExecutionMarker',
  'setForwarderHostCooldownState',
  'getForwarderHostCooldownState',
  'insertForwarderIdempotencyConflict',
  'insertForwarderExecutionSnapshot',
  'queryForwarderExecutionSnapshots'
] as const;

const FORWARDER_DB_DEPENDENCIES: ReadonlyArray<RequiredDependency> = [
  {
    packageName: '@broker-interceptor/db',
    requiredMethods: [...FORWARDER_DB_MVP_REQUIRED_METHODS],
    deferredMethods: [...FORWARDER_DB_POST_MVP_DEFERRED_METHODS],
    integrationStatus: 'mocked'
  }
] as const;

export class ForwarderDbDependencyBridge<TTransactionClient = unknown> {
  private readonly repositories: Partial<ForwarderDbRepositories_INCOMPLETE<TTransactionClient>>;

  public constructor(dependencies: ForwarderDbDependencyBridgeDependencies_INCOMPLETE<TTransactionClient>) {
    this.repositories = dependencies.repositories;
  }

  public listRequiredDependencies_INCOMPLETE() {
    return [...FORWARDER_DB_DEPENDENCIES];
  }

  private getRepositoryMethod_INCOMPLETE<TMethod extends keyof ForwarderDbRepositories_INCOMPLETE<TTransactionClient>>(
    methodName: TMethod
  ): NonNullable<ForwarderDbRepositories_INCOMPLETE<TTransactionClient>[TMethod]> {
    // eslint-disable-next-line security/detect-object-injection -- methodName is constrained to a known repository key union.
    const method = this.repositories[methodName];
    if (!method) {
      throw new ForwarderDbDependencyBridgeError(String(methodName));
    }

    return method;
  }

  public acquireForwarderExecutionLock_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderExecutionLockAcquireInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('acquireForwarderExecutionLock');
    return method(parsed, context);
  }

  public releaseForwarderExecutionLock_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderExecutionLockReleaseInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('releaseForwarderExecutionLock');
    return method(parsed, context);
  }

  public createForwarderIdempotencyRecord_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderIdempotencyRecordInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('createForwarderIdempotencyRecord');
    return method(parsed, context);
  }

  public getForwarderIdempotencyRecord_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderIdempotencyLookupInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('getForwarderIdempotencyRecord');
    return method(parsed, context);
  }

  public completeForwarderIdempotencyRecord_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderIdempotencyCompleteInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('completeForwarderIdempotencyRecord');
    return method(parsed, context);
  }

  public failForwarderIdempotencyRecord_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderIdempotencyFailInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('failForwarderIdempotencyRecord');
    return method(parsed, context);
  }

  public incrementForwarderHostFailureCounter_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderHostFailureIncrementInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('incrementForwarderHostFailureCounter');
    return method(parsed, context);
  }

  public getForwarderHostCircuitState_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderHostCircuitLookupInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('getForwarderHostCircuitState');
    return method(parsed, context);
  }

  public createForwarderInflightExecutionMarker_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderInflightExecutionMarkerInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('createForwarderInflightExecutionMarker');
    return method(parsed, context);
  }

  public deleteForwarderInflightExecutionMarker_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderInflightExecutionDeleteInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('deleteForwarderInflightExecutionMarker');
    return method(parsed, context);
  }

  public setForwarderHostCooldownState_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderHostCooldownSetInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('setForwarderHostCooldownState');
    return method(parsed, context);
  }

  public getForwarderHostCooldownState_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderHostCooldownLookupInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('getForwarderHostCooldownState');
    return method(parsed, context);
  }

  public insertForwarderIdempotencyConflict_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderIdempotencyConflictInsertInputSchema.parse(input);
    if (parsed.existing_request_fingerprint_sha256 === parsed.incoming_request_fingerprint_sha256) {
      throw new Error('Idempotency conflict fingerprints must differ');
    }

    const method = this.getRepositoryMethod_INCOMPLETE('insertForwarderIdempotencyConflict');
    return method(parsed, context);
  }

  public insertForwarderExecutionSnapshot_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderExecutionSnapshotInsertInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('insertForwarderExecutionSnapshot');
    return method(parsed, context);
  }

  public queryForwarderExecutionSnapshots_INCOMPLETE(
    input: unknown,
    context?: ForwarderDbTransactionContext_INCOMPLETE<TTransactionClient>
  ) {
    const parsed = ForwarderExecutionSnapshotQueryInputSchema.parse(input);
    const method = this.getRepositoryMethod_INCOMPLETE('queryForwarderExecutionSnapshots');
    return method(parsed, context);
  }
}

export const createForwarderDbDependencyBridge_INCOMPLETE = <TTransactionClient = unknown>(
  dependencies: ForwarderDbDependencyBridgeDependencies_INCOMPLETE<TTransactionClient>
): ForwarderDbDependencyBridge<TTransactionClient> => new ForwarderDbDependencyBridge(dependencies);
