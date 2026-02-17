import {describe, expect, it, vi} from 'vitest';

import {
  createForwarderDbDependencyBridge_INCOMPLETE,
  ForwarderDbDependencyBridge,
  ForwarderDbDependencyBridgeError,
  type ForwarderDbRepositories_INCOMPLETE,
  type ForwarderDbTransactionContext_INCOMPLETE
} from '../dbDependencyBridge';

const baseScope = {
  tenant_id: 'tenant_1',
  workload_id: 'workload_1',
  integration_id: 'integration_1',
  action_group: 'group_a',
  idempotency_key: 'idem-key-1'
};

const resolveResult = async <T>(value: T | Promise<T>): Promise<T> => value;

const createRepositories = (): ForwarderDbRepositories_INCOMPLETE => ({
  acquireForwarderExecutionLock: vi.fn(() => ({acquired: true, lock_token: 'lock_1'})),
  releaseForwarderExecutionLock: vi.fn(() => ({released: true})),
  createForwarderIdempotencyRecord: vi.fn(() => ({created: true, conflict: null})),
  getForwarderIdempotencyRecord: vi.fn(() => null),
  completeForwarderIdempotencyRecord: vi.fn(() => ({updated: true})),
  failForwarderIdempotencyRecord: vi.fn(() => ({updated: true})),
  incrementForwarderHostFailureCounter: vi.fn(() => ({consecutive_failures: 1})),
  getForwarderHostCircuitState: vi.fn(() => ({is_open: false, open_until: null})),
  createForwarderInflightExecutionMarker: vi.fn(() => ({created: true})),
  deleteForwarderInflightExecutionMarker: vi.fn(() => ({deleted: true})),
  setForwarderHostCooldownState: vi.fn(() => ({updated: true})),
  getForwarderHostCooldownState: vi.fn(() => null),
  insertForwarderIdempotencyConflict: vi.fn(() => ({inserted: true})),
  insertForwarderExecutionSnapshot: vi.fn(() => ({inserted: true})),
  queryForwarderExecutionSnapshots: vi.fn(() => ({items: []}))
});

describe('ForwarderDbDependencyBridge', () => {
  it('declares db dependency requirements as incomplete wiring', () => {
    const bridge = createForwarderDbDependencyBridge_INCOMPLETE({
      repositories: createRepositories()
    });

    const required = bridge.listRequiredDependencies_INCOMPLETE();
    expect(required).toHaveLength(1);
    expect(required[0]?.packageName).toBe('@broker-interceptor/db');
    expect(required[0]?.requiredMethods).toContain('createForwarderIdempotencyRecord');
    expect(required[0]?.requiredMethods).not.toContain('setForwarderHostCooldownState');
    expect(required[0]?.deferredMethods).toContain('setForwarderHostCooldownState');
  });

  it('delegates lock + idempotency methods to app-injected repositories and forwards transaction context', async () => {
    const repositories = createRepositories();
    const bridge = createForwarderDbDependencyBridge_INCOMPLETE({repositories});
    const context: ForwarderDbTransactionContext_INCOMPLETE = {
      transactionClient: {txid: 'tx_1'}
    };

    const lock = await resolveResult(
      bridge.acquireForwarderExecutionLock_INCOMPLETE(
        {
          scope: baseScope,
          ttl_ms: 10_000
        },
        context
      )
    );
    expect(lock).toEqual({acquired: true, lock_token: 'lock_1'});
    expect(repositories.acquireForwarderExecutionLock).toHaveBeenCalledWith(
      {
        scope: baseScope,
        ttl_ms: 10_000
      },
      context
    );

    const released = await resolveResult(
      bridge.releaseForwarderExecutionLock_INCOMPLETE(
        {
          scope: baseScope,
          lock_token: lock.lock_token
        },
        context
      )
    );
    expect(released).toEqual({released: true});

    const created = await resolveResult(
      bridge.createForwarderIdempotencyRecord_INCOMPLETE(
        {
          scope: baseScope,
          request_fingerprint_sha256: 'a'.repeat(64),
          correlation_id: 'corr_1',
          expires_at: new Date(Date.now() + 60_000).toISOString()
        },
        context
      )
    );
    expect(created).toEqual({created: true, conflict: null});

    const lookedUp = await resolveResult(
      bridge.getForwarderIdempotencyRecord_INCOMPLETE(
        {
          scope: baseScope
        },
        context
      )
    );
    expect(lookedUp).toBeNull();

    const completed = await resolveResult(
      bridge.completeForwarderIdempotencyRecord_INCOMPLETE(
        {
          scope: baseScope,
          correlation_id: 'corr_1',
          upstream_status_code: 200,
          response_bytes: 120
        },
        context
      )
    );
    expect(completed).toEqual({updated: true});

    const failed = await resolveResult(
      bridge.failForwarderIdempotencyRecord_INCOMPLETE(
        {
          scope: baseScope,
          correlation_id: 'corr_1',
          error_code: 'upstream_timeout'
        },
        context
      )
    );
    expect(failed).toEqual({updated: true});
  });

  it('delegates host health + inflight + cooldown methods to app-injected repositories', async () => {
    const repositories = createRepositories();
    const bridge = createForwarderDbDependencyBridge_INCOMPLETE({repositories});

    const hostFailure = await resolveResult(
      bridge.incrementForwarderHostFailureCounter_INCOMPLETE({
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        host: 'api.example.com'
      })
    );
    expect(hostFailure).toEqual({consecutive_failures: 1});

    const hostCircuit = await resolveResult(
      bridge.getForwarderHostCircuitState_INCOMPLETE({
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        host: 'api.example.com'
      })
    );
    expect(hostCircuit).toEqual({is_open: false, open_until: null});

    const inflightCreated = await resolveResult(
      bridge.createForwarderInflightExecutionMarker_INCOMPLETE({
        tenant_id: 'tenant_1',
        workload_id: 'workload_1',
        integration_id: 'integration_1',
        correlation_id: 'corr_2',
        request_fingerprint_sha256: 'b'.repeat(64),
        matched_path_group_id: 'group_a',
        upstream_host: 'api.example.com',
        timeout_ms: 5000,
        max_response_bytes: 1024
      })
    );
    expect(inflightCreated).toEqual({created: true});

    const inflightDeleted = await resolveResult(
      bridge.deleteForwarderInflightExecutionMarker_INCOMPLETE({
        tenant_id: 'tenant_1',
        workload_id: 'workload_1',
        integration_id: 'integration_1',
        correlation_id: 'corr_2'
      })
    );
    expect(inflightDeleted).toEqual({deleted: true});

    const cooldownSet = await resolveResult(
      bridge.setForwarderHostCooldownState_INCOMPLETE({
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        host: 'api.example.com',
        reason: 'timeout',
        cooldown_seconds: 30,
        failure_count_window: 3
      })
    );
    expect(cooldownSet).toEqual({updated: true});

    const cooldown = await resolveResult(
      bridge.getForwarderHostCooldownState_INCOMPLETE({
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        host: 'api.example.com'
      })
    );
    expect(cooldown).toBeNull();
  });

  it('delegates postgres-facing methods to app-injected repositories', async () => {
    const repositories = createRepositories();
    const bridge = createForwarderDbDependencyBridge_INCOMPLETE({repositories});

    const conflictInserted = await resolveResult(
      bridge.insertForwarderIdempotencyConflict_INCOMPLETE({
        tenant_id: 'tenant_1',
        workload_id: 'workload_1',
        integration_id: 'integration_1',
        action_group: 'group_a',
        idempotency_key: 'idem-key-1',
        existing_request_fingerprint_sha256: 'c'.repeat(64),
        incoming_request_fingerprint_sha256: 'd'.repeat(64),
        correlation_id: 'corr_3'
      })
    );
    expect(conflictInserted).toEqual({inserted: true});

    const snapshotInserted = await resolveResult(
      bridge.insertForwarderExecutionSnapshot_INCOMPLETE({
        correlation_id: 'corr_4',
        tenant_id: 'tenant_1',
        workload_id: 'workload_1',
        integration_id: 'integration_1',
        action_group: 'group_a',
        request_fingerprint_sha256: 'e'.repeat(64),
        upstream_host: 'api.example.com',
        decision: 'executed',
        latency_ms: 50,
        request_bytes: 120,
        response_bytes: 240
      })
    );
    expect(snapshotInserted).toEqual({inserted: true});

    const snapshots = await resolveResult(
      bridge.queryForwarderExecutionSnapshots_INCOMPLETE({
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        limit: 10
      })
    );
    expect(snapshots).toEqual({items: []});
  });

  it('fails closed for invalid idempotency conflict payloads', () => {
    const bridge = createForwarderDbDependencyBridge_INCOMPLETE({
      repositories: createRepositories()
    });

    expect(() =>
      bridge.insertForwarderIdempotencyConflict_INCOMPLETE({
        tenant_id: 'tenant_1',
        integration_id: 'integration_1',
        action_group: 'group_a',
        idempotency_key: 'idem-key-1',
        existing_request_fingerprint_sha256: 'f'.repeat(64),
        incoming_request_fingerprint_sha256: 'f'.repeat(64),
        correlation_id: 'corr_5'
      })
    ).toThrow('Idempotency conflict fingerprints must differ');
  });

  it('fails closed when app does not inject required repository method', () => {
    const bridge = new ForwarderDbDependencyBridge({repositories: {}});

    expect(() =>
      bridge.acquireForwarderExecutionLock_INCOMPLETE({
        scope: baseScope,
        ttl_ms: 10_000
      })
    ).toThrow(new ForwarderDbDependencyBridgeError('acquireForwarderExecutionLock'));
  });
});
