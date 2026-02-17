import {z} from 'zod';

import {describe, expect, it} from 'vitest';

import {createForwarderRedisAdapter} from '../redis/forwarderRedisAdapters.js';
import type {RedisEvalClient} from '../redis/types.js';

class FakeRedisEval implements RedisEvalClient {
  private readonly store = new Map<string, {value: string; expiresAt?: number}>();

  public get(key: string): string | null {
    const entry = this.store.get(key);
    if (!entry) {
      return null;
    }

    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.store.delete(key);
      return null;
    }

    return entry.value;
  }

  public set(key: string, value: string, options?: {EX?: number; PX?: number; NX?: boolean}): 'OK' | null {
    if (options?.NX && this.get(key)) {
      return null;
    }

    let expiresAt: number | undefined;
    if (options?.EX !== undefined) {
      expiresAt = Date.now() + options.EX * 1000;
    } else if (options?.PX !== undefined) {
      expiresAt = Date.now() + options.PX;
    } else {
      const existing = this.store.get(key);
      expiresAt = existing?.expiresAt;
    }

    this.store.set(key, {value, expiresAt});
    return 'OK';
  }

  public del(...keys: string[]): number {
    let removed = 0;
    for (const key of keys) {
      if (this.store.delete(key)) {
        removed += 1;
      }
    }
    return removed;
  }

  public clearExpiry(key: string): void {
    const entry = this.store.get(key);
    if (!entry) {
      return;
    }

    this.store.set(key, {value: entry.value});
  }

  public forceSet(key: string, value: string, expiresAt?: number): void {
    this.store.set(key, {value, expiresAt});
  }

  public eval(script: string, keys: string[], args: Array<string | number>): Promise<unknown> {
    const key = keys[0];

    if (script.includes('forwarder_lock_release')) {
      const token = String(args[0]);
      const entry = this.store.get(key);
      if (entry && entry.value === token) {
        this.store.delete(key);
        return Promise.resolve(1);
      }

      return Promise.resolve(0);
    }

    if (script.includes('forwarder_idem_update')) {
      const entry = this.store.get(key);
      if (!entry || (entry.expiresAt !== undefined && entry.expiresAt <= Date.now())) {
        this.store.delete(key);
        return Promise.resolve(0);
      }

      const payload = JSON.parse(entry.value) as {
        state: string;
        correlation_id: string;
        expires_at_epoch_ms?: number;
        upstream_status_code?: number | null;
        response_bytes?: number | null;
        error_code?: string | null;
      };

      const newState = String(args[0]);
      const correlationId = String(args[1]);
      if (payload.state !== 'in_progress' || payload.correlation_id !== correlationId) {
        return Promise.resolve(0);
      }

      payload.state = newState;
      if (newState === 'completed') {
        payload.upstream_status_code = Number(args[2]);
        payload.response_bytes = Number(args[3]);
        delete payload.error_code;
      } else {
        payload.error_code = String(args[4]);
        delete payload.upstream_status_code;
        delete payload.response_bytes;
      }

      let nextExpiresAt = entry.expiresAt;
      if (!nextExpiresAt && payload.expires_at_epoch_ms) {
        nextExpiresAt = payload.expires_at_epoch_ms;
      }

      this.store.set(key, {value: JSON.stringify(payload), expiresAt: nextExpiresAt});
      return Promise.resolve(1);
    }

    return Promise.reject(new Error('Unknown script'));
  }
}

const IdempotencyRecordViewSchema = z
  .object({
    state: z.string(),
    upstream_status_code: z.number().optional(),
    error_code: z.string().optional()
  })
  .passthrough();

describe('forwarder redis adapter', () => {
  const now = new Date('2026-02-11T00:00:00.000Z');
  const scope = {
    tenant_id: 'tenant_1',
    workload_id: 'workload_1',
    integration_id: 'integration_1',
    action_group: 'send',
    idempotency_key: 'idem_1'
  };

  it('acquires and releases execution locks', async () => {
    const redis = new FakeRedisEval();
    const adapter = createForwarderRedisAdapter({keyPrefix: 'test:fw:', now: () => now});

    const first = await adapter.acquireForwarderExecutionLock({
      scope,
      ttl_ms: 5_000,
      context: {clients: {redis}}
    });

    const second = await adapter.acquireForwarderExecutionLock({
      scope,
      ttl_ms: 5_000,
      context: {clients: {redis}}
    });

    expect(first.acquired).toBe(true);
    expect(second.acquired).toBe(false);

    const released = await adapter.releaseForwarderExecutionLock({
      scope,
      lock_token: first.lock_token,
      context: {clients: {redis}}
    });

    expect(released.released).toBe(true);

    const notReleased = await adapter.releaseForwarderExecutionLock({
      scope,
      lock_token: 'wrong',
      context: {clients: {redis}}
    });

    expect(notReleased.released).toBe(false);
  });

  it('stores and updates idempotency records', async () => {
    const redis = new FakeRedisEval();
    const adapter = createForwarderRedisAdapter({keyPrefix: 'test:fw:', now: () => now});
    const expiresAt = new Date(now.getTime() + 2 * 60 * 1000).toISOString();

    const created = await adapter.createForwarderIdempotencyRecord({
      scope,
      request_fingerprint_sha256: 'a'.repeat(64),
      correlation_id: 'corr_1',
      expires_at: expiresAt,
      context: {clients: {redis}}
    });

    expect(created).toEqual({created: true, conflict: null});

    const cached = await adapter.getForwarderIdempotencyRecord({
      scope,
      context: {clients: {redis}}
    });

    const cachedRecord = cached ? IdempotencyRecordViewSchema.parse(cached) : null;
    expect(cachedRecord?.state).toBe('in_progress');

    const completed = await adapter.completeForwarderIdempotencyRecord({
      scope,
      correlation_id: 'corr_1',
      upstream_status_code: 200,
      response_bytes: 128,
      context: {clients: {redis}}
    });

    expect(completed.updated).toBe(true);

    const updated = await adapter.getForwarderIdempotencyRecord({
      scope,
      context: {clients: {redis}}
    });

    const updatedRecord = updated ? IdempotencyRecordViewSchema.parse(updated) : null;
    expect(updatedRecord?.state).toBe('completed');
    expect(updatedRecord?.upstream_status_code).toBe(200);
  });

  it('returns conflicts on mismatched fingerprints', async () => {
    const redis = new FakeRedisEval();
    const adapter = createForwarderRedisAdapter({keyPrefix: 'test:fw:', now: () => now});
    const expiresAt = new Date(now.getTime() + 2 * 60 * 1000).toISOString();

    await adapter.createForwarderIdempotencyRecord({
      scope,
      request_fingerprint_sha256: 'a'.repeat(64),
      correlation_id: 'corr_2',
      expires_at: expiresAt,
      context: {clients: {redis}}
    });

    const conflict = await adapter.createForwarderIdempotencyRecord({
      scope,
      request_fingerprint_sha256: 'b'.repeat(64),
      correlation_id: 'corr_3',
      expires_at: expiresAt,
      context: {clients: {redis}}
    });

    expect(conflict).toEqual({created: false, conflict: 'fingerprint_mismatch'});
  });

  it('repairs missing TTL on idempotency updates', async () => {
    const redis = new FakeRedisEval();
    const adapter = createForwarderRedisAdapter({keyPrefix: 'test:fw:', now: () => now});
    const expiresAt = new Date(now.getTime() + 2 * 60 * 1000).toISOString();

    await adapter.createForwarderIdempotencyRecord({
      scope,
      request_fingerprint_sha256: 'd'.repeat(64),
      correlation_id: 'corr_5',
      expires_at: expiresAt,
      context: {clients: {redis}}
    });

    const key = 'test:fw:idem:tenant_1:workload_1:integration_1:send:idem_1';
    redis.clearExpiry(key);

    const completed = await adapter.completeForwarderIdempotencyRecord({
      scope,
      correlation_id: 'corr_5',
      upstream_status_code: 201,
      response_bytes: 64,
      context: {clients: {redis}}
    });

    expect(completed.updated).toBe(true);
  });

  it('recreates idempotency record after corrupt payload', async () => {
    const redis = new FakeRedisEval();
    const adapter = createForwarderRedisAdapter({keyPrefix: 'test:fw:', now: () => now});
    const expiresAt = new Date(now.getTime() + 2 * 60 * 1000).toISOString();

    await adapter.createForwarderIdempotencyRecord({
      scope,
      request_fingerprint_sha256: 'e'.repeat(64),
      correlation_id: 'corr_6',
      expires_at: expiresAt,
      context: {clients: {redis}}
    });

    const key = 'test:fw:idem:tenant_1:workload_1:integration_1:send:idem_1';
    redis.forceSet(key, '{invalid}', undefined);

    const recreated = await adapter.createForwarderIdempotencyRecord({
      scope,
      request_fingerprint_sha256: 'e'.repeat(64),
      correlation_id: 'corr_6',
      expires_at: expiresAt,
      context: {clients: {redis}}
    });

    expect(recreated).toEqual({created: true, conflict: null});
  });

  it('marks failed idempotency records', async () => {
    const redis = new FakeRedisEval();
    const adapter = createForwarderRedisAdapter({keyPrefix: 'test:fw:', now: () => now});
    const expiresAt = new Date(now.getTime() + 2 * 60 * 1000).toISOString();
    const scoped = {...scope, idempotency_key: 'idem_2'};

    await adapter.createForwarderIdempotencyRecord({
      scope: scoped,
      request_fingerprint_sha256: 'c'.repeat(64),
      correlation_id: 'corr_4',
      expires_at: expiresAt,
      context: {clients: {redis}}
    });

    const failed = await adapter.failForwarderIdempotencyRecord({
      scope: scoped,
      correlation_id: 'corr_4',
      error_code: 'network_error',
      context: {clients: {redis}}
    });

    expect(failed.updated).toBe(true);

    const cached = await adapter.getForwarderIdempotencyRecord({
      scope: scoped,
      context: {clients: {redis}}
    });

    const failedRecord = cached ? IdempotencyRecordViewSchema.parse(cached) : null;
    expect(failedRecord?.state).toBe('failed');
    expect(failedRecord?.error_code).toBe('network_error');
  });
});
