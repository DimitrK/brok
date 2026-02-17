import {describe, expect, it, vi} from 'vitest';

import {OpenApiAuditEventSchema, type AuditEvent} from '../contracts.js';
import {createAuditRedisCacheAdapter} from '../redis/auditRedisAdapters.js';
import type {RedisScanClient} from '../redis/types.js';

class FakeRedisScan implements RedisScanClient {
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

  public set(key: string, value: string, options?: {EX?: number; PX?: number}): 'OK' | null {
    let expiresAt: number | undefined;
    if (options?.EX !== undefined) {
      expiresAt = Date.now() + options.EX * 1000;
    } else if (options?.PX !== undefined) {
      expiresAt = Date.now() + options.PX;
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

  public scan(cursor: string, options?: {MATCH?: string; COUNT?: number}): Promise<[string, string[]]> {
    void cursor;
    const pattern = options?.MATCH ?? '*';
    const prefix = pattern.endsWith('*') ? pattern.slice(0, -1) : pattern;
    const keys = [...this.store.keys()].filter(key => key.startsWith(prefix));
    return Promise.resolve(['0', keys]);
  }
}

const sampleEvent = OpenApiAuditEventSchema.parse({
  event_id: 'evt_1',
  timestamp: '2026-02-11T00:00:00.000Z',
  tenant_id: 'tenant_1',
  workload_id: 'workload_1',
  integration_id: 'integration_1',
  correlation_id: 'corr_1',
  event_type: 'execute',
  decision: 'allowed',
  action_group: 'read',
  risk_tier: 'low',
  destination: {
    scheme: 'https',
    host: 'api.example.com',
    port: 443,
    path_group: 'group_1'
  },
  latency_ms: 10,
  upstream_status_code: 200,
  canonical_descriptor: null,
  policy: null,
  message: null,
  metadata: null
});

describe('audit redis cache adapter', () => {
  it('stores and retrieves cached audit queries', async () => {
    const redis = new FakeRedisScan();
    const adapter = createAuditRedisCacheAdapter({
      redisClient: redis,
      cacheTtlSeconds: 30,
      ttlJitterSeconds: 0
    });

    await adapter.setCachedAuditQuery({
      tenant_id: 'tenant_1',
      filter: {tenant_id: 'tenant_1'},
      events: [sampleEvent]
    });

    const cached: AuditEvent[] | null = await adapter.getCachedAuditQuery({
      tenant_id: 'tenant_1',
      filter: {tenant_id: 'tenant_1'}
    });

    expect(cached).not.toBeNull();
    const cachedEvent = cached ? OpenApiAuditEventSchema.parse(cached[0]) : null;
    expect(cachedEvent?.event_id).toBe('evt_1');
  });

  it('supports cache-aside helper', async () => {
    const redis = new FakeRedisScan();
    const adapter = createAuditRedisCacheAdapter({
      redisClient: redis,
      cacheTtlSeconds: 30,
      ttlJitterSeconds: 0
    });
    const loader = vi.fn(() => Promise.resolve([sampleEvent]));

    const first: AuditEvent[] = await adapter.getOrSetAuditQuery({
      tenant_id: 'tenant_1',
      filter: {tenant_id: 'tenant_1'},
      loader
    });

    const second: AuditEvent[] = await adapter.getOrSetAuditQuery({
      tenant_id: 'tenant_1',
      filter: {tenant_id: 'tenant_1'},
      loader
    });

    const firstEvent = first[0] ? OpenApiAuditEventSchema.parse(first[0]) : null;
    const secondEvent = second[0] ? OpenApiAuditEventSchema.parse(second[0]) : null;
    expect(firstEvent?.event_id).toBe('evt_1');
    expect(secondEvent?.event_id).toBe('evt_1');
    expect(loader).toHaveBeenCalledTimes(1);
  });

  it('invalidates cache by tenant prefix', async () => {
    const redis = new FakeRedisScan();
    const adapter = createAuditRedisCacheAdapter({
      redisClient: redis,
      cacheTtlSeconds: 30,
      ttlJitterSeconds: 0
    });

    await adapter.setCachedAuditQuery({
      tenant_id: 'tenant_1',
      filter: {tenant_id: 'tenant_1'},
      events: [sampleEvent]
    });

    await adapter.setCachedAuditQuery({
      tenant_id: 'tenant_1',
      filter: {tenant_id: 'tenant_1', action_group: 'read'},
      events: [sampleEvent]
    });

    await adapter.invalidateAuditQueryCacheByTenant({
      tenant_id: 'tenant_1'
    });

    const cached: AuditEvent[] | null = await adapter.getCachedAuditQuery({
      tenant_id: 'tenant_1',
      filter: {tenant_id: 'tenant_1'}
    });

    expect(cached).toBeNull();
  });
});
