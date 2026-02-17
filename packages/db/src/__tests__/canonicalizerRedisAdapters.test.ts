import {describe, expect, it} from 'vitest';

import {CanonicalRequestDescriptorSchema, OpenApiTemplateSchema} from '../contracts.js';
import {createCanonicalizerRedisCacheStore} from '../redis/canonicalizerRedisAdapters.js';
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

  public eval(_script: string, keys: string[], args: Array<string | number>): Promise<unknown> {
    const key = keys[0];
    const intervalMs = Number(args[0]);
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || (entry.expiresAt !== undefined && entry.expiresAt <= now)) {
      const expiresAt = now + intervalMs;
      this.store.set(key, {value: '1', expiresAt});
      return Promise.resolve([1, intervalMs]);
    }

    const count = Number(entry.value) + 1;
    this.store.set(key, {value: String(count), expiresAt: entry.expiresAt});
    const ttlMs = Math.max(0, (entry.expiresAt ?? now) - now);
    return Promise.resolve([count, ttlMs]);
  }
}

const sampleTemplate = OpenApiTemplateSchema.parse({
  template_id: 'tpl_test',
  version: 1,
  provider: 'test',
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: ['api.example.com'],
  redirect_policy: {mode: 'deny'},
  path_groups: [
    {
      group_id: 'g1',
      risk_tier: 'low',
      approval_mode: 'none',
      methods: ['GET'],
      path_patterns: ['^/v1/test$'],
      query_allowlist: [],
      header_forward_allowlist: [],
      body_policy: {max_bytes: 0, content_types: []},
      constraints: {}
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

const sampleDescriptor = CanonicalRequestDescriptorSchema.parse({
  tenant_id: 'tenant_1',
  workload_id: 'workload_1',
  integration_id: 'integration_1',
  template_id: 'tpl_test',
  template_version: 1,
  method: 'GET',
  canonical_url: 'https://api.example.com/v1/test',
  matched_path_group_id: 'g1',
  normalized_headers: [],
  query_keys: [],
  query_fingerprint_base64: null,
  body_sha256_base64: null
});

describe('canonicalizer redis cache store', () => {
  it('stores and retrieves template cache entries', async () => {
    const redis = new FakeRedisEval();
    const store = createCanonicalizerRedisCacheStore({keyPrefix: 'test:canon:', templateCacheTtlSeconds: 60});

    await store.setTemplateCache({
      tenant_id: 'tenant_1',
      template_id: 'tpl_test',
      version: 1,
      template: sampleTemplate,
      context: {clients: {redis}}
    });

    const cached = await store.getTemplateCache({
      tenant_id: 'tenant_1',
      template_id: 'tpl_test',
      version: 1,
      context: {clients: {redis}}
    });

    expect(cached?.template_id).toBe('tpl_test');
  });

  it('ignores malformed template cache payloads', async () => {
    const redis = new FakeRedisEval();
    const store = createCanonicalizerRedisCacheStore({keyPrefix: 'test:canon:', templateCacheTtlSeconds: 60});

    redis.set('test:canon:template:tenant_1:tpl_test:1', '{invalid}', {EX: 60});

    const cached = await store.getTemplateCache({
      tenant_id: 'tenant_1',
      template_id: 'tpl_test',
      version: 1,
      context: {clients: {redis}}
    });

    expect(cached).toBeNull();
  });

  it('stores and retrieves approval once cache entries', async () => {
    const redis = new FakeRedisEval();
    const store = createCanonicalizerRedisCacheStore({keyPrefix: 'test:canon:'});

    await store.setApprovalOnceCache({
      descriptor: sampleDescriptor,
      value: {
        approval_id: 'apr_1',
        status: 'pending',
        expires_at: '2026-02-11T00:00:00.000Z',
        template_id: 'tpl_test',
        template_version: 1
      },
      ttl_seconds: 30,
      context: {clients: {redis}}
    });

    const cached = await store.getApprovalOnceCache({
      descriptor: sampleDescriptor,
      context: {clients: {redis}}
    });

    expect(cached?.approval_id).toBe('apr_1');
  });

  it('increments rate limit counters with expiry', async () => {
    const redis = new FakeRedisEval();
    const store = createCanonicalizerRedisCacheStore({keyPrefix: 'test:canon:'});

    const first = await store.incrementRateLimitCounter({
      tenant_id: 'tenant_1',
      workload_id: 'workload_1',
      integration_id: 'integration_1',
      action_group: 'send',
      method: 'POST',
      host: 'api.example.com',
      interval_seconds: 60,
      max_requests: 2,
      context: {clients: {redis}}
    });

    const second = await store.incrementRateLimitCounter({
      tenant_id: 'tenant_1',
      workload_id: 'workload_1',
      integration_id: 'integration_1',
      action_group: 'send',
      method: 'POST',
      host: 'api.example.com',
      interval_seconds: 60,
      max_requests: 2,
      context: {clients: {redis}}
    });

    const third = await store.incrementRateLimitCounter({
      tenant_id: 'tenant_1',
      workload_id: 'workload_1',
      integration_id: 'integration_1',
      action_group: 'send',
      method: 'POST',
      host: 'api.example.com',
      interval_seconds: 60,
      max_requests: 2,
      context: {clients: {redis}}
    });

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(third.allowed).toBe(false);
  });
});
