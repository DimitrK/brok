import {describe, expect, it} from 'vitest';

import {OpenApiPolicyRuleSchema} from '../contracts.js';
import {createPolicyEngineRedisRateLimitStore} from '../redis/policyEngineRedisAdapters.js';
import type {RedisEvalClient} from '../redis/types.js';

class FakeRedisEval implements RedisEvalClient {
  private readonly store = new Map<string, {count: number; expiresAt?: number}>();

  public get(key: string): string | null {
    const entry = this.store.get(key);
    if (!entry) {
      return null;
    }

    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.store.delete(key);
      return null;
    }

    return String(entry.count);
  }

  public set(): 'OK' | null {
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
    const existing = this.store.get(key);

    if (!existing || (existing.expiresAt !== undefined && existing.expiresAt <= now)) {
      const expiresAt = now + intervalMs;
      this.store.set(key, {count: 1, expiresAt});
      return Promise.resolve([1, intervalMs]);
    }

    const nextCount = existing.count + 1;
    this.store.set(key, {count: nextCount, expiresAt: existing.expiresAt});
    const ttlMs = Math.max(0, (existing.expiresAt ?? now) - now);
    return Promise.resolve([nextCount, ttlMs]);
  }
}

const rateLimitRule = OpenApiPolicyRuleSchema.parse({
  policy_id: 'pol_1',
  rule_type: 'rate_limit',
  scope: {
    tenant_id: 't_1',
    integration_id: 'int_1',
    action_group: 'send',
    method: 'POST',
    host: 'api.example.com'
  },
  rate_limit: {
    max_requests: 2,
    interval_seconds: 60
  }
});

describe('policy-engine redis rate limiter', () => {
  it('allows requests until limit exceeded', async () => {
    const redis = new FakeRedisEval();
    const rateLimitStore = createPolicyEngineRedisRateLimitStore({keyPrefix: 'test:pe:'});
    const now = new Date('2026-02-11T00:00:00.000Z');

    const first = await rateLimitStore.checkAndConsumePolicyRateLimit({
      descriptor: {},
      rule: rateLimitRule,
      key: 'tenant:t_1|workload:w_1',
      now,
      context: {clients: {redis}}
    });

    const second = await rateLimitStore.checkAndConsumePolicyRateLimit({
      descriptor: {},
      rule: rateLimitRule,
      key: 'tenant:t_1|workload:w_1',
      now,
      context: {clients: {redis}}
    });

    const third = await rateLimitStore.checkAndConsumePolicyRateLimit({
      descriptor: {},
      rule: rateLimitRule,
      key: 'tenant:t_1|workload:w_1',
      now,
      context: {clients: {redis}}
    });

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(third.allowed).toBe(false);
  });

  it('rejects non rate-limit rules', async () => {
    const redis = new FakeRedisEval();
    const rateLimitStore = createPolicyEngineRedisRateLimitStore();
    const now = new Date('2026-02-11T00:00:00.000Z');

    await expect(
      rateLimitStore.checkAndConsumePolicyRateLimit({
        descriptor: {},
        rule: {
          ...rateLimitRule,
          rule_type: 'allow' as const,
          rate_limit: null
        },
        key: 'tenant:t_1',
        now,
        context: {clients: {redis}}
      })
    ).rejects.toMatchObject({
      code: 'validation_error'
    });
  });
});
