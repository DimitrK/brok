import {describe, expect, it, vi} from 'vitest';

import {createSsrfGuardRedisAdapter} from '../redis/ssrfGuardRedisAdapters.js';
import type {RedisEvalClient, RedisPubSubClient} from '../redis/types.js';

class FakeRedisClient implements RedisEvalClient, RedisPubSubClient {
  private readonly store = new Map<string, {value: string; expiresAt?: number}>();
  private readonly listeners = new Map<string, Set<(message: string, channel?: string) => void>>();

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

  public set(
    key: string,
    value: string,
    options?: {EX?: number; PX?: number; NX?: boolean; XX?: boolean}
  ): 'OK' | null {
    const existing = this.get(key);
    if (options?.NX && existing !== null) {
      return null;
    }
    if (options?.XX && existing === null) {
      return null;
    }

    let expiresAt: number | undefined;
    if (options?.EX !== undefined) {
      expiresAt = Date.now() + options.EX * 1000;
    }
    if (options?.PX !== undefined) {
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

  public eval(script: string, keys: string[], args: Array<string | number>): Promise<unknown> {
    const key = keys[0];
    if (!key) {
      throw new Error('Expected Redis key');
    }

    if (script.includes('ssrf_dns_cache_cas')) {
      const payload = String(args[0]);
      const ttlSeconds = Number(args[1]);
      const newResolvedAtMs = Number(args[2]);
      const existing = this.get(key);
      if (!existing) {
        this.set(key, payload, {EX: ttlSeconds});
        return Promise.resolve('applied');
      }

      let parsedExisting: {resolved_at_epoch_ms?: unknown} | null = null;
      try {
        parsedExisting = JSON.parse(existing) as {resolved_at_epoch_ms?: unknown};
      } catch {
        this.set(key, payload, {EX: ttlSeconds});
        return Promise.resolve('applied');
      }

      const existingResolvedAtMs = Number(parsedExisting.resolved_at_epoch_ms);
      if (!Number.isFinite(existingResolvedAtMs) || newResolvedAtMs >= existingResolvedAtMs) {
        this.set(key, payload, {EX: ttlSeconds});
        return Promise.resolve('applied');
      }

      return Promise.resolve('skipped_stale');
    }

    if (script.includes('ssrf_dns_history_append')) {
      const payload = String(args[0]);
      const ttlSeconds = Number(args[1]);
      const maxEntries = Number(args[2]);
      const existing = this.get(key);

      let history: unknown[] = [];
      if (existing) {
        try {
          const parsed: unknown = JSON.parse(existing);
          if (Array.isArray(parsed)) {
            history = parsed;
          }
        } catch {
          history = [];
        }
      }

      const observation = JSON.parse(payload) as unknown;
      history.push(observation);
      while (history.length > maxEntries) {
        history.shift();
      }

      this.set(key, JSON.stringify(history), {EX: ttlSeconds});
      return Promise.resolve(history.length);
    }

    throw new Error('Unknown eval script');
  }

  public publish(channel: string, message: string): number {
    const listeners = this.listeners.get(channel);
    if (!listeners || listeners.size === 0) {
      return 0;
    }

    for (const listener of listeners) {
      listener(message, channel);
    }

    return listeners.size;
  }

  public subscribe(channel: string, listener: (message: string, channel?: string) => void): void {
    const listeners = this.listeners.get(channel) ?? new Set<(message: string, channel?: string) => void>();
    listeners.add(listener);
    this.listeners.set(channel, listeners);
  }

  public unsubscribe(channel: string, listener?: (message: string, channel?: string) => void): void {
    if (!listener) {
      this.listeners.delete(channel);
      return;
    }

    const listeners = this.listeners.get(channel);
    if (!listeners) {
      return;
    }

    listeners.delete(listener);
    if (listeners.size === 0) {
      this.listeners.delete(channel);
    }
  }

  public forceSet(key: string, value: string): void {
    this.store.set(key, {value});
  }

  public hasKey(key: string): boolean {
    return this.store.has(key);
  }
}

describe('ssrf-guard redis adapters', () => {
  it('writes and reads DNS cache entries with normalized host keys', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});
    const entry = {
      resolved_ips: ['203.0.113.9'],
      resolved_at_epoch_ms: 1_700_000_000_000,
      ttl_seconds: 60
    };

    const result = await adapter.upsertDnsResolutionCache({
      normalized_host: 'Example.COM.',
      entry,
      context: {
        clients: {
          redis
        }
      }
    });

    expect(result).toEqual({
      outcome: 'applied',
      applied: true,
      entry
    });

    const cached = await adapter.readDnsResolutionCache({
      normalized_host: 'example.com',
      context: {
        clients: {
          redis
        }
      }
    });

    expect(cached).toEqual(entry);
  });

  it('skips stale DNS cache writes when resolved_at goes backwards', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});

    await adapter.upsertDnsResolutionCache({
      normalized_host: 'api.example.com',
      entry: {
        resolved_ips: ['198.51.100.10'],
        resolved_at_epoch_ms: 2_000,
        ttl_seconds: 30
      },
      context: {
        clients: {
          redis
        }
      }
    });

    const staleWrite = await adapter.upsertDnsResolutionCache({
      normalized_host: 'api.example.com',
      entry: {
        resolved_ips: ['198.51.100.11'],
        resolved_at_epoch_ms: 1_000,
        ttl_seconds: 30
      },
      context: {
        clients: {
          redis
        }
      }
    });

    expect(staleWrite.outcome).toBe('skipped_stale');
    expect(staleWrite.applied).toBe(false);

    const cached = await adapter.readDnsResolutionCache({
      normalized_host: 'api.example.com',
      context: {
        clients: {
          redis
        }
      }
    });

    expect(cached?.resolved_ips).toEqual(['198.51.100.10']);
    expect(cached?.resolved_at_epoch_ms).toBe(2_000);
  });

  it('rejects DNS cache writes containing denylisted addresses', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});

    await expect(
      adapter.upsertDnsResolutionCache({
        normalized_host: 'api.example.com',
        entry: {
          resolved_ips: ['127.0.0.1'],
          resolved_at_epoch_ms: 2_000,
          ttl_seconds: 30
        },
        context: {
          clients: {
            redis
          }
        }
      })
    ).rejects.toMatchObject({
      name: 'ZodError'
    });
  });

  it('deletes malformed DNS cache payloads on read', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});
    const key = 'test:ssrf:dns:v1:api.example.com';
    redis.forceSet(key, '{invalid json');

    const cached = await adapter.readDnsResolutionCache({
      normalized_host: 'api.example.com',
      context: {
        clients: {
          redis
        }
      }
    });

    expect(cached).toBeNull();
    expect(redis.hasKey(key)).toBe(false);
  });

  it('deletes denylisted DNS cache payloads on read', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});
    const key = 'test:ssrf:dns:v1:api.example.com';
    redis.forceSet(
      key,
      JSON.stringify({
        resolved_ips: ['169.254.169.254'],
        resolved_at_epoch_ms: 1_700_000_000_000,
        ttl_seconds: 60
      })
    );

    const cached = await adapter.readDnsResolutionCache({
      normalized_host: 'api.example.com',
      context: {
        clients: {
          redis
        }
      }
    });

    expect(cached).toBeNull();
    expect(redis.hasKey(key)).toBe(false);
  });

  it('appends bounded DNS rebinding history with retention limits', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({
      keyPrefix: 'test:ssrf:',
      dnsHistoryMaxEntries: 2
    });
    const context = {
      clients: {
        redis
      }
    };

    await adapter.appendDnsRebindingObservation({
      normalized_host: 'api.example.com',
      observation: {
        ip_set_hash: 'h1',
        resolved_ips: ['198.51.100.10'],
        observed_at_epoch_ms: 1
      },
      context
    });

    await adapter.appendDnsRebindingObservation({
      normalized_host: 'api.example.com',
      observation: {
        ip_set_hash: 'h2',
        resolved_ips: ['198.51.100.11'],
        observed_at_epoch_ms: 2
      },
      context
    });

    const third = await adapter.appendDnsRebindingObservation({
      normalized_host: 'api.example.com',
      observation: {
        ip_set_hash: 'h3',
        resolved_ips: ['198.51.100.12'],
        observed_at_epoch_ms: 3
      },
      context
    });

    expect(third.history_size).toBe(2);

    const history = await adapter.readDnsRebindingObservationHistory({
      normalized_host: 'api.example.com',
      context
    });

    expect(history).toHaveLength(2);
    expect(history[0]?.ip_set_hash).toBe('h2');
    expect(history[1]?.ip_set_hash).toBe('h3');
  });

  it('publishes and subscribes to template invalidation signals', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});
    const received: Array<{template_id: string; version: number; tenant_id: string; updated_at: string}> = [];

    const unsubscribe = adapter.subscribeTemplateInvalidationSignal({
      onSignal: signal => {
        received.push(signal);
      },
      context: {
        clients: {
          redis
        }
      }
    });

    await adapter.publishTemplateInvalidationSignal({
      signal: {
        template_id: 'tpl_demo',
        version: 2,
        tenant_id: 'tenant_1',
        updated_at: '2026-02-13T03:00:00.000Z'
      },
      context: {
        clients: {
          redis
        }
      }
    });

    redis.publish('test:ssrf:invalidation:v1', '{invalid-json');

    expect(received).toEqual([
      {
        template_id: 'tpl_demo',
        version: 2,
        tenant_id: 'tenant_1',
        updated_at: '2026-02-13T03:00:00.000Z'
      }
    ]);

    unsubscribe();
  });

  it('returns sync unsubscribe even when subscribe is async', async () => {
    const subscribe = vi.fn(() => Promise.resolve());
    const unsubscribeClient = vi.fn(() => Promise.resolve());
    const redis: RedisPubSubClient = {
      publish: vi.fn(() => Promise.resolve(1)),
      subscribe,
      unsubscribe: unsubscribeClient
    };
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});

    const unsubscribe = adapter.subscribeTemplateInvalidationSignal({
      onSignal: vi.fn(),
      context: {
        clients: {
          redis
        }
      }
    });

    expect(typeof unsubscribe).toBe('function');
    expect(subscribe).toHaveBeenCalledTimes(1);

    unsubscribe();
    await Promise.resolve();
    expect(unsubscribeClient).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed normalized host values', async () => {
    const redis = new FakeRedisClient();
    const adapter = createSsrfGuardRedisAdapter({keyPrefix: 'test:ssrf:'});

    await expect(
      adapter.readDnsResolutionCache({
        normalized_host: 'api/example.com',
        context: {
          clients: {
            redis
          }
        }
      })
    ).rejects.toMatchObject({
      name: 'ZodError'
    });
  });
});
