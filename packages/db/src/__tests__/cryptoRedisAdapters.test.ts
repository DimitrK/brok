import {describe, expect, it} from 'vitest';

import {createCryptoRedisRotationLockAdapter} from '../redis/cryptoRedisAdapters.js';
import type {RedisEvalClient, RedisSetOptions} from '../redis/types.js';

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

  public set(key: string, value: string, options?: RedisSetOptions): 'OK' | null {
    const existing = this.get(key);
    if (options?.NX && existing !== null) {
      return null;
    }
    if (options?.XX && existing === null) {
      return null;
    }

    const expiresAt = options?.PX ? Date.now() + options.PX : undefined;
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

  public eval(_script: string, keys: string[], args: Array<string | number>): Promise<number> {
    const key = keys[0];
    const token = String(args[0] ?? '');
    const current = this.get(key);
    if (current === null || current !== token) {
      return Promise.resolve(0);
    }

    this.store.delete(key);
    return Promise.resolve(1);
  }
}

describe('crypto redis rotation lock adapter', () => {
  it('acquires once and fails closed under contention', async () => {
    const redis = new FakeRedisEval();
    const locks = createCryptoRedisRotationLockAdapter({keyPrefix: 'test:crypto:'});

    const first = await locks.acquireCryptoRotationLock({
      lock_name: 'manifest-rotation',
      ttl_ms: 10_000,
      context: {clients: {redis}}
    });

    const second = await locks.acquireCryptoRotationLock({
      lock_name: 'manifest-rotation',
      ttl_ms: 10_000,
      context: {clients: {redis}}
    });

    expect(first.acquired).toBe(true);
    expect(second.acquired).toBe(false);
  });

  it('releases only for the owning token', async () => {
    const redis = new FakeRedisEval();
    const locks = createCryptoRedisRotationLockAdapter({keyPrefix: 'test:crypto:'});

    const lock = await locks.acquireCryptoRotationLock({
      lock_name: 'manifest-rotation',
      ttl_ms: 10_000,
      context: {clients: {redis}}
    });

    const wrongTokenRelease = await locks.releaseCryptoRotationLock({
      lock_name: 'manifest-rotation',
      token: '4a96e16b-5ce0-4a91-8a22-0bce43f5c80d',
      context: {clients: {redis}}
    });
    expect(wrongTokenRelease.released).toBe(false);

    const correctTokenRelease = await locks.releaseCryptoRotationLock({
      lock_name: 'manifest-rotation',
      token: lock.token,
      context: {clients: {redis}}
    });
    expect(correctTokenRelease.released).toBe(true);
  });

  it('rejects calls without a redis client', async () => {
    const locks = createCryptoRedisRotationLockAdapter();

    await expect(
      locks.acquireCryptoRotationLock({
        lock_name: 'manifest-rotation',
        ttl_ms: 10_000,
        context: {clients: {}}
      })
    ).rejects.toMatchObject({
      code: 'dependency_missing'
    });
  });
});
