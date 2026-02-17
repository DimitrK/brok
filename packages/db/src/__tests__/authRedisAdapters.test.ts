import {describe, expect, it} from 'vitest';

import {createAuthRedisStores} from '../redis/authRedisAdapters.js';
import type {RedisClient, RedisSetOptions} from '../redis/types.js';

class FakeRedis implements RedisClient {
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
    const now = Date.now();
    const existing = this.store.get(key);
    const hasExisting = existing !== undefined && (existing.expiresAt === undefined || existing.expiresAt > now);

    if (options?.NX && hasExisting) {
      return null;
    }

    if (options?.XX && !hasExisting) {
      return null;
    }

    const expiresAt = options?.EX !== undefined ? now + options.EX * 1000 : undefined;
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
}

describe('auth redis adapters', () => {
  it('persists and revokes sessions by token and id', async () => {
    const redis = new FakeRedis();
    const now = new Date('2026-02-11T00:00:00.000Z');
    const {sessionStore} = createAuthRedisStores({
      now: () => now,
      keyPrefix: 'test:auth:'
    });

    const session = {
      sessionId: '2ef34a0b-8d77-4b2b-96b0-6b2a60c76fd5',
      workloadId: 'w_1',
      tenantId: 't_1',
      certFingerprint256: 'fp',
      tokenHash: 'a'.repeat(64),
      expiresAt: '2026-02-11T00:01:00.000Z'
    };

    await sessionStore.upsertSession({session, redisClient: redis});
    const loaded = await sessionStore.getSessionByTokenHash({
      tokenHash: session.tokenHash,
      redisClient: redis
    });

    expect(loaded).toMatchObject({
      sessionId: session.sessionId,
      tenantId: session.tenantId
    });

    await sessionStore.revokeSessionById({sessionId: session.sessionId, redisClient: redis});
    const missing = await sessionStore.getSessionByTokenHash({
      tokenHash: session.tokenHash,
      redisClient: redis
    });

    expect(missing).toBeNull();
  });

  it('issues and consumes enrollment tokens once', async () => {
    const redis = new FakeRedis();
    const now = new Date('2026-02-11T00:00:00.000Z');
    const {enrollmentTokenStore} = createAuthRedisStores({
      now: () => now,
      keyPrefix: 'test:auth:'
    });

    const record = {
      tokenHash: 'b'.repeat(64),
      workloadId: 'w_2',
      expiresAt: '2026-02-11T00:02:00.000Z'
    };

    await enrollmentTokenStore.issueEnrollmentToken({record, redisClient: redis});
    const first = await enrollmentTokenStore.consumeEnrollmentTokenByHash({
      tokenHash: record.tokenHash,
      redisClient: redis
    });
    const second = await enrollmentTokenStore.consumeEnrollmentTokenByHash({
      tokenHash: record.tokenHash,
      redisClient: redis
    });

    expect(first).toMatchObject({
      tokenHash: record.tokenHash,
      workloadId: record.workloadId
    });
    expect(second).toBeNull();
  });

  it('reserves DPoP JTI once', async () => {
    const redis = new FakeRedis();
    const now = new Date('2026-02-11T00:00:00.000Z');
    const {replayStore} = createAuthRedisStores({
      now: () => now,
      keyPrefix: 'test:auth:'
    });

    const expiresAt = new Date('2026-02-11T00:01:00.000Z');
    const first = await replayStore.reserveDpopJti({
      replayScope: 't_1|w_1',
      jti: 'jti-1',
      expiresAt,
      redisClient: redis
    });
    const second = await replayStore.reserveDpopJti({
      replayScope: 't_1|w_1',
      jti: 'jti-1',
      expiresAt,
      redisClient: redis
    });

    expect(first).toBe(true);
    expect(second).toBe(false);
  });

  it('rejects malformed token hashes', async () => {
    const redis = new FakeRedis();
    const {sessionStore} = createAuthRedisStores({keyPrefix: 'test:auth:'});

    await expect(sessionStore.getSessionByTokenHash({tokenHash: 'bad', redisClient: redis})).rejects.toMatchObject({
      code: 'validation_error'
    });
  });
});
