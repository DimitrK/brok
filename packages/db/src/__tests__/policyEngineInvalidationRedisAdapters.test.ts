import {describe, expect, it, vi} from 'vitest';

import {
  createPolicyEngineRedisInvalidationBus,
  type PolicyEngineInvalidationEvent
} from '../redis/policyEngineInvalidationRedisAdapters.js';
import type {RedisPubSubClient} from '../redis/types.js';

class FakeRedisPubSub implements RedisPubSubClient {
  private readonly listeners = new Map<string, Set<(message: string) => void>>();

  public publish(channel: string, message: string): number {
    const handlers = this.listeners.get(channel);
    if (!handlers) {
      return 0;
    }

    for (const handler of handlers) {
      handler(message);
    }

    return handlers.size;
  }

  public subscribe(channel: string, listener: (message: string) => void): void {
    const handlers = this.listeners.get(channel);
    if (handlers) {
      handlers.add(listener);
      return;
    }

    this.listeners.set(channel, new Set([listener]));
  }

  public unsubscribe(channel: string, listener?: (message: string) => void): void {
    const handlers = this.listeners.get(channel);
    if (!handlers) {
      return;
    }

    if (!listener) {
      handlers.clear();
      return;
    }

    handlers.delete(listener);
  }
}

const sampleEvent: PolicyEngineInvalidationEvent = {
  tenant_id: 'tenant_1',
  entity_type: 'policy_rule',
  entity_id: 'policy_1',
  updated_at: '2026-02-11T00:00:00.000Z'
};

describe('policy-engine redis invalidation bus', () => {
  it('publishes and receives invalidation events', async () => {
    const redis = new FakeRedisPubSub();
    const bus = createPolicyEngineRedisInvalidationBus({keyPrefix: 'test:pe:'});
    const onEvent = vi.fn();

    const unsubscribe = bus.subscribePolicyEngineInvalidation({
      onEvent,
      context: {clients: {redis}}
    });
    expect(typeof unsubscribe).toBe('function');

    await bus.publishPolicyEngineInvalidation({
      event: sampleEvent,
      context: {clients: {redis}}
    });

    expect(onEvent).toHaveBeenCalledWith(sampleEvent);

    unsubscribe();
  });

  it('ignores malformed payloads', () => {
    const redis = new FakeRedisPubSub();
    const bus = createPolicyEngineRedisInvalidationBus({keyPrefix: 'test:pe:'});
    const onEvent = vi.fn();

    bus.subscribePolicyEngineInvalidation({
      onEvent,
      context: {clients: {redis}}
    });

    redis.publish('test:pe:invalidation:v1', '{not-json');

    expect(onEvent).not.toHaveBeenCalled();
  });

  it('returns sync unsubscribe even when subscribe is async', async () => {
    const subscribe = vi.fn(() => Promise.resolve());
    const unsubscribeClient = vi.fn(() => Promise.resolve());
    const redis: RedisPubSubClient = {
      publish: vi.fn(() => Promise.resolve(1)),
      subscribe,
      unsubscribe: unsubscribeClient
    };
    const bus = createPolicyEngineRedisInvalidationBus({keyPrefix: 'test:pe:'});

    const unsubscribe = bus.subscribePolicyEngineInvalidation({
      onEvent: vi.fn(),
      context: {clients: {redis}}
    });

    expect(typeof unsubscribe).toBe('function');
    expect(subscribe).toHaveBeenCalledTimes(1);

    unsubscribe();
    await Promise.resolve();
    expect(unsubscribeClient).toHaveBeenCalledTimes(1);
  });
});
