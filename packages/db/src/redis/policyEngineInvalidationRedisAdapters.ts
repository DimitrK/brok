import {z} from 'zod';

import {DbRepositoryError} from '../errors.js';
import type {RedisPubSubClient} from './types.js';

const PolicyEngineInvalidationEventSchema = z
  .object({
    tenant_id: z.string().min(1),
    entity_type: z.enum(['policy_rule', 'template_binding', 'template_version']),
    entity_id: z.string().min(1),
    updated_at: z.iso.datetime({offset: true})
  })
  .strict();

const PublishInputSchema = z
  .object({
    event: PolicyEngineInvalidationEventSchema
  })
  .strict();

const SubscribeInputSchema = z
  .object({
    onEvent: z.custom<(event: PolicyEngineInvalidationEvent) => void>(
      value => typeof value === 'function',
      'onEvent must be a function'
    )
  })
  .strict();

type PolicyEngineInvalidationBusOptions = {
  keyPrefix?: string;
};

export type PolicyEngineInvalidationEvent = z.infer<typeof PolicyEngineInvalidationEventSchema>;

export type PolicyEngineInvalidationBusAdapter = {
  publishPolicyEngineInvalidation: (input: {
    event: PolicyEngineInvalidationEvent;
    context: {
      clients: {
        redis?: RedisPubSubClient;
      };
    };
  }) => Promise<void>;
  subscribePolicyEngineInvalidation: (input: {
    onEvent: (event: PolicyEngineInvalidationEvent) => void;
    context: {
      clients: {
        redis?: RedisPubSubClient;
      };
    };
  }) => () => void;
};

const normalizeKeyPrefix = (prefix?: string): string => {
  const trimmed = prefix?.trim();
  if (!trimmed) {
    return 'broker:pe:';
  }

  return trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
};

const resolveRedisClient = (context: {clients: {redis?: RedisPubSubClient}}): RedisPubSubClient => {
  const client = context.clients.redis;
  if (!client) {
    throw new DbRepositoryError('dependency_missing', 'Redis client is required for policy invalidation');
  }

  if (typeof client.publish !== 'function' || typeof client.subscribe !== 'function') {
    throw new DbRepositoryError('dependency_missing', 'Redis client must support pub/sub for policy invalidation');
  }

  return client;
};

const decodeEvent = (payload: string): PolicyEngineInvalidationEvent | null => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }

  const result = PolicyEngineInvalidationEventSchema.safeParse(parsed);
  if (!result.success) {
    return null;
  }

  return result.data;
};

export const createPolicyEngineRedisInvalidationBus = (
  options: PolicyEngineInvalidationBusOptions = {}
): PolicyEngineInvalidationBusAdapter => {
  const prefix = normalizeKeyPrefix(options.keyPrefix);
  const channel = `${prefix}invalidation:v1`;

  return {
    publishPolicyEngineInvalidation: async ({event, context}) => {
      const parsed = PublishInputSchema.parse({event});
      const redis = resolveRedisClient(context);
      await redis.publish(channel, JSON.stringify(parsed.event));
    },
    subscribePolicyEngineInvalidation: ({onEvent, context}) => {
      SubscribeInputSchema.parse({onEvent});
      const redis = resolveRedisClient(context);
      let closed = false;
      let subscribed = false;

      const handler = (message: string) => {
        const event = decodeEvent(message);
        if (!event) {
          return;
        }

        onEvent(event);
      };

      const detach = () => {
        if (typeof redis.unsubscribe === 'function') {
          void redis.unsubscribe(channel, handler);
        }
      };

      const subscribeResult = redis.subscribe(channel, handler);
      if (subscribeResult instanceof Promise) {
        void subscribeResult.then(() => {
          subscribed = true;
          if (closed) {
            detach();
          }
        });
        void subscribeResult.catch(() => {
          detach();
        });
      } else {
        subscribed = true;
      }

      return () => {
        closed = true;
        if (subscribed) {
          detach();
        }
      };
    }
  };
};
