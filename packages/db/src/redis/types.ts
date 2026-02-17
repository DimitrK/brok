export type RedisSetOptions = {
  EX?: number;
  PX?: number;
  NX?: boolean;
  XX?: boolean;
};

export type RedisClient = {
  get: (key: string) => Promise<string | null> | string | null;
  set: (key: string, value: string, options?: RedisSetOptions) => Promise<'OK' | null> | 'OK' | null;
  del: (...keys: string[]) => Promise<number> | number;
};

export type RedisEvalClient = RedisClient & {
  eval: (script: string, keys: string[], args: Array<string | number>) => Promise<unknown>;
};

export type RedisPubSubClient = {
  publish: (channel: string, message: string) => Promise<number> | number;
  subscribe: (channel: string, listener: (message: string, channel?: string) => void) => Promise<void> | void;
  unsubscribe: (channel: string, listener?: (message: string, channel?: string) => void) => Promise<void> | void;
};

export type RedisScanClient = RedisClient & {
  scan: (
    cursor: string,
    options?: {
      MATCH?: string;
      COUNT?: number;
    }
  ) => Promise<[string, string[]]>;
};
