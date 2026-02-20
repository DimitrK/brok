import {describe, expect, it} from 'vitest';

import {
  createNoopLogger,
  createStructuredLogger,
  getLogContext,
  runWithLogContext,
  sanitizeForLog,
  setLogContextFields
} from '../index';

const createBufferedWriter = () => {
  const stdout: string[] = [];
  const stderr: string[] = [];

  return {
    stdout,
    stderr,
    writer: {
      stdout: {
        write: (chunk: string | Uint8Array) => {
          stdout.push(String(chunk).trim());
          return true;
        }
      } as never,
      stderr: {
        write: (chunk: string | Uint8Array) => {
          stderr.push(String(chunk).trim());
          return true;
        }
      } as never
    }
  };
};

describe('@broker-interceptor/logging', () => {
  it('redacts sensitive keys recursively', () => {
    const sanitized = sanitizeForLog({
      value: {
        authorization: 'Bearer value',
        nested: {
          dpop: 'token',
          api_secret: 'secret',
          allowed: 'ok'
        },
        body: {
          foo: 'bar'
        }
      }
    }) as Record<string, unknown>;

    expect(sanitized.authorization).toBe('[REDACTED]');
    expect((sanitized.nested as Record<string, unknown>).dpop).toBe('[REDACTED]');
    expect((sanitized.nested as Record<string, unknown>).api_secret).toBe('[REDACTED]');
    expect((sanitized.nested as Record<string, unknown>).allowed).toBe('ok');
    expect(sanitized.body).toBe('[REDACTED]');
  });

  it('isolates async context across concurrent requests', async () => {
    const seen: string[] = [];

    await Promise.all([
      runWithLogContext(
        {
          correlation_id: 'corr_a',
          request_id: 'req_a'
        },
        async () => {
          await new Promise(resolve => setTimeout(resolve, 5));
          seen.push(getLogContext()?.correlation_id ?? 'missing');
        }
      ),
      runWithLogContext(
        {
          correlation_id: 'corr_b',
          request_id: 'req_b'
        },
        async () => {
          await new Promise(resolve => setTimeout(resolve, 1));
          seen.push(getLogContext()?.correlation_id ?? 'missing');
        }
      )
    ]);

    expect(new Set(seen)).toEqual(new Set(['corr_a', 'corr_b']));
  });

  it('merges context fields incrementally', () => {
    runWithLogContext(
      {
        correlation_id: 'corr_1',
        request_id: 'req_1'
      },
      () => {
        setLogContextFields({tenant_id: 't_1', workload_id: 'w_1'});
        const context = getLogContext();
        expect(context?.tenant_id).toBe('t_1');
        expect(context?.workload_id).toBe('w_1');
        expect(context?.correlation_id).toBe('corr_1');
      }
    );
  });

  it('emits valid envelope JSON', () => {
    const writerBuffer = createBufferedWriter();
    const logger = createStructuredLogger({
      service: 'broker-api',
      env: 'test',
      level: 'debug',
      writer: writerBuffer.writer
    });

    runWithLogContext(
      {
        correlation_id: 'corr_2',
        request_id: 'req_2',
        route: '/healthz',
        method: 'GET'
      },
      () => {
        logger.info({
          event: 'request.received',
          component: 'http.server',
          message: 'request received',
          metadata: {
            authorization: 'Bearer test'
          }
        });
      }
    );

    expect(writerBuffer.stdout.length).toBe(1);
    const payload = JSON.parse(writerBuffer.stdout[0]) as Record<string, unknown>;
    expect(payload.event).toBe('request.received');
    expect(payload.correlation_id).toBe('corr_2');
    expect(payload.request_id).toBe('req_2');
    expect(payload.service).toBe('broker-api');
    expect((payload.metadata as Record<string, unknown>).authorization).toBe('[REDACTED]');
  });

  it('never throws when writer fails', () => {
    const logger = createStructuredLogger({
      service: 'broker-api',
      env: 'test',
      level: 'debug',
      writer: {
        stdout: {
          write: () => {
            throw new Error('write failed');
          }
        } as never,
        stderr: {
          write: () => {
            throw new Error('write failed');
          }
        } as never
      }
    });

    expect(() => {
      logger.error({
        event: 'dependency.redis.error',
        component: 'redis.client',
        message: 'redis failed'
      });
    }).not.toThrow();
  });

  it('supports level filtering and stream routing', () => {
    const writerBuffer = createBufferedWriter();
    const logger = createStructuredLogger({
      service: 'broker-api',
      env: 'test',
      level: 'warn',
      writer: writerBuffer.writer
    });

    logger.debug({
      event: 'debug.event',
      component: 'test'
    });
    logger.info({
      event: 'info.event',
      component: 'test'
    });
    logger.warn({
      event: 'warn.event',
      component: 'test'
    });
    logger.error({
      event: 'error.event',
      component: 'test'
    });
    logger.fatal({
      event: 'fatal.event',
      component: 'test'
    });

    expect(writerBuffer.stdout).toHaveLength(1);
    expect(writerBuffer.stderr).toHaveLength(2);

    const warnPayload = JSON.parse(writerBuffer.stdout[0]) as Record<string, unknown>;
    const errorPayload = JSON.parse(writerBuffer.stderr[0]) as Record<string, unknown>;
    const fatalPayload = JSON.parse(writerBuffer.stderr[1]) as Record<string, unknown>;
    expect(warnPayload.event).toBe('warn.event');
    expect(errorPayload.event).toBe('error.event');
    expect(fatalPayload.event).toBe('fatal.event');
  });

  it('does not emit when logger level is silent', () => {
    const writerBuffer = createBufferedWriter();
    const logger = createStructuredLogger({
      service: 'broker-api',
      env: 'test',
      level: 'silent',
      writer: writerBuffer.writer
    });

    logger.error({
      event: 'error.event',
      component: 'test'
    });

    expect(writerBuffer.stdout).toHaveLength(0);
    expect(writerBuffer.stderr).toHaveLength(0);
  });

  it('fills default correlation context when request context is absent', () => {
    const writerBuffer = createBufferedWriter();
    const logger = createStructuredLogger({
      service: 'broker-api',
      env: 'test',
      level: 'debug',
      writer: writerBuffer.writer
    });

    logger.info({
      event: 'request.received',
      component: 'http.server'
    });

    const payload = JSON.parse(writerBuffer.stdout[0]) as Record<string, unknown>;
    expect(payload.correlation_id).toBe('n/a');
    expect(payload.request_id).toBe('n/a');
  });

  it('returns undefined when setting context fields outside ALS scope', () => {
    expect(setLogContextFields({tenant_id: 't_1'})).toBeUndefined();
  });

  it('sanitizes complex values and extra key configuration', () => {
    const circular: Record<string, unknown> = {
      plain: 'ok',
      created_at: new Date('2026-01-01T00:00:00.000Z'),
      invalid_created_at: new Date('invalid'),
      symbol: Symbol('s'),
      usage_count: BigInt(7),
      payload: ['a', {token_value: 'abc'}],
      maybe_error: new Error('failure'),
      execute: () => 'result'
    };
    circular.self = circular;

    let tooDeep: unknown = {value: 'stop'};
    for (let depth = 0; depth < 15; depth += 1) {
      tooDeep = [tooDeep];
    }

    const sanitized = sanitizeForLog({
      value: {
        customSecretLabel: 'sensitive',
        'x-api-key': 'api-key-secret',
        'auth-tag': 'tag-secret',
        circular,
        tooDeep
      },
      extraSensitiveKeys: ['custom_secret_label']
    }) as Record<string, unknown>;

    expect(sanitized.customSecretLabel).toBe('[REDACTED]');
    expect(sanitized['x-api-key']).toBe('[REDACTED]');
    expect(sanitized['auth-tag']).toBe('[REDACTED]');
    const circularSanitized = sanitized.circular as Record<string, unknown>;
    expect(circularSanitized.self).toBe('[CIRCULAR]');
    expect(circularSanitized.symbol).toBe('Symbol(s)');
    expect(circularSanitized.execute).toBe('[FUNCTION]');
    expect(circularSanitized.invalid_created_at).toBe('[INVALID_DATE]');
    expect(circularSanitized.usage_count).toBe('7');

    const payloadSanitized = circularSanitized.payload as unknown[];
    expect((payloadSanitized[1] as Record<string, unknown>).token_value).toBe('[REDACTED]');

    const maybeError = circularSanitized.maybe_error as Record<string, unknown>;
    expect(maybeError.name).toBe('Error');
    expect(maybeError.message).toBe('failure');
    expect(typeof maybeError.stack).toBe('string');

    const tooDeepSanitized = sanitized.tooDeep as unknown[];
    expect(JSON.stringify(tooDeepSanitized)).toContain('[TRUNCATED]');
  });

  it('provides no-op logger implementation', () => {
    const noop = createNoopLogger();
    expect(() => {
      noop.log({
        level: 'info',
        event: 'test.event.log',
        component: 'test'
      });
      noop.debug({
        event: 'test.event.debug',
        component: 'test'
      });
      noop.info({
        event: 'test.event.info',
        component: 'test'
      });
      noop.warn({
        event: 'test.event.warn',
        component: 'test'
      });
      noop.error({
        event: 'test.event.error',
        component: 'test'
      });
      noop.fatal({
        event: 'test.event.fatal',
        component: 'test'
      });
    }).not.toThrow();
  });

  it('drops invalid log events without throwing', () => {
    const writerBuffer = createBufferedWriter();
    const logger = createStructuredLogger({
      service: 'broker-api',
      env: 'test',
      level: 'debug',
      writer: writerBuffer.writer
    });

    expect(() => {
      logger.log({
        level: 'info',
        event: '',
        component: 'test'
      } as unknown as never);
    }).not.toThrow();

    expect(writerBuffer.stdout).toHaveLength(0);
    expect(writerBuffer.stderr).toHaveLength(0);
  });

  it('uses default writer when no custom writer is provided', () => {
    const logger = createStructuredLogger({
      service: 'broker-api',
      env: 'test',
      level: 'silent'
    });

    expect(() => {
      logger.info({
        event: 'default.writer.ignored',
        component: 'test'
      });
    }).not.toThrow();
  });
});
