import type {Writable} from 'node:stream';

import {LogEventSchema} from '@broker-interceptor/schemas';
import {z} from 'zod';

import {getLogContext, type LogContext} from './context';
import {sanitizeForLog} from './redaction';

export const LogLevelSchema = z.enum(['debug', 'info', 'warn', 'error', 'fatal', 'silent']);
export type LogLevel = z.infer<typeof LogLevelSchema>;

const EmittableLogLevelSchema = z.enum(['debug', 'info', 'warn', 'error', 'fatal']);
type EmittableLogLevel = z.infer<typeof EmittableLogLevelSchema>;

export const LogEventInputSchema = z
  .object({
    level: EmittableLogLevelSchema,
    event: z.string().min(1),
    component: z.string().min(1),
    message: z.string().min(1).optional(),
    correlation_id: z.string().min(1).max(128).optional(),
    request_id: z.string().min(1).max(128).optional(),
    tenant_id: z.string().min(1).optional(),
    workload_id: z.string().min(1).optional(),
    integration_id: z.string().min(1).optional(),
    reason_code: z.string().min(1).optional(),
    duration_ms: z.number().int().gte(0).optional(),
    status_code: z.number().int().gte(100).lte(599).optional(),
    route: z.string().min(1).optional(),
    method: z.string().min(1).optional(),
    metadata: z.record(z.string(), z.unknown()).optional()
  })
  .strict();

export type LogEventInput = z.infer<typeof LogEventInputSchema>;

type LogEventEnvelope = z.infer<typeof LogEventSchema>;

const toLevelOrder = (level: LogLevel | EmittableLogLevel) => {
  switch (level) {
    case 'debug':
      return 10;
    case 'info':
      return 20;
    case 'warn':
      return 30;
    case 'error':
      return 40;
    case 'fatal':
      return 50;
    case 'silent':
      return 90;
  }
};

export type StructuredLogWriter = {
  stdout: Writable;
  stderr: Writable;
};

export type StructuredLoggerOptions = {
  service: string;
  env: string;
  level: LogLevel;
  now?: () => Date;
  writer?: StructuredLogWriter;
  extraSensitiveKeys?: string[];
};

export type StructuredLogger = {
  log: (input: LogEventInput) => void;
  debug: (input: Omit<LogEventInput, 'level'>) => void;
  info: (input: Omit<LogEventInput, 'level'>) => void;
  warn: (input: Omit<LogEventInput, 'level'>) => void;
  error: (input: Omit<LogEventInput, 'level'>) => void;
  fatal: (input: Omit<LogEventInput, 'level'>) => void;
};

const defaultWriter: StructuredLogWriter = {
  stdout: process.stdout,
  stderr: process.stderr
};

const shouldEmit = ({configuredLevel, eventLevel}: {configuredLevel: LogLevel; eventLevel: EmittableLogLevel}) =>
  toLevelOrder(eventLevel) >= toLevelOrder(configuredLevel);

const chooseStream = ({
  level,
  writer
}: {
  level: EmittableLogLevel;
  writer: StructuredLogWriter;
}) => (level === 'error' || level === 'fatal' ? writer.stderr : writer.stdout);

const extractContext = ({context, input}: {context: LogContext | undefined; input: LogEventInput}) => ({
  correlation_id: input.correlation_id ?? context?.correlation_id ?? 'n/a',
  request_id: input.request_id ?? context?.request_id ?? 'n/a',
  tenant_id: input.tenant_id ?? context?.tenant_id,
  workload_id: input.workload_id ?? context?.workload_id,
  integration_id: input.integration_id ?? context?.integration_id,
  route: input.route ?? context?.route,
  method: input.method ?? context?.method
});

const createEnvelope = ({
  input,
  options,
  context
}: {
  input: LogEventInput;
  options: StructuredLoggerOptions;
  context: LogContext | undefined;
}): LogEventEnvelope => {
  const resolvedContext = extractContext({context, input});
  const sanitizedMetadata = sanitizeForLog({
    value: input.metadata ?? {},
    extraSensitiveKeys: options.extraSensitiveKeys
  }) as Record<string, unknown>;

  return LogEventSchema.parse({
    ts: (options.now ?? (() => new Date()))().toISOString(),
    level: input.level,
    service: options.service,
    env: options.env,
    event: input.event,
    component: input.component,
    correlation_id: resolvedContext.correlation_id,
    request_id: resolvedContext.request_id,
    ...(input.message ? {message: input.message} : {}),
    ...(resolvedContext.tenant_id ? {tenant_id: resolvedContext.tenant_id} : {}),
    ...(resolvedContext.workload_id ? {workload_id: resolvedContext.workload_id} : {}),
    ...(resolvedContext.integration_id ? {integration_id: resolvedContext.integration_id} : {}),
    ...(input.reason_code ? {reason_code: input.reason_code} : {}),
    ...(input.duration_ms !== undefined ? {duration_ms: input.duration_ms} : {}),
    ...(input.status_code !== undefined ? {status_code: input.status_code} : {}),
    ...(resolvedContext.route ? {route: resolvedContext.route} : {}),
    ...(resolvedContext.method ? {method: resolvedContext.method} : {}),
    metadata: sanitizedMetadata
  });
};

const writeLine = ({
  line,
  level,
  writer
}: {
  line: string;
  level: EmittableLogLevel;
  writer: StructuredLogWriter;
}) => {
  const stream = chooseStream({level, writer});
  stream.write(`${line}\n`);
};

export const createStructuredLogger = (options: StructuredLoggerOptions): StructuredLogger => {
  const parsedOptions = {
    ...options,
    level: LogLevelSchema.parse(options.level),
    service: z.string().min(1).parse(options.service),
    env: z.string().min(1).parse(options.env),
    writer: options.writer ?? defaultWriter,
    extraSensitiveKeys: options.extraSensitiveKeys ?? []
  };

  const log = (rawInput: LogEventInput) => {
    const input = LogEventInputSchema.parse(rawInput);
    if (!shouldEmit({configuredLevel: parsedOptions.level, eventLevel: input.level})) {
      return;
    }

    try {
      const envelope = createEnvelope({
        input,
        options: parsedOptions,
        context: getLogContext()
      });
      writeLine({
        line: JSON.stringify(envelope),
        level: input.level,
        writer: parsedOptions.writer
      });
    } catch {
      // Logging failures must never break runtime behavior.
    }
  };

  return {
    log,
    debug: input => log({...input, level: 'debug'}),
    info: input => log({...input, level: 'info'}),
    warn: input => log({...input, level: 'warn'}),
    error: input => log({...input, level: 'error'}),
    fatal: input => log({...input, level: 'fatal'})
  };
};

export const createNoopLogger = (): StructuredLogger => ({
  log: () => undefined,
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  fatal: () => undefined
});
