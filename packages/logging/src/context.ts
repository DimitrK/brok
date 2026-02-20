import {AsyncLocalStorage} from 'node:async_hooks';

import {z} from 'zod';

export const LogContextSchema = z
  .object({
    correlation_id: z.string().min(1).max(128).optional(),
    request_id: z.string().min(1).max(128).optional(),
    tenant_id: z.string().min(1).optional(),
    workload_id: z.string().min(1).optional(),
    integration_id: z.string().min(1).optional(),
    route: z.string().min(1).optional(),
    method: z.string().min(1).optional()
  })
  .strict();

export type LogContext = z.infer<typeof LogContextSchema>;

const logContextStorage = new AsyncLocalStorage<LogContext>();

export const runWithLogContext = <T>(context: LogContext, operation: () => T): T => {
  const parsedContext = LogContextSchema.parse(context);
  return logContextStorage.run(parsedContext, operation);
};

export const getLogContext = (): LogContext | undefined => logContextStorage.getStore();

export const setLogContextFields = (partialContext: Partial<LogContext>): LogContext | undefined => {
  const currentContext = logContextStorage.getStore();
  if (!currentContext) {
    return undefined;
  }

  const parsedPartial = LogContextSchema.partial().parse(partialContext);
  const nextContext: LogContext = {
    ...currentContext,
    ...parsedPartial
  };

  Object.assign(currentContext, nextContext);
  return currentContext;
};
