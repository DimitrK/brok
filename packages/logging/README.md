# @broker-interceptor/logging

Structured logging primitives for broker runtime services.

## Scope

- JSON log envelope with stable top-level fields
- Request context propagation via AsyncLocalStorage
- Redaction-first metadata sanitation
- Non-throwing logging emit path

## Log Envelope

Required top-level fields:
- `ts`, `level`, `service`, `env`, `event`, `component`, `correlation_id`, `request_id`

Optional top-level fields:
- `tenant_id`, `workload_id`, `integration_id`, `reason_code`, `duration_ms`, `status_code`, `route`, `method`

All extra details are emitted under `metadata`.

## Default Redaction Policy

`sanitizeForLog` redacts values for keys that match sensitive families (case-insensitive), including:
- `token`, `secret`, `authorization`, `cookie`, `dpop`, `private_key`, `ciphertext`, `auth_tag`, and request/response body keys.

## Exports

- `LogLevelSchema`, `LogLevel`
- `LogContextSchema`, `LogContext`
- `LogEventInputSchema`, `LogEventInput`
- `createStructuredLogger(options)`
- `createNoopLogger()`
- `runWithLogContext(context, fn)`
- `getLogContext()`
- `setLogContextFields(partial)`
- `sanitizeForLog(value)`

## Usage

```ts
import {
  createStructuredLogger,
  runWithLogContext,
  setLogContextFields
} from '@broker-interceptor/logging';

const logger = createStructuredLogger({
  service: 'broker-api',
  env: 'production',
  level: 'info'
});

await runWithLogContext(
  {
    correlation_id: 'corr_1',
    request_id: 'req_1'
  },
  async () => {
    setLogContextFields({tenant_id: 't_1'});
    logger.info({
      event: 'request.received',
      component: 'http.server',
      message: 'request received'
    });
  }
);
```
