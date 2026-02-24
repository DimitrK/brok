import {describe, expect, it} from 'vitest';

import {parseControlPlaneAuthzEvent} from '../contracts/events.js';
import {parseControlProtocolResponse} from '../control/protocol.js';
import {
  serializeControlPlaneAuthzErrorToLog,
  serializeDataplanePacketEventToLog
} from '../observability/serialization.js';

describe('observability serialization', () => {
  it('serializes dataplane events with explicit dataplane namespace', () => {
    const serialized = serializeDataplanePacketEventToLog({
      code_namespace: 'dataplane_verdict',
      reason_code: 'DENY_DEFAULT',
      verdict: 'deny',
      hook: 'connect6'
    });

    expect(serialized.code_namespace).toBe('dataplane_verdict');
    expect(serialized.reason_code).toBe('DENY_DEFAULT');
    expect('verdict' in serialized).toBe(true);
  });

  it('serializes control authz errors with explicit control namespace', () => {
    const serialized = serializeControlPlaneAuthzErrorToLog({
      code_namespace: 'control_authz',
      reason_code: 'CTRL_AUTH_PEERCRED_REJECTED_UID',
      message: 'peer uid is not authorized'
    });

    expect(serialized.code_namespace).toBe('control_authz');
    expect(serialized.reason_code).toBe('CTRL_AUTH_PEERCRED_REJECTED_UID');
    expect('verdict' in (serialized as Record<string, unknown>)).toBe(false);
    expect('would_block' in (serialized as Record<string, unknown>)).toBe(false);
  });

  it('rejects control protocol errors that include dataplane-only fields', () => {
    const invalidResponse: unknown = {
      ok: false,
      error: {
        code_namespace: 'control_authz',
        reason_code: 'CTRL_AUTH_SOCKET_MODE_INVALID',
        message: 'invalid mode',
        verdict: 'deny',
        would_block: true
      }
    };

    expect(() => parseControlProtocolResponse(invalidResponse)).toThrow();
  });

  it('rejects control authz events with dataplane-only fields', () => {
    const invalidEvent: unknown = {
      code_namespace: 'control_authz',
      reason_code: 'CTRL_AUTH_SOCKET_MODE_INVALID',
      message: 'invalid mode',
      verdict: 'deny'
    };

    expect(() => parseControlPlaneAuthzEvent(invalidEvent)).toThrow();
  });
});
