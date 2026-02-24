import {describe, expect, it} from 'vitest';

import {parseEbpfInterceptorConfig, shouldFailClosedOnUnknownReasonCode} from '../config.js';
import {parseControlPlaneAuthzEvent, parseDataplanePacketEvent} from '../contracts/events.js';
import {parseControlProtocolResponse} from '../control/protocol.js';

describe('boundary validation is fail-closed for unknown reason codes', () => {
  it('rejects unknown dataplane reason codes', () => {
    const invalidEvent: unknown = {
      code_namespace: 'dataplane_verdict',
      reason_code: 'SOME_UNKNOWN_REASON_CODE',
      verdict: 'allow'
    };

    expect(() => parseDataplanePacketEvent(invalidEvent)).toThrow();
  });

  it('rejects unknown control-plane reason codes', () => {
    const invalidEvent: unknown = {
      code_namespace: 'control_authz',
      reason_code: 'CTRL_AUTH_UNKNOWN_CODE',
      message: 'bad peer'
    };

    expect(() => parseControlPlaneAuthzEvent(invalidEvent)).toThrow();
  });

  it('rejects unknown control protocol reason codes', () => {
    const invalidResponse: unknown = {
      ok: false,
      error: {
        code_namespace: 'control_authz',
        reason_code: 'CTRL_AUTH_UNKNOWN_CODE',
        message: 'bad peer'
      }
    };

    expect(() => parseControlProtocolResponse(invalidResponse)).toThrow();
  });

  it('enforces fail-closed mode in production even when rejectUnknownReasonCodes is false', () => {
    const config = parseEbpfInterceptorConfig({
      environment: 'production',
      rejectUnknownReasonCodes: false
    });

    expect(shouldFailClosedOnUnknownReasonCode(config)).toBe(true);
  });
});
