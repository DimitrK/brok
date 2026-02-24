import {describe, expect, it} from 'vitest';

import {parseDataplanePacketEvent} from '../contracts/events.js';
import {assertNoReasonCodeOverlap} from '../contracts/no-overlap.js';
import {parseControlProtocolResponse} from '../control/protocol.js';
import {controlPlaneAuthzErrorCodes} from '../contracts/control-authz-codes.js';
import {dataplaneVerdictReasonCodes} from '../contracts/reason-codes.js';

describe('reason code contracts', () => {
  it('keeps dataplane and control-plane code lists disjoint at runtime', () => {
    const overlap = dataplaneVerdictReasonCodes.filter(code =>
      (controlPlaneAuthzErrorCodes as readonly string[]).includes(code)
    );

    expect(overlap).toEqual([]);
  });

  it('assertNoReasonCodeOverlap does not throw', () => {
    expect(() => assertNoReasonCodeOverlap()).not.toThrow();
  });

  it('dataplane packet parser rejects control-plane reason codes', () => {
    const invalidEvent: unknown = {
      code_namespace: 'dataplane_verdict',
      reason_code: 'CTRL_AUTH_PEERCRED_UNAVAILABLE',
      verdict: 'deny'
    };

    expect(() => parseDataplanePacketEvent(invalidEvent)).toThrow();
  });

  it('control protocol failure parser rejects dataplane reason codes', () => {
    const invalidResponse: unknown = {
      ok: false,
      error: {
        code_namespace: 'control_authz',
        reason_code: 'DENY_DEFAULT',
        message: 'not allowed'
      }
    };

    expect(() => parseControlProtocolResponse(invalidResponse)).toThrow();
  });
});
