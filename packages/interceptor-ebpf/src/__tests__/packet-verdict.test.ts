import {describe, expect, it} from 'vitest';

import {parseDataplanePacketEvent} from '../contracts/events.js';

describe('dataplane verdict events', () => {
  it('accepts enforce-mode dataplane verdict codes', () => {
    const parsed = parseDataplanePacketEvent({
      code_namespace: 'dataplane_verdict',
      reason_code: 'ALLOW_EXPLICIT',
      verdict: 'allow',
      hook: 'connect4'
    });

    expect(parsed.reason_code).toBe('ALLOW_EXPLICIT');
    expect(parsed.code_namespace).toBe('dataplane_verdict');
  });

  it('accepts observe-mode intent codes with would_block', () => {
    const parsed = parseDataplanePacketEvent({
      code_namespace: 'dataplane_verdict',
      reason_code: 'OBSERVE_WOULD_DENY_DEFAULT',
      verdict: 'allow',
      would_block: true,
      hook: 'sendmsg4'
    });

    expect(parsed.would_block).toBe(true);
  });

  it('rejects observe intent codes with verdict=deny', () => {
    const invalidEvent: unknown = {
      code_namespace: 'dataplane_verdict',
      reason_code: 'OBSERVE_WOULD_DENY_EXPLICIT',
      verdict: 'deny',
      would_block: true
    };

    expect(() => parseDataplanePacketEvent(invalidEvent)).toThrow();
  });

  it('rejects observe intent codes without would_block', () => {
    const invalidEvent: unknown = {
      code_namespace: 'dataplane_verdict',
      reason_code: 'OBSERVE_WOULD_ALLOW',
      verdict: 'allow'
    };

    expect(() => parseDataplanePacketEvent(invalidEvent)).toThrow();
  });

  it('rejects would_block on non-observe reason codes', () => {
    const invalidEvent: unknown = {
      code_namespace: 'dataplane_verdict',
      reason_code: 'DENY_DEFAULT',
      verdict: 'deny',
      would_block: true
    };

    expect(() => parseDataplanePacketEvent(invalidEvent)).toThrow();
  });

  it('rejects control-plane reason codes on dataplane events', () => {
    const invalidEvent: unknown = {
      code_namespace: 'dataplane_verdict',
      reason_code: 'CTRL_AUTH_SOCKET_OWNER_INVALID',
      verdict: 'deny'
    };

    expect(() => parseDataplanePacketEvent(invalidEvent)).toThrow();
  });
});
