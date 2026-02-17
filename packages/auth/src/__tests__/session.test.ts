import {describe, expect, it} from 'vitest';

import {createOpaqueToken, issueSession, SessionInputValidationError, verifySessionBinding} from '../session';

const VALID_DPOP_JKT = 'A'.repeat(43);
const baseIssueInput = {
  workloadId: 'w1',
  tenantId: 't1',
  certFingerprint256: 'fp',
  ttlSeconds: 60,
  now: new Date(0)
};

describe('session', () => {
  it('issueSession binds to cert fingerprint', () => {
    const result = issueSession(baseIssueInput);

    expect(result.session.certFingerprint256).toBe('fp');
  });

  it('issueSession rejects ttl outside OpenAPI bounds', () => {
    expect(() => issueSession({...baseIssueInput, ttlSeconds: 59})).toThrowError(SessionInputValidationError);
    expect(() => issueSession({...baseIssueInput, ttlSeconds: 59})).toThrowError('session_ttl_invalid');
    expect(() => issueSession({...baseIssueInput, ttlSeconds: 3601})).toThrowError('session_ttl_invalid');
    expect(() =>
      issueSession({...baseIssueInput, ttlSeconds: undefined as unknown as number})
    ).toThrowError('session_ttl_invalid');
  });

  it('issueSession rejects weak token byte sizes', () => {
    expect(() => issueSession({...baseIssueInput, tokenBytes: 16})).toThrowError('session_token_bytes_invalid');
    expect(() => issueSession({...baseIssueInput, tokenBytes: 65})).toThrowError('session_token_bytes_invalid');
  });

  it('createOpaqueToken enforces token entropy bounds', () => {
    expect(() => createOpaqueToken({bytes: 8})).toThrowError('session_token_bytes_invalid');
    expect(() => createOpaqueToken({bytes: 128})).toThrowError('session_token_bytes_invalid');
  });

  it('issueSession rejects malformed dpop thumbprints', () => {
    expect(() => issueSession({...baseIssueInput, dpopKeyThumbprint: 'bad-thumbprint'})).toThrowError(
      'session_dpop_jkt_invalid'
    );
  });

  it('verifySessionBinding rejects mismatch', () => {
    const {session} = issueSession(baseIssueInput);

    const result = verifySessionBinding({
      session,
      certFingerprint256: 'other',
      now: new Date(0)
    });

    expect(result.ok).toBe(false);
  });

  it('verifySessionBinding requires matching dpop thumbprint when session is dpop-bound', () => {
    const {session} = issueSession({
      ...baseIssueInput,
      dpopKeyThumbprint: VALID_DPOP_JKT
    });

    const missing = verifySessionBinding({
      session,
      certFingerprint256: 'fp',
      now: new Date(0)
    });
    expect(missing).toEqual({ok: false, error: 'session_dpop_required'});

    const mismatch = verifySessionBinding({
      session,
      certFingerprint256: 'fp',
      dpopKeyThumbprint: 'B'.repeat(43),
      now: new Date(0)
    });
    expect(mismatch).toEqual({ok: false, error: 'session_dpop_mismatch'});

    const ok = verifySessionBinding({
      session,
      certFingerprint256: 'fp',
      dpopKeyThumbprint: VALID_DPOP_JKT,
      now: new Date(0)
    });
    expect(ok).toEqual({ok: true});
  });
});
