import crypto from 'crypto';

import {describe, expect, it} from 'vitest';

import {
  calculateJwkThumbprint,
  normalizeHtu,
  verifyBoundDpopProofJwt,
  verifyDpopClaimsOnly,
  verifyDpopProofJwt
} from '../dpop';
import type {JtiStore} from '../types';

const toBase64Url = (value: Buffer) =>
  value
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const encodeJson = (value: unknown) => toBase64Url(Buffer.from(JSON.stringify(value), 'utf8'));

const signInput = ({
  alg,
  input,
  privateKey
}: {
  alg: string;
  input: string;
  privateKey: crypto.KeyObject;
}) => {
  const data = Buffer.from(input, 'ascii');
  if (alg === 'ES256') {
    return crypto.sign('sha256', data, {key: privateKey, dsaEncoding: 'ieee-p1363'});
  }

  if (alg === 'EdDSA') {
    return crypto.sign(null, data, privateKey);
  }

  throw new Error(`unsupported test alg: ${alg}`);
};

const createDpopJwt = ({
  method,
  htu,
  iat,
  jti,
  alg = 'ES256',
  accessToken
}: {
  method: string;
  htu: string;
  iat: number;
  jti: string;
  alg?: 'ES256' | 'EdDSA';
  accessToken?: string;
}) => {
  const keyPair =
    alg === 'ES256'
      ? crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'})
      : crypto.generateKeyPairSync('ed25519');

  const publicJwk = keyPair.publicKey.export({format: 'jwk'}) as Record<string, unknown>;
  const header = {alg, typ: 'dpop+jwt', jwk: publicJwk};

  const payload: Record<string, unknown> = {
    htm: method,
    htu,
    iat,
    jti
  };

  if (accessToken) {
    payload.ath = toBase64Url(crypto.createHash('sha256').update(accessToken, 'utf8').digest());
  }

  const encodedHeader = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signInput({alg, input: signingInput, privateKey: keyPair.privateKey});

  return {
    jwt: `${signingInput}.${toBase64Url(signature)}`,
    publicJwk
  };
};

const createReplayStoreFake = (): JtiStore => {
  const entries = new Set<string>();
  return {
    // Minimal in-memory fake for replay semantics: first use accepts, repeats reject.
    checkAndStore: jti => {
      if (entries.has(jti)) {
        return false;
      }
      entries.add(jti);
      return true;
    }
  };
};

const splitJwt = (jwt: string): [string, string, string] => {
  const jwtParts = jwt.split('.');
  expect(jwtParts).toHaveLength(3);
  return jwtParts as [string, string, string];
};

describe('dpop', () => {
  it('normalizeHtu strips query and fragment', () => {
    const normalized = normalizeHtu('https://example.com/path?x=1#hash');
    expect(normalized).toBe('https://example.com/path');
  });

  it('normalizeHtu rejects non-http(s) schemes and userinfo', () => {
    expect(() => normalizeHtu('ftp://example.com/path')).toThrowError();
    expect(() => normalizeHtu('https://user:password@example.com/path')).toThrowError();
  });

  it('verifyDpopClaims validates method and htu', async () => {
    const payload = {htm: 'POST', htu: 'https://example.com/execute?x=1', iat: 1000, jti: 'a'};
    const result = await verifyDpopClaimsOnly({
      payload,
      method: 'POST',
      url: 'https://example.com/execute?y=2',
      now: new Date(1000 * 1000),
      maxSkewSeconds: 10
    });

    expect(result.ok).toBe(true);
  });

  it('verifyDpopClaims accepts RFC token-compatible methods', async () => {
    const payload = {htm: 'M-SEARCH', htu: 'https://example.com/execute?x=1', iat: 1000, jti: 'method-token'};
    const result = await verifyDpopClaimsOnly({
      payload,
      method: 'm-search',
      url: 'https://example.com/execute?y=2',
      now: new Date(1000 * 1000),
      maxSkewSeconds: 10
    });

    expect(result.ok).toBe(true);
  });

  it('scopes replay detection by replayScope when provided', async () => {
    const payload = {htm: 'POST', htu: 'https://example.com/execute', iat: 1000, jti: 'shared-jti'};
    const jtiStore = createReplayStoreFake();

    const firstScopeA = await verifyDpopClaimsOnly({
      payload,
      method: 'POST',
      url: 'https://example.com/execute',
      now: new Date(1000 * 1000),
      maxSkewSeconds: 10,
      jtiStore,
      replayScope: 'scope-a'
    });
    expect(firstScopeA.ok).toBe(true);

    const firstScopeB = await verifyDpopClaimsOnly({
      payload,
      method: 'POST',
      url: 'https://example.com/execute',
      now: new Date(1000 * 1000),
      maxSkewSeconds: 10,
      jtiStore,
      replayScope: 'scope-b'
    });
    expect(firstScopeB.ok).toBe(true);

    const secondScopeA = await verifyDpopClaimsOnly({
      payload,
      method: 'POST',
      url: 'https://example.com/execute',
      now: new Date(1000 * 1000),
      maxSkewSeconds: 10,
      jtiStore,
      replayScope: 'scope-a'
    });
    expect(secondScopeA).toEqual({ok: false, error: 'dpop_replay'});
  });

  it('verifyDpopProofJwt validates signature and claims and returns jkt', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt, publicJwk} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute?x=1',
      iat,
      jti: 'proof-1'
    });
    const expectedJkt = await calculateJwkThumbprint(publicJwk);
    expect(expectedJkt).not.toBeNull();

    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute?y=2',
      now,
      expectedJkt: expectedJkt ?? undefined
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.jkt).toBe(expectedJkt);
    }
  });

  it('verifyDpopProofJwt rejects malformed jwt', async () => {
    const result = await verifyDpopProofJwt({
      dpopJwt: 'not-a-jwt',
      method: 'POST',
      url: 'https://broker.example/v1/execute'
    });

    expect(result).toEqual({ok: false, error: 'dpop_malformed_jwt'});
  });

  it('verifyDpopProofJwt rejects forbidden alg', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt, publicJwk} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-forbidden-alg'
    });
    const [, payload, signature] = splitJwt(jwt);
    const badHeader = encodeJson({
      alg: 'HS256',
      typ: 'dpop+jwt',
      jwk: publicJwk
    });
    const badJwt = `${badHeader}.${payload}.${signature}`;

    const result = await verifyDpopProofJwt({
      dpopJwt: badJwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_alg_forbidden'});
  });

  it('verifyDpopProofJwt rejects missing or invalid jwk header', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-jwk-missing'
    });
    const [, payload, signature] = splitJwt(jwt);
    const badHeader = encodeJson({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: 'not-an-object'
    });
    const badJwt = `${badHeader}.${payload}.${signature}`;

    const result = await verifyDpopProofJwt({
      dpopJwt: badJwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_jwk_missing'});
  });

  it('verifyDpopProofJwt rejects private jwk material in header', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt, publicJwk} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-jwk-private'
    });
    const [, payload, signature] = splitJwt(jwt);
    const badHeader = encodeJson({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: {...publicJwk, d: 'private-key-material'}
    });
    const badJwt = `${badHeader}.${payload}.${signature}`;

    const result = await verifyDpopProofJwt({
      dpopJwt: badJwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_jwk_private'});
  });

  it('verifyDpopProofJwt rejects thumbprint calculation failures', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-jwk-thumbprint'
    });
    const [, payload, signature] = splitJwt(jwt);
    const badHeader = encodeJson({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: {}
    });
    const badJwt = `${badHeader}.${payload}.${signature}`;

    const result = await verifyDpopProofJwt({
      dpopJwt: badJwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_jwk_thumbprint_failed'});
  });

  it('verifyDpopProofJwt rejects jkt mismatch', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-jkt-mismatch'
    });

    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      expectedJkt: toBase64Url(crypto.randomBytes(32))
    });

    expect(result).toEqual({ok: false, error: 'dpop_jkt_mismatch'});
  });

  it('verifyDpopProofJwt rejects malformed expected jkt input', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-jkt-invalid'
    });

    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      expectedJkt: 'not-a-valid-thumbprint'
    });

    expect(result).toEqual({ok: false, error: 'dpop_jkt_invalid'});
  });

  it('verifyDpopProofJwt rejects tampered signatures', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-signature-invalid'
    });
    const [header, payload, signature] = splitJwt(jwt);
    // Mutate a significant base64url position; trailing chars may include ignored bits.
    const tamperedSignature = `${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`;
    const tamperedJwt = `${header}.${payload}.${tamperedSignature}`;

    const result = await verifyDpopProofJwt({
      dpopJwt: tamperedJwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_signature_invalid'});
  });

  it('verifyDpopProofJwt surfaces claims-level mismatches', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-method-mismatch'
    });

    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'GET',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_method_mismatch'});
  });

  it('verifyDpopProofJwt rejects iat outside allowed skew', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const staleIat = Math.floor(now.getTime() / 1000) - 3600;
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat: staleIat,
      jti: 'proof-iat-skew'
    });

    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      maxSkewSeconds: 30
    });

    expect(result).toEqual({ok: false, error: 'dpop_iat_skew'});
  });

  it('verifyDpopProofJwt rejects invalid htu claim format', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'not-a-valid-url',
      iat,
      jti: 'proof-htu-invalid'
    });
    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_htu_invalid'});
  });

  it('verifyDpopProofJwt rejects invalid verifier method input', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-method-input-invalid'
    });

    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST /evil',
      url: 'https://broker.example/v1/execute',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_method_invalid'});
  });

  it('verifyDpopProofJwt rejects bad typ', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt, publicJwk} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/session',
      iat,
      jti: 'proof-2'
    });
    const [header, payload, signature] = splitJwt(jwt);
    const badHeader = encodeJson({
      alg: 'ES256',
      typ: 'jwt',
      jwk: publicJwk
    });
    const badJwt = `${badHeader}.${payload}.${signature}`;
    expect(header).toBeDefined();

    const result = await verifyDpopProofJwt({
      dpopJwt: badJwt,
      method: 'POST',
      url: 'https://broker.example/v1/session',
      now
    });

    expect(result).toEqual({ok: false, error: 'dpop_bad_typ'});
  });

  it('verifyDpopProofJwt enforces ath when access token is provided', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const accessToken = 'bk_sess_v1_token';
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-3'
    });

    const missingAthResult = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      accessToken
    });
    expect(missingAthResult).toEqual({ok: false, error: 'dpop_ath_missing'});

    const withAth = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-4',
      accessToken
    });
    const okResult = await verifyDpopProofJwt({
      dpopJwt: withAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      accessToken
    });
    expect(okResult.ok).toBe(true);

    const mismatch = await verifyDpopProofJwt({
      dpopJwt: withAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      accessToken: 'different-token'
    });
    expect(mismatch).toEqual({ok: false, error: 'dpop_ath_mismatch'});
  });

  it('verifyBoundDpopProofJwt requires ath and expected jkt for bound sessions', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const accessToken = 'bk_sess_v1_token';
    const jtiStore = createReplayStoreFake();
    const withAth = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-bound-1',
      accessToken
    });
    const expectedJkt = await calculateJwkThumbprint(withAth.publicJwk);
    expect(expectedJkt).toBeTruthy();

    const success = await verifyBoundDpopProofJwt({
      dpopJwt: withAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      expectedJkt: expectedJkt ?? '',
      accessToken,
      jtiStore
    });
    expect(success.ok).toBe(true);

    const withoutAth = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-bound-2'
    });
    const withoutAthJkt = await calculateJwkThumbprint(withoutAth.publicJwk);
    expect(withoutAthJkt).toBeTruthy();
    const missingAth = await verifyBoundDpopProofJwt({
      dpopJwt: withoutAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      expectedJkt: withoutAthJkt ?? '',
      accessToken,
      jtiStore
    });
    expect(missingAth).toEqual({ok: false, error: 'dpop_ath_missing'});
  });

  it('verifyBoundDpopProofJwt fails closed when replay store is missing', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const accessToken = 'bk_sess_v1_token';
    const withAth = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-bound-missing-store',
      accessToken
    });
    const expectedJkt = await calculateJwkThumbprint(withAth.publicJwk);
    expect(expectedJkt).toBeTruthy();

    const result = await verifyBoundDpopProofJwt({
      dpopJwt: withAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      expectedJkt: expectedJkt ?? '',
      accessToken
    } as unknown as Parameters<typeof verifyBoundDpopProofJwt>[0]);
    expect(result).toEqual({ok: false, error: 'dpop_replay_store_required'});
  });

  it('verifyDpopProofJwt rejects invalid replay scope', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-replay-scope-invalid'
    });

    const result = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      replayScope: ' '
    });
    expect(result).toEqual({ok: false, error: 'dpop_replay_scope_invalid'});
  });

  it('verifyDpopProofJwt does not consume replay entries when ath validation fails', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const accessToken = 'bk_sess_v1_token';
    const replayScope = 'tenant-1:session-ath-scope';
    const jtiStore = createReplayStoreFake();

    const withoutAth = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'ath-replay-jti'
    });
    const missingAth = await verifyDpopProofJwt({
      dpopJwt: withoutAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      accessToken,
      jtiStore,
      replayScope
    });
    expect(missingAth).toEqual({ok: false, error: 'dpop_ath_missing'});

    const withAth = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'ath-replay-jti',
      accessToken
    });
    const acceptedAfterAthFailure = await verifyDpopProofJwt({
      dpopJwt: withAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      accessToken,
      jtiStore,
      replayScope
    });
    expect(acceptedAfterAthFailure.ok).toBe(true);

    const replayAfterSuccess = await verifyDpopProofJwt({
      dpopJwt: withAth.jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      accessToken,
      jtiStore,
      replayScope
    });
    expect(replayAfterSuccess).toEqual({ok: false, error: 'dpop_replay'});
  });

  it('verifyDpopProofJwt detects replay when jti store is provided', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'proof-5'
    });
    const jtiStore = createReplayStoreFake();

    const first = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      jtiStore
    });
    expect(first.ok).toBe(true);

    const second = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      jtiStore
    });
    expect(second).toEqual({ok: false, error: 'dpop_replay'});
  });

  it('verifyDpopProofJwt isolates replay by tenant/session scope', async () => {
    const now = new Date('2026-02-05T00:00:00.000Z');
    const iat = Math.floor(now.getTime() / 1000);
    const {jwt, publicJwk} = createDpopJwt({
      method: 'POST',
      htu: 'https://broker.example/v1/execute',
      iat,
      jti: 'shared-jti-scope'
    });
    const expectedJkt = await calculateJwkThumbprint(publicJwk);
    expect(expectedJkt).not.toBeNull();

    const jtiStore = createReplayStoreFake();
    const firstSession = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      jtiStore,
      tenantId: 'tenant-1',
      sessionId: 'session-a',
      expectedJkt: expectedJkt ?? undefined
    });
    expect(firstSession.ok).toBe(true);

    const secondSessionSameTenant = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      jtiStore,
      tenantId: 'tenant-1',
      sessionId: 'session-b',
      expectedJkt: expectedJkt ?? undefined
    });
    expect(secondSessionSameTenant.ok).toBe(true);

    const replaySameSession = await verifyDpopProofJwt({
      dpopJwt: jwt,
      method: 'POST',
      url: 'https://broker.example/v1/execute',
      now,
      jtiStore,
      tenantId: 'tenant-1',
      sessionId: 'session-a',
      expectedJkt: expectedJkt ?? undefined
    });
    expect(replaySameSession).toEqual({ok: false, error: 'dpop_replay'});
  });
});
