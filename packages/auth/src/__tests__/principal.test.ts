import type {TLSSocket} from 'tls';

import {describe, expect, it} from 'vitest';

import {extractWorkloadPrincipal, verifyMtls} from '../principal';

const createTlsSocket = ({
  authorized = true,
  authorizationError,
  cert
}: {
  authorized?: boolean;
  authorizationError?: unknown;
  cert: unknown;
}) =>
  ({
    authorized,
    authorizationError,
    getPeerCertificate: () => cert
  }) as unknown as TLSSocket;

describe('principal', () => {
  it('extractWorkloadPrincipal handles string EKU format and non-string authorization errors', () => {
    const principal = extractWorkloadPrincipal({
      tlsSocket: createTlsSocket({
        authorizationError: undefined,
        cert: {
          subjectaltname: 'URI:spiffe://tenant/workload-a',
          ext_key_usage: 'TLS Web Client Authentication',
          fingerprint256: 'AA:BB:CC'
        }
      })
    });

    expect(principal.authorized).toBe(true);
    expect(principal.extKeyUsageOids).toEqual(['TLS Web Client Authentication']);
  });

  it('extractWorkloadPrincipal stringifies non-string authorization errors', () => {
    const principal = extractWorkloadPrincipal({
      tlsSocket: createTlsSocket({
        authorized: false,
        authorizationError: {message: 'bad certificate state'},
        cert: {
          subjectaltname: 'URI:spiffe://tenant/workload-a',
          ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
          fingerprint256: 'AA:BB:CC'
        }
      })
    });

    expect(principal.authorizationError).toBe('bad certificate state');
  });

  it('extractWorkloadPrincipal reads SAN URI, EKU, and fingerprint from certificate', () => {
    const principal = extractWorkloadPrincipal({
      tlsSocket: createTlsSocket({
        cert: {
          subjectaltname: 'URI:spiffe://tenant/workload-a,DNS:ignored.example.com',
          ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
          fingerprint256: 'AA:BB:CC'
        }
      })
    });

    expect(principal).toEqual({
      sanUri: 'spiffe://tenant/workload-a',
      sanUriCount: 1,
      certFingerprint256: 'AA:BB:CC',
      extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'],
      authorized: true,
      authorizationError: undefined
    });
  });

  it('extractWorkloadPrincipal fails closed on malformed certificate shapes', () => {
    const principal = extractWorkloadPrincipal({
      tlsSocket: createTlsSocket({
        cert: {
          subjectaltname: 42,
          ext_key_usage: {oid: '1.3.6.1.5.5.7.3.2'}
        }
      })
    });

    expect(principal.sanUri).toBeNull();
    expect(principal.sanUriCount).toBe(0);
    expect(principal.certFingerprint256).toBeNull();
    expect(principal.extKeyUsageOids).toEqual([]);
  });

  it('verifyMtls rejects ambiguous SAN URIs', () => {
    const result = verifyMtls({
      principal: {
        sanUri: null,
        sanUriCount: 2,
        certFingerprint256: 'AA:BB:CC',
        extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'],
        authorized: true
      }
    });

    expect(result).toEqual({ok: false, error: 'san_uri_ambiguous'});
  });

  it('verifyMtls rejects unauthorized principals with default reason', () => {
    const result = verifyMtls({
      principal: {
        sanUri: 'spiffe://tenant/workload-a',
        sanUriCount: 1,
        certFingerprint256: 'AA:BB:CC',
        extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'],
        authorized: false
      }
    });

    expect(result).toEqual({ok: false, error: 'mtls_not_authorized'});
  });

  it('verifyMtls returns explicit authorization errors when present', () => {
    const result = verifyMtls({
      principal: {
        sanUri: 'spiffe://tenant/workload-a',
        sanUriCount: 1,
        certFingerprint256: 'AA:BB:CC',
        extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'],
        authorized: false,
        authorizationError: 'CERT_REVOKED'
      }
    });

    expect(result).toEqual({ok: false, error: 'CERT_REVOKED'});
  });

  it('verifyMtls rejects missing SAN URI', () => {
    const result = verifyMtls({
      principal: {
        sanUri: null,
        sanUriCount: 0,
        certFingerprint256: 'AA:BB:CC',
        extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'],
        authorized: true
      }
    });

    expect(result).toEqual({ok: false, error: 'san_uri_missing'});
  });

  it('verifyMtls rejects missing certificate fingerprint', () => {
    const result = verifyMtls({
      principal: {
        sanUri: 'spiffe://tenant/workload-a',
        sanUriCount: 1,
        certFingerprint256: null,
        extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'],
        authorized: true
      }
    });

    expect(result).toEqual({ok: false, error: 'fingerprint_missing'});
  });

  it('verifyMtls rejects SAN URIs outside expected prefix', () => {
    const result = verifyMtls({
      principal: {
        sanUri: 'spiffe://tenant-b/workload-a',
        sanUriCount: 1,
        certFingerprint256: 'AA:BB:CC',
        extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'],
        authorized: true
      },
      expectedSanUriPrefix: 'spiffe://tenant-a/'
    });

    expect(result).toEqual({ok: false, error: 'san_uri_invalid'});
  });
});
