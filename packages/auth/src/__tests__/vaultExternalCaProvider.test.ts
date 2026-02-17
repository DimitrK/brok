/* eslint-disable @typescript-eslint/no-unsafe-assignment -- Tests use vi.stubGlobal('fetch') which causes type inference loss */
import {beforeEach, describe, expect, it, vi} from 'vitest';
import {createVaultExternalCaProvider} from '../vaultExternalCaProvider';

const VALID_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpqZNJX5MAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB1Rlc3Qg
Q0EwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjASMRAwDgYDVQQDDAdU
ZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdefghij
klmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn
opqrstuvwxyz==
-----END CERTIFICATE-----`;

describe('createVaultExternalCaProvider', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('throws when vaultAddr is missing', () => {
    expect(() =>
      createVaultExternalCaProvider({
        vaultAddr: '',
        vaultToken: 'token'
      })
    ).toThrow('vaultAddr is required');
  });

  it('throws when vaultToken is missing', () => {
    expect(() =>
      createVaultExternalCaProvider({
        vaultAddr: 'https://vault.example.com',
        vaultToken: ''
      })
    ).toThrow('vaultToken is required');
  });

  it('returns provider with issueEnrollment method', () => {
    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    expect(provider).toHaveProperty('issueEnrollment');
    expect(typeof provider.issueEnrollment).toBe('function');
  });

  it('fetches CA chain from vault on enrollment', async () => {
    const fetchSpy = vi.fn(() =>
      Promise.resolve({
        ok: true,
        headers: {get: () => null},
        text: () => Promise.resolve(VALID_CA_PEM)
      })
    );
    vi.stubGlobal('fetch', fetchSpy);

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com:8200',
      vaultToken: 's.testtoken',
      pkiMount: 'pki',
      requestTimeoutMs: 5000
    });

    const result = await provider.issueEnrollment({
      tenantId: 'tenant-123',
      workloadName: 'my-workload'
    });

    expect(result).toEqual({
      ok: true,
      value: {mtlsCaPem: VALID_CA_PEM}
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, options] = fetchSpy.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vault.example.com:8200/v1/pki/ca_chain');
    expect(options.method).toBe('GET');
    expect(options.headers).toEqual({
      'X-Vault-Token': 's.testtoken',
      Accept: 'application/x-pem-file'
    });
    expect(options.redirect).toBe('error');
  });

  it('normalizes vault address with trailing slash', async () => {
    const fetchSpy = vi.fn(() =>
      Promise.resolve({
        ok: true,
        headers: {get: () => null},
        text: () => Promise.resolve(VALID_CA_PEM)
      })
    );
    vi.stubGlobal('fetch', fetchSpy);

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com/',
      vaultToken: 'token'
    });

    await provider.issueEnrollment({tenantId: 't', workloadName: 'w'});

    const [url] = fetchSpy.mock.calls[0] as unknown as [string];
    expect(url).toBe('https://vault.example.com/v1/pki/ca_chain');
  });

  it('returns error when vault returns 403', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve({ok: false, status: 403}))
    );

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w'
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_enrollment_denied',
        message: expect.stringContaining('403')
      }
    });
  });

  it('returns error when vault returns 404', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve({ok: false, status: 404}))
    );

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w'
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: expect.stringContaining('not found')
      }
    });
  });

  it('returns error when CA chain is empty', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          headers: {get: () => null},
          text: () => Promise.resolve('')
        })
      )
    );

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w'
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: expect.stringContaining('empty')
      }
    });
  });

  it('returns error when response contains no certificate block', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          headers: {get: () => null},
          text: () => Promise.resolve('not a certificate')
        })
      )
    );

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w'
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: expect.stringContaining('valid certificate')
      }
    });
  });

  it('returns error when response contains private key', async () => {
    const pemWithPrivateKey = `${VALID_CA_PEM}
-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAT
-----END PRIVATE KEY-----`;

    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          headers: {get: () => null},
          text: () => Promise.resolve(pemWithPrivateKey)
        })
      )
    );

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w'
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: expect.stringContaining('private key')
      }
    });
  });

  it('returns error when fetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new Error('Network error')))
    );

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w'
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_unreachable',
        message: expect.stringContaining('connect')
      }
    });
  });

  it('respects abort signal', async () => {
    const controller = new AbortController();
    controller.abort();

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w',
      signal: controller.signal
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_unreachable',
        message: expect.stringContaining('aborted')
      }
    });
  });

  it('denies redirect attempts', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch: redirect')))
    );

    const provider = createVaultExternalCaProvider({
      vaultAddr: 'https://vault.example.com',
      vaultToken: 'token'
    });

    const result = await provider.issueEnrollment({
      tenantId: 't',
      workloadName: 'w'
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_unreachable',
        message: expect.stringContaining('redirect')
      }
    });
  });
});
