import {describe, expect, it} from 'vitest';

import {issueExternalCaEnrollment} from '../externalCa';
import type {ExternalCaEnrollmentProvider} from '../types';

const MTLS_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUd/N26R7S5lyQx31V6wAn7e5fMmUwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHYnJva2VyQ0EwHhcNMjYwMjA4MDAwMDAwWhcNMzYwMjA1MDAw
MDAwWjASMRAwDgYDVQQDDAdicm9rZXJDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNtvYzD0q8sfyQ6eU9lJ7o5x4NzhBfBY0l5fhp7v2NLxqjX9t2+6s2x+o5Qf
7A+7uQn+5m4h5W8HWSJ3Q2iR2f6jUzBRMB0GA1UdDgQWBBT2sJv7H+z5hMsl7m6h
H8ZrV9vQ2DAfBgNVHSMEGDAWgBT2sJv7H+z5hMsl7m6hH8ZrV9vQ2DAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDEm9v9E2fY6xZk2oE6rV+TLsJk
6d7kqHqk2J0QmUq3LQIhAL3w6M0xhs5JXn7u+6G5jGm4U5+q3M3QOqkT8Q3uJxYB
-----END CERTIFICATE-----`;

describe('issueExternalCaEnrollment', () => {
  it('fails closed when provider is not configured', async () => {
    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'}
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_not_configured',
        message: 'External CA enrollment provider is not configured'
      }
    });
  });

  it('fails closed when input payload is invalid', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({mtlsCaPem: MTLS_CA_PEM})
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: '', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: 'External CA provider returned an invalid response'
      }
    });
  });

  it('returns enrollment material when provider returns a raw output payload', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({
        mtlsCaPem: MTLS_CA_PEM,
        enrollmentReference: 'external-ref-1',
        ignored_field: 'value'
      })
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: true,
      value: {
        mtlsCaPem: MTLS_CA_PEM,
        enrollmentReference: 'external-ref-1'
      }
    });
  });

  it('returns enrollment material when provider returns result envelope', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({
        ok: true,
        value: {mtlsCaPem: MTLS_CA_PEM}
      })
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: true,
      value: {mtlsCaPem: MTLS_CA_PEM}
    });
  });

  it('maps provider connectivity failures to external_ca_unreachable', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => {
        throw new Error('dial tcp timeout');
      }
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_unreachable',
        message: 'External CA enrollment provider is unreachable'
      }
    });
  });

  it('maps provider timeouts to external_ca_unreachable', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: ({signal}) =>
        new Promise<never>((_, reject) => {
          signal?.addEventListener(
            'abort',
            () => {
              const error = new Error('timed out');
              error.name = 'AbortError';
              reject(error);
            },
            {once: true}
          );
        })
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider,
      timeoutMs: 5
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_unreachable',
        message: 'External CA enrollment provider is unreachable'
      }
    });
  });

  it('passes through stable provider denial codes', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({
        ok: false,
        error: {
          code: 'external_ca_enrollment_denied',
          message: 'Enrollment denied by external CA policy'
        }
      })
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_enrollment_denied',
        message: 'External CA enrollment request was denied'
      }
    });
  });

  it('maps thrown structured provider errors with known codes', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => {
        const error = new Error('Denied by provider');
        (error as Error & {code: string}).code = 'external_ca_enrollment_denied';
        throw error;
      }
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_enrollment_denied',
        message: 'External CA enrollment request was denied'
      }
    });
  });

  it('fails closed when provider returns unknown error code', async () => {
    const provider = {
      issueEnrollment: () => ({
        ok: false,
        error: {
          code: 'foo_unknown_code',
          message: 'Something happened'
        }
      })
    } as unknown as ExternalCaEnrollmentProvider;

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: 'External CA provider returned an invalid response'
      }
    });
  });

  it('fails closed when provider returns malformed certificate payload', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({mtlsCaPem: 'not-a-certificate'})
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: 'External CA provider returned an invalid response'
      }
    });
  });

  it('fails closed when provider returns private key material', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({
        mtlsCaPem: `${MTLS_CA_PEM}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----`
      })
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: 'External CA provider returned an invalid response'
      }
    });
  });

  it('fails closed when provider returns non-RSA private key material', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({
        mtlsCaPem: `${MTLS_CA_PEM}\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----`
      })
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: 'External CA provider returned an invalid response'
      }
    });
  });

  it('fails closed when mtlsCaPem exceeds maximum allowed size', async () => {
    const provider: ExternalCaEnrollmentProvider = {
      issueEnrollment: () => ({
        mtlsCaPem: `-----BEGIN CERTIFICATE-----\n${'A'.repeat(70_000)}\n-----END CERTIFICATE-----`
      })
    };

    const result = await issueExternalCaEnrollment({
      input: {tenantId: 'tenant-a', workloadName: 'workload-a'},
      provider
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'external_ca_profile_invalid',
        message: 'External CA provider returned an invalid response'
      }
    });
  });
});
