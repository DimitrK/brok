import {describe, expect, it} from 'vitest';

import {parseAndValidateCsr, validateCsrInfo} from '../enrollment';

describe('enrollment', () => {
  it('validateCsrInfo rejects SAN mismatches', () => {
    const result = validateCsrInfo({
      csrInfo: {sanUris: ['spiffe://tenant/workload-a'], extKeyUsageOids: ['1.3.6.1.5.5.7.3.2']},
      expectedSanUri: 'spiffe://tenant/workload-b',
      requireClientAuthEku: true
    });

    expect(result).toEqual({ok: false, error: 'csr_san_mismatch'});
  });

  it('validateCsrInfo rejects missing client auth EKU when required', () => {
    const result = validateCsrInfo({
      csrInfo: {sanUris: ['spiffe://tenant/workload-a'], extKeyUsageOids: ['1.3.6.1.5.5.7.3.1']},
      expectedSanUri: 'spiffe://tenant/workload-a',
      requireClientAuthEku: true
    });

    expect(result).toEqual({ok: false, error: 'csr_eku_missing'});
  });

  it('parseAndValidateCsr fails closed when parseCsr output is invalid', async () => {
    const result = await parseAndValidateCsr({
      csrPem: '---csr---',
      expectedSanUri: 'spiffe://tenant/workload-a',
      requireClientAuthEku: true,
      parseCsr: () =>
        ({sanUris: ['spiffe://tenant/workload-a']} as unknown as {
          sanUris: string[];
          extKeyUsageOids: string[];
        })
    });

    expect(result).toEqual({ok: false, error: 'csr_invalid'});
  });

  it('parseAndValidateCsr accepts valid CSR metadata', async () => {
    const result = await parseAndValidateCsr({
      csrPem: '---csr---',
      expectedSanUri: 'spiffe://tenant/workload-a',
      requireClientAuthEku: true,
      parseCsr: () => ({
        sanUris: ['spiffe://tenant/workload-a'],
        extKeyUsageOids: ['1.3.6.1.5.5.7.3.2']
      })
    });

    expect(result).toEqual({ok: true});
  });
});
