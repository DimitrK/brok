import {parsedCsrSchema} from './contracts';
import type {ParsedCsr} from './types';

const hasClientAuthEku = (oids: string[]) => {
  const lowered = oids.map(item => item.toLowerCase());
  return (
    oids.includes('1.3.6.1.5.5.7.3.2') ||
    lowered.some(item => item.includes('client') && item.includes('auth'))
  );
};

export const validateCsrInfo = ({
  csrInfo,
  expectedSanUri,
  requireClientAuthEku
}: {
  csrInfo: ParsedCsr;
  expectedSanUri: string;
  requireClientAuthEku: boolean;
}) => {
  const uriMatch = csrInfo.sanUris.includes(expectedSanUri);
  if (!uriMatch) {
    return {ok: false, error: 'csr_san_mismatch'};
  }

  if (requireClientAuthEku && !hasClientAuthEku(csrInfo.extKeyUsageOids)) {
    return {ok: false, error: 'csr_eku_missing'};
  }

  return {ok: true};
};

export const parseAndValidateCsr = async ({
  csrPem,
  expectedSanUri,
  requireClientAuthEku,
  parseCsr
}: {
  csrPem: string;
  expectedSanUri: string;
  requireClientAuthEku: boolean;
  parseCsr: (csrPem: string) => Promise<ParsedCsr> | ParsedCsr;
}) => {
  const csrInfoRaw = await parseCsr(csrPem);
  const parsedCsr = parsedCsrSchema.safeParse(csrInfoRaw);
  if (!parsedCsr.success) {
    return {ok: false, error: 'csr_invalid'};
  }

  return validateCsrInfo({csrInfo: parsedCsr.data, expectedSanUri, requireClientAuthEku});
};
