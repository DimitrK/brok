import type {TLSSocket} from 'tls';

import {peerCertificateSchema} from './contracts';
import type {WorkloadPrincipal} from './types';

const parseSanUris = (subjectAltName?: string) =>
  subjectAltName
    ? subjectAltName
        .split(',')
        .map(entry => entry.trim())
        .filter(entry => entry.startsWith('URI:'))
        .map(entry => entry.slice(4))
    : [];

const parseExtKeyUsage = (usage?: string | string[]) => {
  if (Array.isArray(usage)) {
    return usage.map(item => item.trim()).filter(Boolean);
  }

  return usage ? usage.split(',').map(item => item.trim()).filter(Boolean) : [];
};

const hasClientAuthUsage = (usage: string[]) => {
  const normalized = usage.map(item => item.toLowerCase());
  return (
    usage.includes('1.3.6.1.5.5.7.3.2') ||
    normalized.some(item => item.includes('client') && item.includes('auth'))
  );
};

export const extractWorkloadPrincipal = ({tlsSocket}: {tlsSocket: TLSSocket}): WorkloadPrincipal => {
  const parsedCert = peerCertificateSchema.safeParse(tlsSocket.getPeerCertificate());
  const cert = parsedCert.success ? parsedCert.data : {};
  const sanUris = parseSanUris(cert?.subjectaltname);
  const extKeyUsageOids = parseExtKeyUsage(cert?.ext_key_usage);
  const certFingerprint256 = cert?.fingerprint256 ?? null;
  const sanUri = sanUris.length === 1 ? sanUris[0] : null;

  return {
    sanUri,
    sanUriCount: sanUris.length,
    certFingerprint256,
    extKeyUsageOids,
    authorized: Boolean(tlsSocket.authorized) && hasClientAuthUsage(extKeyUsageOids),
    authorizationError:
      typeof tlsSocket.authorizationError === 'string'
        ? tlsSocket.authorizationError
        : tlsSocket.authorizationError
        ? String(tlsSocket.authorizationError.message || tlsSocket.authorizationError)
        : undefined
  };
};

export const verifyMtls = ({
  principal,
  expectedSanUriPrefix
}: {
  principal: WorkloadPrincipal;
  expectedSanUriPrefix?: string;
}): {ok: true} | {ok: false; error: string} => {
  if (!principal.authorized) {
    return {ok: false, error: principal.authorizationError || 'mtls_not_authorized'};
  }

  if (!principal.sanUri) {
    if (principal.sanUriCount > 1) {
      return {ok: false, error: 'san_uri_ambiguous'};
    }

    return {ok: false, error: 'san_uri_missing'};
  }

  if (!principal.certFingerprint256) {
    return {ok: false, error: 'fingerprint_missing'};
  }

  if (expectedSanUriPrefix && !principal.sanUri.startsWith(expectedSanUriPrefix)) {
    return {ok: false, error: 'san_uri_invalid'};
  }

  return {ok: true};
};
