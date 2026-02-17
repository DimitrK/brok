import type {TLSSocket} from 'tls';

import {workloadRecordSchema} from './contracts';
import {extractWorkloadPrincipal, verifyMtls} from './principal';
import type {MtlsContext, WorkloadRecord} from './types';

export type MtlsMiddlewareDeps<Request, Response> = {
  getTlsSocket: (req: Request) => TLSSocket;
  loadWorkload: (input: {sanUri: string}) => Promise<WorkloadRecord | null> | WorkloadRecord | null;
  setContext: (input: {req: Request; context: MtlsContext}) => void;
  onError: (input: {req: Request; res: Response; error: string}) => void;
  expectedSanUriPrefix?: string;
  isIpAllowed?: (input: {ip: string; allowlist: string[]}) => boolean;
};

const normalizeRemoteIp = (ip: string) => {
  if (ip.startsWith('::ffff:')) {
    return ip.slice(7);
  }

  return ip;
};

const parseIpv4 = (ip: string) => {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return null;
  }

  const nums = parts.map(part => Number(part));
  if (nums.some(num => Number.isNaN(num) || num < 0 || num > 255)) {
    return null;
  }

  return nums.reduce((acc, num) => (acc << 8) + num, 0);
};

const matchesCidr = (ip: string, cidr: string) => {
  const [base, mask] = cidr.split('/');
  if (!base || !mask) {
    return false;
  }

  const baseNum = parseIpv4(base);
  const ipNum = parseIpv4(ip);
  const maskNum = Number(mask);
  if (baseNum === null || ipNum === null || Number.isNaN(maskNum)) {
    return false;
  }

  const maskBits = Math.max(0, Math.min(32, maskNum));
  const maskValue = maskBits === 0 ? 0 : ~((1 << (32 - maskBits)) - 1);
  return (ipNum & maskValue) === (baseNum & maskValue);
};

const isIpAllowedDefault = ({ip, allowlist}: {ip: string; allowlist: string[]}) => {
  const normalized = normalizeRemoteIp(ip);
  return allowlist.some(entry => (entry.includes('/') ? matchesCidr(normalized, entry) : entry === normalized));
};

export const createMtlsMiddleware = <Request, Response>({
  getTlsSocket,
  loadWorkload,
  setContext,
  onError,
  expectedSanUriPrefix,
  isIpAllowed = isIpAllowedDefault
}: MtlsMiddlewareDeps<Request, Response>) => {
  return async (req: Request, res: Response, next: (err?: unknown) => void) => {
    const principal = extractWorkloadPrincipal({tlsSocket: getTlsSocket(req)});
    const mtlsCheck = verifyMtls({principal, expectedSanUriPrefix});

    if (!mtlsCheck.ok || !principal.sanUri || !principal.certFingerprint256) {
      onError({req, res, error: mtlsCheck.ok ? 'mtls_invalid' : mtlsCheck.error});
      return;
    }

    const workloadRaw = await loadWorkload({sanUri: principal.sanUri});
    if (!workloadRaw) {
      onError({req, res, error: 'workload_disabled'});
      return;
    }

    const parsedWorkload = workloadRecordSchema.safeParse(workloadRaw);
    if (!parsedWorkload.success) {
      onError({req, res, error: 'workload_invalid'});
      return;
    }

    const workload = parsedWorkload.data;
    if (!workload.enabled) {
      onError({req, res, error: 'workload_disabled'});
      return;
    }

    const remoteAddress = getTlsSocket(req).remoteAddress;
    if (workload.ipAllowlist && workload.ipAllowlist.length > 0) {
      if (!remoteAddress) {
        onError({req, res, error: 'workload_ip_denied'});
        return;
      }

      const allowed = isIpAllowed({ip: remoteAddress, allowlist: workload.ipAllowlist});
      if (!allowed) {
        onError({req, res, error: 'workload_ip_denied'});
        return;
      }
    }

    setContext({
      req,
      context: {
        tenantId: workload.tenantId,
        workloadId: workload.workloadId,
        certFingerprint256: principal.certFingerprint256,
        sanUri: principal.sanUri
      }
    });

    next();
  };
};
