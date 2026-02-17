import type {TLSSocket} from 'tls';

import {describe, expect, it, vi} from 'vitest';

import {createMtlsMiddleware} from '../middleware';

const createTlsSocket = ({
  remoteAddress = '10.10.10.10',
  cert
}: {
  remoteAddress?: string;
  cert: unknown;
}) =>
  ({
    authorized: true,
    authorizationError: undefined,
    remoteAddress,
    getPeerCertificate: () => cert
  }) as unknown as TLSSocket;

describe('middleware', () => {
  it('returns verifyMtls reason when mTLS principal validation fails', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.1'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => ({
        workloadId: 'w1',
        tenantId: 't1',
        enabled: true
      }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(setContext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({req, res, error: 'mtls_not_authorized'});
  });

  it('returns workload_disabled when workload lookup returns null', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => null,
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(setContext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({req, res, error: 'workload_disabled'});
  });

  it('returns workload_disabled when workload exists but is disabled', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => ({
        workloadId: 'w1',
        tenantId: 't1',
        enabled: false
      }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(setContext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({req, res, error: 'workload_disabled'});
  });

  it('allows IPv4-mapped addresses after normalization', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      remoteAddress: '::ffff:10.10.10.50',
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => ({
        workloadId: 'w1',
        tenantId: 't1',
        enabled: true,
        ipAllowlist: ['10.10.10.0/24']
      }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(onError).not.toHaveBeenCalled();
    expect(setContext).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('denies when allowlist contains malformed CIDR entries', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      remoteAddress: '10.10.10.50',
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => ({
        workloadId: 'w1',
        tenantId: 't1',
        enabled: true,
        ipAllowlist: ['10.10.10.0', '10.10.10.0/abc']
      }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(setContext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({req, res, error: 'workload_ip_denied'});
  });

  it('creates context when mTLS and workload checks pass', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => ({
        workloadId: 'w1',
        tenantId: 't1',
        enabled: true,
        ipAllowlist: ['10.10.10.0/24']
      }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(onError).not.toHaveBeenCalled();
    expect(setContext).toHaveBeenCalledWith({
      req,
      context: {
        tenantId: 't1',
        workloadId: 'w1',
        certFingerprint256: 'AA:BB:CC',
        sanUri: 'spiffe://tenant/workload-a'
      }
    });
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('fails closed when workload payload is malformed', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () =>
        ({workloadId: 'w1', enabled: true} as unknown as {
          workloadId: string;
          tenantId: string;
          enabled: boolean;
        }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(setContext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({req, res, error: 'workload_invalid'});
  });

  it('rejects requests from disallowed source IPs', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      remoteAddress: '192.168.10.50',
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => ({
        workloadId: 'w1',
        tenantId: 't1',
        enabled: true,
        ipAllowlist: ['10.10.10.0/24']
      }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(setContext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({req, res, error: 'workload_ip_denied'});
  });

  it('fails closed when source IP is unavailable but allowlist is configured', async () => {
    const req = {id: 'req-1'};
    const res = {id: 'res-1'};
    const socket = createTlsSocket({
      remoteAddress: '',
      cert: {
        subjectaltname: 'URI:spiffe://tenant/workload-a',
        ext_key_usage: ['1.3.6.1.5.5.7.3.2'],
        fingerprint256: 'AA:BB:CC'
      }
    });
    const setContext = vi.fn();
    const onError = vi.fn();
    const next = vi.fn();

    const middleware = createMtlsMiddleware({
      getTlsSocket: () => socket,
      loadWorkload: () => ({
        workloadId: 'w1',
        tenantId: 't1',
        enabled: true,
        ipAllowlist: ['10.10.10.0/24']
      }),
      setContext,
      onError
    });

    await middleware(req, res, next);

    expect(setContext).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({req, res, error: 'workload_ip_denied'});
  });
});
