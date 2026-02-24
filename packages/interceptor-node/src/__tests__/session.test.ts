import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';

import {SessionManager, canCreateSessionManager} from '../session.js';

function createLogger() {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  };
}

function createMtlsFiles(): {certPath: string; keyPath: string; cleanup: () => void} {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'session-manager-test-'));
  const certPath = path.join(dir, 'workload.crt');
  const keyPath = path.join(dir, 'workload.key');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.writeFileSync(certPath, 'cert');
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.writeFileSync(keyPath, 'key');
  return {
    certPath,
    keyPath,
    cleanup: () => {
      fs.rmSync(dir, {recursive: true, force: true});
    }
  };
}

describe('SessionManager', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('parses valid session response and returns token', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi.fn().mockResolvedValue({
      status: 200,
      body: JSON.stringify({
        session_token: 'sess_1',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        bound_cert_thumbprint: 'sha256:test'
      })
    });

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath
        },
        logger,
        requestImpl
      );

      const token = await manager.getToken();
      expect(token).toBe('sess_1');
      expect(manager.hasValidToken()).toBe(true);
      expect(requestImpl).toHaveBeenCalledTimes(1);
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('fails when session payload does not match OpenAPI schema', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi.fn().mockResolvedValue({
      status: 200,
      body: JSON.stringify({
        session_token: 'sess_1'
      })
    });

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath
        },
        logger,
        requestImpl
      );

      await expect(manager.getToken()).rejects.toThrow('Session response failed schema validation');
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('fails when session payload is not valid JSON', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi.fn().mockResolvedValue({
      status: 200,
      body: '{'
    });

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath
        },
        logger,
        requestImpl
      );

      await expect(manager.getToken()).rejects.toThrow('Session response is not valid JSON');
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('schedules token refresh and updates token on success', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi
      .fn()
      .mockResolvedValueOnce({
        status: 200,
        body: JSON.stringify({
          session_token: 'sess_1',
          expires_at: new Date(Date.now() + 2_000).toISOString(),
          bound_cert_thumbprint: 'sha256:test'
        })
      })
      .mockResolvedValueOnce({
        status: 200,
        body: JSON.stringify({
          session_token: 'sess_2',
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          bound_cert_thumbprint: 'sha256:test'
        })
      });

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath,
          refreshThreshold: 0.5
        },
        logger,
        requestImpl
      );

      expect(await manager.getToken()).toBe('sess_1');
      await vi.advanceTimersByTimeAsync(1_100);

      expect(requestImpl).toHaveBeenCalledTimes(2);
      expect(await manager.getToken()).toBe('sess_2');
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('returns the same in-flight promise for concurrent getToken calls', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    let resolveRequest: (value: {status: number; body: string}) => void = () => {
      throw new Error('resolver not initialized');
    };
    const requestImpl = vi.fn(
      () =>
        new Promise<{status: number; body: string}>(resolve => {
          resolveRequest = resolve;
        })
    );

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath
        },
        logger,
        requestImpl
      );

      const firstPromise = manager.getToken();
      const secondPromise = manager.getToken();
      expect(requestImpl).toHaveBeenCalledTimes(1);

      resolveRequest({
        status: 200,
        body: JSON.stringify({
          session_token: 'sess_shared',
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          bound_cert_thumbprint: 'sha256:test'
        })
      });

      const [first, second] = await Promise.all([firstPromise, secondPromise]);
      expect(first).toBe('sess_shared');
      expect(second).toBe('sess_shared');
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('logs refresh failure deterministically in background refresh', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi
      .fn()
      .mockResolvedValueOnce({
        status: 200,
        body: JSON.stringify({
          session_token: 'sess_1',
          expires_at: new Date(Date.now() + 2_000).toISOString(),
          bound_cert_thumbprint: 'sha256:test'
        })
      })
      .mockResolvedValueOnce({
        status: 500,
        body: 'internal'
      });

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath,
          refreshThreshold: 0.5
        },
        logger,
        requestImpl
      );

      await manager.getToken();
      await vi.advanceTimersByTimeAsync(1_100);

      expect(logger.error).toHaveBeenCalled();
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('includes mTLS guidance for 401 mtls_required errors', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi.fn().mockResolvedValue({
      status: 401,
      body: '{"error":"mtls_required"}'
    });

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath
        },
        logger,
        requestImpl
      );

      await expect(manager.getToken()).rejects.toThrow('BROKER_API_TLS_REQUIRE_CLIENT_CERT=true');
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('loads optional CA file and exposes it in credentials', () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const caPath = path.join(path.dirname(certPath), 'ca.pem');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    fs.writeFileSync(caPath, 'ca');
    const logger = createLogger();

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath,
          mtlsCaPath: caPath
        },
        logger,
        () =>
          Promise.resolve({
            status: 200,
            body: JSON.stringify({
              session_token: 'unused',
              expires_at: new Date(Date.now() + 60_000).toISOString(),
              bound_cert_thumbprint: 'sha256:test'
            })
          })
      );

      expect(manager.getMtlsCredentials().ca).toBeDefined();
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('throws for non-absolute cert path', () => {
    const logger = createLogger();
    expect(
      () =>
        new SessionManager(
          {
            brokerUrl: 'https://broker.example.com',
            mtlsCertPath: 'relative/cert.pem',
            mtlsKeyPath: '/absolute/key.pem'
          },
          logger
        )
    ).toThrow('mtlsCertPath must be an absolute path');
  });

  it('throws for suspicious path segments containing traversal tokens', () => {
    const logger = createLogger();
    expect(
      () =>
        new SessionManager(
          {
            brokerUrl: 'https://broker.example.com',
            mtlsCertPath: '/tmp/..unsafe/cert.pem',
            mtlsKeyPath: '/tmp/key.pem'
          },
          logger
        )
    ).toThrow('mtlsCertPath contains path traversal');
  });

  it('refreshes immediately when computed refresh window is non-positive', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi
      .fn()
      .mockResolvedValueOnce({
        status: 200,
        body: JSON.stringify({
          session_token: 'sess_1',
          expires_at: new Date(Date.now() - 1_000).toISOString(),
          bound_cert_thumbprint: 'sha256:test'
        })
      })
      .mockResolvedValueOnce({
        status: 200,
        body: JSON.stringify({
          session_token: 'sess_2',
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          bound_cert_thumbprint: 'sha256:test'
        })
      });

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath
        },
        logger,
        requestImpl
      );

      await manager.getToken();
      await vi.runAllTimersAsync();
      expect(requestImpl.mock.calls.length).toBeGreaterThanOrEqual(2);
      manager.stop();
    } finally {
      cleanup();
    }
  });

  it('logs non-Error values from background refresh failures', async () => {
    const {certPath, keyPath, cleanup} = createMtlsFiles();
    const logger = createLogger();
    const requestImpl = vi
      .fn()
      .mockResolvedValueOnce({
        status: 200,
        body: JSON.stringify({
          session_token: 'sess_1',
          expires_at: new Date(Date.now() + 2_000).toISOString(),
          bound_cert_thumbprint: 'sha256:test'
        })
      })
      .mockRejectedValueOnce('string-failure');

    try {
      const manager = new SessionManager(
        {
          brokerUrl: 'https://broker.example.com',
          mtlsCertPath: certPath,
          mtlsKeyPath: keyPath,
          refreshThreshold: 0.5
        },
        logger,
        requestImpl
      );

      await manager.getToken();
      await vi.advanceTimersByTimeAsync(1_100);

      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('string-failure'));
      manager.stop();
    } finally {
      cleanup();
    }
  });
});

describe('canCreateSessionManager', () => {
  it('returns true only when cert and key are both present', () => {
    expect(canCreateSessionManager({mtlsCertPath: '/cert', mtlsKeyPath: '/key'})).toBe(true);
    expect(canCreateSessionManager({mtlsCertPath: '/cert'})).toBe(false);
    expect(canCreateSessionManager({mtlsKeyPath: '/key'})).toBe(false);
    expect(canCreateSessionManager({})).toBe(false);
  });
});
