/**
 * Session management for the broker interceptor.
 *
 * Automatically acquires and refreshes session tokens using mTLS credentials.
 * This removes the need for users to manually manage session tokens.
 */

import * as fs from 'node:fs';
import * as https from 'node:https';
import * as http from 'node:http';
import * as nodePath from 'node:path';

import type {Logger} from './types.js';

/** Session response from broker-api /v1/sessions */
export interface SessionResponse {
  session_token: string;
  expires_at: string;
  bound_cert_thumbprint: string;
}

/** Session manager configuration */
export interface SessionManagerConfig {
  brokerUrl: string;
  mtlsCertPath: string;
  mtlsKeyPath: string;
  mtlsCaPath?: string;
  /** Session TTL in seconds (default: 3600 = 1 hour) */
  sessionTtlSeconds?: number;
  /** Scopes to request (default: ['execute', 'manifest.read']) */
  scopes?: string[];
  /** Refresh threshold ratio (default: 0.8 = refresh at 80% of TTL) */
  refreshThreshold?: number;
}

/** Internal resolved config with defaults applied (mtlsCaPath remains optional) */
interface ResolvedSessionManagerConfig {
  brokerUrl: string;
  mtlsCertPath: string;
  mtlsKeyPath: string;
  mtlsCaPath?: string;
  sessionTtlSeconds: number;
  scopes: string[];
  refreshThreshold: number;
}

/**
 * Validates that a file path is absolute and doesn't contain traversal.
 */
function validateFilePath(filePath: string, description: string): string {
  if (!nodePath.isAbsolute(filePath)) {
    throw new Error(`${description} must be an absolute path: ${filePath}`);
  }
  const normalized = nodePath.normalize(filePath);
  if (normalized.includes('..')) {
    throw new Error(`${description} contains path traversal: ${filePath}`);
  }
  return normalized;
}

/**
 * Raw HTTP request that doesn't go through interceptor patches.
 */
async function rawSessionRequest(
  url: string,
  options: {
    method: string;
    headers: Record<string, string>;
    body: string;
    cert: Buffer;
    key: Buffer;
    ca?: Buffer;
  }
): Promise<{status: number; body: string}> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    const requestOptions: https.RequestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method,
      headers: options.headers,
      cert: options.cert,
      key: options.key,
      ...(options.ca ? {ca: options.ca} : {})
    };

    const req = transport.request(requestOptions, res => {
      let body = '';
      res.on('data', (chunk: Buffer) => {
        body += chunk.toString();
      });
      res.on('end', () => {
        resolve({status: res.statusCode || 0, body});
      });
    });

    req.on('error', reject);
    req.write(options.body);
    req.end();
  });
}

/**
 * Session manager that auto-acquires and refreshes tokens.
 */
export class SessionManager {
  private readonly config: ResolvedSessionManagerConfig;
  private readonly logger: Logger;
  private cert: Buffer;
  private key: Buffer;
  private ca?: Buffer;

  private currentToken: string | null = null;
  private expiresAt: Date | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private acquiring: Promise<string> | null = null;

  constructor(config: SessionManagerConfig, logger: Logger) {
    this.config = {
      ...config,
      sessionTtlSeconds: config.sessionTtlSeconds ?? 3600,
      scopes: config.scopes ?? ['execute', 'manifest.read'],
      refreshThreshold: config.refreshThreshold ?? 0.8
    };
    this.logger = logger;

    // Load mTLS credentials
    const certPath = validateFilePath(this.config.mtlsCertPath, 'mtlsCertPath');
    const keyPath = validateFilePath(this.config.mtlsKeyPath, 'mtlsKeyPath');

    // eslint-disable-next-line security/detect-non-literal-fs-filename
    this.cert = fs.readFileSync(certPath);
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    this.key = fs.readFileSync(keyPath);

    if (this.config.mtlsCaPath) {
      const caPath = validateFilePath(this.config.mtlsCaPath, 'mtlsCaPath');
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      this.ca = fs.readFileSync(caPath);
    }
  }

  /**
   * Get the mTLS credentials for making requests.
   */
  getMtlsCredentials(): {cert: Buffer; key: Buffer; ca?: Buffer} {
    return {cert: this.cert, key: this.key, ca: this.ca};
  }

  /**
   * Get the current session token, acquiring one if necessary.
   * Returns a cached token if still valid.
   */
  async getToken(): Promise<string> {
    // If we have a valid token, return it
    if (this.currentToken && this.expiresAt && this.expiresAt > new Date()) {
      return this.currentToken;
    }

    // If already acquiring, wait for that
    if (this.acquiring) {
      return this.acquiring;
    }

    // Acquire new token
    this.acquiring = this.acquireToken();
    try {
      const token = await this.acquiring;
      return token;
    } finally {
      this.acquiring = null;
    }
  }

  /**
   * Check if we have a valid session token.
   */
  hasValidToken(): boolean {
    return this.currentToken !== null && this.expiresAt !== null && this.expiresAt > new Date();
  }

  /**
   * Acquire a new session token from the broker.
   */
  private async acquireToken(): Promise<string> {
    const url = `${this.config.brokerUrl}/v1/session`;

    this.logger.debug(`Acquiring session token from ${url}`);

    const payload = JSON.stringify({
      requested_ttl_seconds: this.config.sessionTtlSeconds,
      scopes: this.config.scopes
    });

    const response = await rawSessionRequest(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: payload,
      cert: this.cert,
      key: this.key,
      ca: this.ca
    });

    if (response.status !== 200) {
      let guidance = '';
      if (response.status === 401 && response.body.includes('"error":"mtls_required"')) {
        guidance =
          ' (check broker mTLS settings: BROKER_API_TLS_REQUIRE_CLIENT_CERT=true and CA alignment between enrollment issuer and broker-api TLS client CA)'
      }
      const error = `Failed to acquire session token: HTTP ${response.status} - ${response.body}${guidance}`;
      this.logger.error(error);
      throw new Error(error);
    }

    const sessionResponse = JSON.parse(response.body) as SessionResponse;

    this.currentToken = sessionResponse.session_token;
    this.expiresAt = new Date(sessionResponse.expires_at);

    this.logger.info(`Session token acquired, expires at ${sessionResponse.expires_at}`);

    // Schedule refresh
    this.scheduleRefresh();

    return this.currentToken;
  }

  /**
   * Schedule automatic token refresh before expiry.
   */
  private scheduleRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    if (!this.expiresAt) return;

    const now = Date.now();
    const expiresMs = this.expiresAt.getTime();
    const ttlMs = expiresMs - now;
    const refreshAtMs = ttlMs * this.config.refreshThreshold;

    if (refreshAtMs <= 0) {
      // Token is already close to expiry, refresh immediately
      this.logger.debug('Token near expiry, refreshing immediately');
      void this.acquireToken().catch(err => {
        this.logger.error(`Background token refresh failed: ${err instanceof Error ? err.message : String(err)}`);
      });
      return;
    }

    this.logger.debug(`Scheduling token refresh in ${Math.round(refreshAtMs / 1000)}s`);

    this.refreshTimer = setTimeout(() => {
      this.logger.debug('Refreshing session token...');
      void this.acquireToken().catch(err => {
        this.logger.error(`Background token refresh failed: ${err instanceof Error ? err.message : String(err)}`);
      });
    }, refreshAtMs);
  }

  /**
   * Stop the session manager and clear any pending refresh timers.
   */
  stop(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.currentToken = null;
    this.expiresAt = null;
  }
}

/**
 * Check if session manager can be created with the given config.
 */
export function canCreateSessionManager(config: {
  mtlsCertPath?: string;
  mtlsKeyPath?: string;
  mtlsCaPath?: string;
}): config is {mtlsCertPath: string; mtlsKeyPath: string; mtlsCaPath?: string} {
  return Boolean(config.mtlsCertPath && config.mtlsKeyPath);
}
