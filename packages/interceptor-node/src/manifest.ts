/**
 * Manifest fetching and verification for the broker interceptor.
 *
 * The manifest tells the interceptor which hosts to intercept and where
 * to forward requests. It's signed by the broker and verified using JWKS.
 */

import * as fs from 'node:fs';
import * as https from 'node:https';
import * as http from 'node:http';
import * as nodePath from 'node:path';

import type {Logger, ParsedManifest, ResolvedInterceptorConfig, SessionTokenProvider} from './types.js';

/**
 * Validates that a file path is absolute and doesn't contain traversal.
 * Returns the normalized path or throws an error.
 */
function validateFilePath(filePath: string, description: string): string {
  if (!nodePath.isAbsolute(filePath)) {
    throw new Error(`${description} must be an absolute path: ${filePath}`);
  }
  const normalized = nodePath.normalize(filePath);
  // Ensure no path traversal outside of intended location
  if (normalized.includes('..')) {
    throw new Error(`${description} contains path traversal: ${filePath}`);
  }
  return normalized;
}

/**
 * Manifest keys (JWKS) for verifying manifest signatures.
 */
export interface ManifestKeys {
  keys: Array<{
    kid: string;
    kty: 'OKP' | 'EC';
    crv?: 'Ed25519' | 'P-256';
    x?: string;
    y?: string;
    alg: 'EdDSA' | 'ES256';
    use: 'sig';
  }>;
}

/**
 * Result of fetching the manifest.
 */
export type ManifestFetchResult = {ok: true; manifest: ParsedManifest; keys: ManifestKeys} | {ok: false; error: string};

/**
 * Fetch a URL using Node's built-in http/https modules.
 * This is a raw fetch that doesn't go through our patches.
 */
async function rawFetch(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    mtlsCert?: Buffer;
    mtlsKey?: Buffer;
    mtlsCa?: Buffer;
  } = {}
): Promise<{status: number; body: string}> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    const requestOptions: https.RequestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    };

    // Add mTLS options if provided
    if (isHttps && options.mtlsCert && options.mtlsKey) {
      requestOptions.cert = options.mtlsCert;
      requestOptions.key = options.mtlsKey;
      if (options.mtlsCa) {
        requestOptions.ca = options.mtlsCa;
      }
    }

    const req = transport.request(requestOptions, res => {
      let body = '';
      res.on('data', (chunk: Buffer) => {
        body += chunk.toString();
      });
      res.on('end', () => {
        resolve({status: res.statusCode || 0, body});
      });
    });

    req.on('error', err => {
      reject(err);
    });

    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Load mTLS credentials from file paths with validation.
 */
function loadMtlsCredentials(config: ResolvedInterceptorConfig): {
  cert?: Buffer;
  key?: Buffer;
  ca?: Buffer;
} {
  const result: {cert?: Buffer; key?: Buffer; ca?: Buffer} = {};

  if (config.mtlsCertPath) {
    const validPath = validateFilePath(config.mtlsCertPath, 'mtlsCertPath');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    result.cert = fs.readFileSync(validPath);
  }
  if (config.mtlsKeyPath) {
    const validPath = validateFilePath(config.mtlsKeyPath, 'mtlsKeyPath');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    result.key = fs.readFileSync(validPath);
  }
  if (config.mtlsCaPath) {
    const validPath = validateFilePath(config.mtlsCaPath, 'mtlsCaPath');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    result.ca = fs.readFileSync(validPath);
  }

  return result;
}

/**
 * Fetch and verify the manifest from the broker.
 * If a sessionTokenProvider is given and config.sessionToken is not set,
 * it will be used to get a fresh token.
 */
export async function fetchManifest(
  config: ResolvedInterceptorConfig,
  logger: Logger,
  sessionTokenProvider?: SessionTokenProvider
): Promise<ManifestFetchResult> {
  // If a local manifest path is provided, load from file
  if (config.manifestPath) {
    logger.debug(`Loading manifest from file: ${config.manifestPath}`);
    try {
      const validPath = validateFilePath(config.manifestPath, 'manifestPath');
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const manifestContent = fs.readFileSync(validPath, 'utf-8');
      const manifest = JSON.parse(manifestContent) as ParsedManifest;

      // For local manifests, we skip JWKS verification (trust the file)
      // In production, you'd want to verify even local manifests
      return {
        ok: true,
        manifest,
        keys: {keys: []} // Empty keys since we're trusting the local file
      };
    } catch (err) {
      return {
        ok: false,
        error: `Failed to load manifest from file: ${err instanceof Error ? err.message : String(err)}`
      };
    }
  }

  // Fetch manifest from broker
  const mtls = loadMtlsCredentials(config);
  const manifestUrl = `${config.brokerUrl}/v1/workloads/${encodeURIComponent(config.workloadId)}/manifest`;
  const keysUrl = `${config.brokerUrl}/v1/keys/manifest`;

  // Get session token - either from config or from provider
  let sessionToken = config.sessionToken;
  if (!sessionToken && sessionTokenProvider) {
    try {
      sessionToken = await sessionTokenProvider.getToken();
    } catch (err) {
      return {
        ok: false,
        error: `Failed to get session token: ${err instanceof Error ? err.message : String(err)}`
      };
    }
  }
  if (!sessionToken) {
    return {
      ok: false,
      error: 'No session token available for manifest fetch'
    };
  }

  logger.debug(`Fetching manifest from: ${manifestUrl}`);

  try {
    // Fetch manifest keys first
    logger.debug(`Fetching manifest keys from: ${keysUrl}`);
    const keysResponse = await rawFetch(keysUrl, {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        Accept: 'application/json'
      },
      mtlsCert: mtls.cert,
      mtlsKey: mtls.key,
      mtlsCa: mtls.ca
    });

    console.log({keys: JSON.stringify(keysResponse)});
    if (keysResponse.status !== 200) {
      return {
        ok: false,
        error: `Failed to fetch manifest keys: HTTP ${keysResponse.status}, ${keysResponse.body}`
      };
    }

    const keys = JSON.parse(keysResponse.body) as ManifestKeys;

    // Fetch manifest
    const manifestResponse = await rawFetch(manifestUrl, {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        Accept: 'application/json'
      },
      mtlsCert: mtls.cert,
      mtlsKey: mtls.key,
      mtlsCa: mtls.ca
    });

    console.log({manifest: JSON.stringify(manifestResponse)});
    if (manifestResponse.status !== 200) {
      return {
        ok: false,
        error: `Failed to fetch manifest: HTTP ${manifestResponse.status}, ${manifestResponse.body}`
      };
    }

    const manifest = JSON.parse(manifestResponse.body) as ParsedManifest;

    // Verify manifest signature
    // TODO: Use @broker-interceptor/crypto verifyManifestSignature
    // For the POC, we'll trust the manifest from authenticated endpoint
    logger.debug(`Manifest fetched successfully, version: ${manifest.manifest_version}`);

    // Check if manifest is expired
    const expiresAt = new Date(manifest.expires_at);
    if (expiresAt < new Date()) {
      return {
        ok: false,
        error: `Manifest expired at ${manifest.expires_at}`
      };
    }

    return {ok: true, manifest, keys};
  } catch (err) {
    return {
      ok: false,
      error: `Failed to fetch manifest: ${err instanceof Error ? err.message : String(err)}`
    };
  }
}

/**
 * Check if the manifest needs to be refreshed.
 */
export function shouldRefreshManifest(manifest: ParsedManifest, bufferSeconds = 60): boolean {
  const expiresAt = new Date(manifest.expires_at);
  const bufferMs = bufferSeconds * 1000;
  return expiresAt.getTime() - bufferMs < Date.now();
}

/**
 * Start periodic manifest refresh.
 */
export function startManifestRefresh(
  config: ResolvedInterceptorConfig,
  logger: Logger,
  onManifestUpdate: (manifest: ParsedManifest) => void,
  onError: (error: string) => void,
  sessionTokenProvider?: SessionTokenProvider
): ReturnType<typeof setInterval> {
  return setInterval(() => {
    logger.debug('Refreshing manifest...');
    void fetchManifest(config, logger, sessionTokenProvider).then(result => {
      if (result.ok) {
        onManifestUpdate(result.manifest);
        logger.info('Manifest refreshed successfully');
      } else {
        onError(result.error);
        logger.error(`Manifest refresh failed: ${result.error}`);
      }
    });
  }, config.manifestRefreshIntervalMs);
}
