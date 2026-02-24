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
import {createPublicKey, verify as verifySignature} from 'node:crypto';
import {TextDecoder} from 'node:util';

import {
  OpenApiManifestKeysSchema,
  OpenApiManifestSchema,
  type OpenApiManifestKeys,
  type OpenApiManifest
} from '@broker-interceptor/schemas/dist/generated/schemas.js';

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
export type ManifestKeys = OpenApiManifestKeys;

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

export type RawManifestFetch = typeof rawFetch;

const textDecoder = new TextDecoder();

function isRegexPattern(pattern: string): boolean {
  return pattern.startsWith('^');
}

function validatePathGroupPattern(pattern: string): string | null {
  if (isRegexPattern(pattern)) {
    if (!pattern.endsWith('$')) {
      return 'regex path pattern must be anchored with $';
    }

    try {
      // eslint-disable-next-line security/detect-non-literal-regexp -- manifest pattern is signature-verified before use
      new RegExp(pattern);
    } catch {
      return 'regex path pattern is invalid';
    }

    return null;
  }

  if (pattern.endsWith('/*')) {
    if (!pattern.startsWith('/')) {
      return 'prefix path pattern must start with /';
    }
    if (pattern.length < 3) {
      return 'prefix path pattern must contain a non-root prefix';
    }
    return null;
  }

  if (!pattern.startsWith('/')) {
    return 'exact path pattern must start with /';
  }

  if (pattern.includes('*')) {
    return 'wildcards are only allowed as suffix /*';
  }

  return null;
}

export function validateManifestForInterception(manifest: OpenApiManifest): {ok: true} | {ok: false; error: string} {
  for (const [ruleIndex, rule] of manifest.match_rules.entries()) {
    for (const host of rule.match.hosts) {
      if (host.includes('*')) {
        return {
          ok: false,
          error: `Manifest rule ${ruleIndex} (${rule.integration_id}) uses unsupported wildcard host: ${host}`
        };
      }
    }

    for (const [pathIndex, pattern] of rule.match.path_groups.entries()) {
      const pathError = validatePathGroupPattern(pattern);
      if (pathError) {
        return {
          ok: false,
          error: `Manifest rule ${ruleIndex} (${rule.integration_id}) path_groups[${pathIndex}] invalid: ${pathError}`
        };
      }
    }
  }

  return {ok: true};
}

function stripManifestSignature(manifest: OpenApiManifest): Omit<OpenApiManifest, 'signature'> {
  const {signature, ...unsignedManifest} = manifest;
  void signature;
  return unsignedManifest;
}

function canonicalJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  if (typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }

  const objectValue = value as Record<string, unknown>;
  const keys = Object.keys(objectValue).sort();
  // eslint-disable-next-line security/detect-object-injection
  const pairs = keys.map(key => `${JSON.stringify(key)}:${canonicalJson(objectValue[key])}`);
  return `{${pairs.join(',')}}`;
}

function parseManifest(rawBody: string): {ok: true; manifest: OpenApiManifest} | {ok: false; error: string} {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(rawBody);
  } catch (error) {
    return {
      ok: false,
      error: `Manifest response is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
    };
  }

  const parsedManifest = OpenApiManifestSchema.safeParse(parsedJson);
  if (!parsedManifest.success) {
    return {ok: false, error: `Manifest response failed schema validation: ${parsedManifest.error.message}`};
  }

  const validatedPatterns = validateManifestForInterception(parsedManifest.data);
  if (!validatedPatterns.ok) {
    return validatedPatterns;
  }

  return {ok: true, manifest: parsedManifest.data};
}

function parseManifestKeys(rawBody: string): {ok: true; keys: OpenApiManifestKeys} | {ok: false; error: string} {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(rawBody);
  } catch (error) {
    return {
      ok: false,
      error: `Manifest keys response is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
    };
  }

  const parsedKeys = OpenApiManifestKeysSchema.safeParse(parsedJson);
  if (!parsedKeys.success) {
    return {ok: false, error: `Manifest keys response failed schema validation: ${parsedKeys.error.message}`};
  }

  return {ok: true, keys: parsedKeys.data};
}

export function verifyManifestSignature(
  manifest: OpenApiManifest,
  keys: OpenApiManifestKeys
): {ok: true} | {ok: false; error: string} {
  const signingKey = keys.keys.find((key: OpenApiManifestKeys['keys'][number]) => key.kid === manifest.signature.kid);
  if (!signingKey) {
    const availableKids = keys.keys.map(key => key.kid).join(', ') || 'none';
    return {
      ok: false,
      error: `Manifest signing key not found for kid=${manifest.signature.kid}; available_kids=[${availableKids}]`
    };
  }

  if (signingKey.alg !== manifest.signature.alg) {
    return {ok: false, error: 'Manifest signature algorithm does not match manifest key metadata'};
  }

  try {
    const segments = manifest.signature.jws.split('.');
    if (segments.length !== 3) {
      return {ok: false, error: 'Manifest JWS is malformed'};
    }
    const [headerSegment, payloadSegment, signatureSegment] = segments;

    const protectedHeader = JSON.parse(Buffer.from(headerSegment, 'base64url').toString('utf-8')) as {
      alg?: string;
      kid?: string;
    };
    if (protectedHeader.alg !== manifest.signature.alg || protectedHeader.kid !== manifest.signature.kid) {
      return {ok: false, error: 'Manifest JWS protected header does not match signature metadata'};
    }

    const publicJwk =
      signingKey.kty === 'OKP'
        ? ({
            kty: 'OKP',
            crv: signingKey.crv,
            x: signingKey.x,
            kid: signingKey.kid
          } as const)
        : ({
            kty: 'EC',
            crv: signingKey.crv,
            x: signingKey.x,
            y: signingKey.y,
            kid: signingKey.kid
          } as const);

    const publicKey = createPublicKey({format: 'jwk', key: publicJwk});
    const data = Buffer.from(`${headerSegment}.${payloadSegment}`, 'utf-8');
    const signature = Buffer.from(signatureSegment, 'base64url');

    const isValid =
      signingKey.alg === 'ES256'
        ? verifySignature('sha256', data, {key: publicKey, dsaEncoding: 'ieee-p1363'}, signature)
        : verifySignature(null, data, publicKey, signature);
    if (!isValid) {
      return {ok: false, error: 'Manifest signature verification failed'};
    }

    const decodedPayload = textDecoder.decode(Buffer.from(payloadSegment, 'base64url'));
    const parsedPayload = JSON.parse(decodedPayload) as unknown;
    const expectedPayload = stripManifestSignature(manifest);

    if (canonicalJson(parsedPayload) !== canonicalJson(expectedPayload)) {
      return {ok: false, error: 'Manifest payload does not match signed JWS payload'};
    }

    return {ok: true};
  } catch (error) {
    return {
      ok: false,
      error: `Manifest signature verification failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function fetchManifestKeys(
  keysUrl: string,
  sessionToken: string,
  mtls: {cert?: Buffer; key?: Buffer; ca?: Buffer},
  requestImpl: RawManifestFetch
): Promise<{ok: true; keys: OpenApiManifestKeys} | {ok: false; error: string}> {
  const keysResponse = await requestImpl(keysUrl, {
    headers: {
      Authorization: `Bearer ${sessionToken}`,
      Accept: 'application/json'
    },
    mtlsCert: mtls.cert,
    mtlsKey: mtls.key,
    mtlsCa: mtls.ca
  });

  if (keysResponse.status !== 200) {
    return {
      ok: false,
      error: `Failed to fetch manifest keys: HTTP ${keysResponse.status}`
    };
  }

  return parseManifestKeys(keysResponse.body);
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
  sessionTokenProvider?: SessionTokenProvider,
  requestImpl: RawManifestFetch = rawFetch
): Promise<ManifestFetchResult> {
  let mtls: {cert?: Buffer; key?: Buffer; ca?: Buffer};
  try {
    mtls = loadMtlsCredentials(config);
  } catch (err) {
    return {
      ok: false,
      error: `Failed to load mTLS credentials: ${err instanceof Error ? err.message : String(err)}`
    };
  }
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
    const initialKeysResult = await fetchManifestKeys(keysUrl, sessionToken, mtls, requestImpl);
    if (!initialKeysResult.ok) {
      return initialKeysResult;
    }
    let keys = initialKeysResult.keys;

    let manifest: ParsedManifest;
    if (config.manifestPath) {
      logger.debug(`Loading manifest from file: ${config.manifestPath}`);
      const validPath = validateFilePath(config.manifestPath, 'manifestPath');
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const manifestContent = fs.readFileSync(validPath, 'utf-8');
      const parsedManifest = parseManifest(manifestContent);
      if (!parsedManifest.ok) {
        return parsedManifest;
      }
      manifest = parsedManifest.manifest;
    } else {
      const manifestResponse = await requestImpl(manifestUrl, {
        headers: {
          Authorization: `Bearer ${sessionToken}`,
          Accept: 'application/json'
        },
        mtlsCert: mtls.cert,
        mtlsKey: mtls.key,
        mtlsCa: mtls.ca
      });

      if (manifestResponse.status !== 200) {
        return {
          ok: false,
          error: `Failed to fetch manifest: HTTP ${manifestResponse.status}`
        };
      }

      const parsedManifest = parseManifest(manifestResponse.body);
      if (!parsedManifest.ok) {
        return parsedManifest;
      }
      manifest = parsedManifest.manifest;
    }

    const signatureValidation = verifyManifestSignature(manifest, keys);
    if (!signatureValidation.ok) {
      const missingKidPrefix = 'Manifest signing key not found for kid=';
      if (signatureValidation.error.startsWith(missingKidPrefix)) {
        logger.warn('Manifest signing key missing from current JWKS, refetching manifest keys once');
        const refetchedKeysResult = await fetchManifestKeys(keysUrl, sessionToken, mtls, requestImpl);
        if (!refetchedKeysResult.ok) {
          return {
            ok: false,
            error: `Manifest key refetch failed after kid mismatch: ${refetchedKeysResult.error}`
          };
        }

        keys = refetchedKeysResult.keys;
        const retriedSignatureValidation = verifyManifestSignature(manifest, keys);
        if (!retriedSignatureValidation.ok) {
          return retriedSignatureValidation;
        }
      } else {
        return signatureValidation;
      }
    }

    logger.debug(`Manifest fetched and verified, version: ${manifest.manifest_version}`);

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
  sessionTokenProvider?: SessionTokenProvider,
  requestImpl: RawManifestFetch = rawFetch
): ReturnType<typeof setInterval> {
  return setInterval(() => {
    logger.debug('Refreshing manifest...');
    void fetchManifest(config, logger, sessionTokenProvider, requestImpl).then(result => {
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
