/**
 * Preload entry point for broker interceptor.
 *
 * This file is loaded via `node --import @broker-interceptor/interceptor-node/preload`
 * or via NODE_OPTIONS environment variable.
 *
 * It patches Node's http, https, fetch, and child_process modules BEFORE
 * any user code runs, enabling transparent request interception.
 */

import * as path from 'node:path';

import {initializeInterceptor} from './index.js';
import {defaultLogger, type InterceptorConfig, type Logger} from './types.js';

/**
 * Resolve a path to absolute if it's relative.
 */
function resolvePath(filePath: string | undefined): string | undefined {
  if (!filePath) return undefined;
  if (path.isAbsolute(filePath)) return filePath;
  return path.resolve(process.cwd(), filePath);
}

// Configuration from environment variables
function getConfigFromEnv(): InterceptorConfig | null {
  const brokerUrl = process.env.BROKER_URL;
  const workloadId = process.env.BROKER_WORKLOAD_ID;
  const sessionToken = process.env.BROKER_SESSION_TOKEN;
  const mtlsCertPath = resolvePath(process.env.BROKER_MTLS_CERT_PATH);
  const mtlsKeyPath = resolvePath(process.env.BROKER_MTLS_KEY_PATH);
  const mtlsCaPath = resolvePath(process.env.BROKER_MTLS_CA_PATH);
  const manifestPath = resolvePath(process.env.BROKER_MANIFEST_PATH);
  const manifestFailurePolicy =
    process.env.BROKER_MANIFEST_FAILURE_POLICY === 'fail_closed' ||
    process.env.BROKER_MANIFEST_FAILURE_POLICY === 'fail_open' ||
    process.env.BROKER_MANIFEST_FAILURE_POLICY === 'use_last_valid'
      ? process.env.BROKER_MANIFEST_FAILURE_POLICY
      : undefined;

  // Need either session token OR mTLS credentials (cert + key)
  const hasSessionToken = Boolean(sessionToken);
  const hasMtlsCreds = Boolean(mtlsCertPath && mtlsKeyPath);

  if (!brokerUrl || !workloadId || (!hasSessionToken && !hasMtlsCreds)) {
    // Not configured, skip initialization
    return null;
  }

  return {
    brokerUrl,
    workloadId,
    ...(sessionToken ? {sessionToken} : {}),
    manifestPath,
    mtlsCertPath,
    mtlsKeyPath,
    mtlsCaPath,
    sessionTtlSeconds: process.env.BROKER_SESSION_TTL_SECONDS
      ? parseInt(process.env.BROKER_SESSION_TTL_SECONDS, 10)
      : undefined,
    manifestRefreshIntervalMs: process.env.BROKER_MANIFEST_REFRESH_MS
      ? parseInt(process.env.BROKER_MANIFEST_REFRESH_MS, 10)
      : undefined,
    failOnManifestError: process.env.BROKER_FAIL_ON_MANIFEST_ERROR !== 'false',
    manifestFailurePolicy
  };
}

// Create logger based on environment
function getLogger(): Logger {
  const logLevel = process.env.BROKER_LOG_LEVEL || 'info';

  if (logLevel === 'silent') {
    return {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {}
    };
  }

  const logger = {...defaultLogger};

  if (logLevel !== 'debug') {
    logger.debug = () => {};
  }

  return logger;
}

// Initialize on module load
async function init(): Promise<void> {
  const logger = getLogger();
  const config = getConfigFromEnv();

  if (!config) {
    logger.debug(
      'Broker interceptor not configured (need BROKER_URL + BROKER_WORKLOAD_ID + either BROKER_SESSION_TOKEN or BROKER_MTLS_CERT_PATH+BROKER_MTLS_KEY_PATH)'
    );
    return;
  }

  logger.info(`Initializing broker interceptor for ${config.brokerUrl}`);

  try {
    const result = await initializeInterceptor({
      ...config,
      logger
    });

    if (result.ok) {
      logger.info(`Broker interceptor initialized, ${result.manifest.match_rules.length} match rules loaded`);
    } else {
      if (config.failOnManifestError) {
        logger.error(`Failed to initialize broker interceptor: ${result.error}`);
        process.exit(1);
      } else {
        logger.warn(`Broker interceptor initialization failed: ${result.error} (continuing without interception)`);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Broker interceptor initialization error: ${message}`);

    if (config.failOnManifestError !== false) {
      process.exit(1);
    }
  }
}

// Run initialization
init().catch(err => {
  console.error('[broker-interceptor] Fatal initialization error:', err);
  process.exit(1);
});
