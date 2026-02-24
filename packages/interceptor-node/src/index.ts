/**
 * @broker-interceptor/interceptor-node
 *
 * Node.js request interceptor for routing HTTP/HTTPS traffic through the broker.
 *
 * This is a POC implementation that establishes the protocol patterns needed for
 * the production eBPF-based interceptor. Key concepts that transfer to eBPF:
 *
 * 1. Manifest format and matching rules
 * 2. Session token authentication (auto-acquired with mTLS)
 * 3. Execute request/response protocol
 * 4. Child process propagation strategy
 *
 * Usage:
 *
 * Option 1: Programmatic initialization with mTLS (session tokens auto-managed)
 * ```ts
 * import {initializeInterceptor} from '@broker-interceptor/interceptor-node'
 *
 * await initializeInterceptor({
 *   brokerUrl: 'https://broker.example.com',
 *   workloadId: 'w_xxx',
 *   mtlsCertPath: '/path/to/workload.crt',
 *   mtlsKeyPath: '/path/to/workload.key',
 *   mtlsCaPath: '/path/to/ca-chain.pem',
 * })
 * ```
 *
 * Option 2: Preload via NODE_OPTIONS (zero-code change)
 * ```bash
 * export BROKER_URL=https://broker.example.com
 * export BROKER_WORKLOAD_ID=w_xxx
 * export BROKER_MTLS_CERT_PATH=/path/to/workload.crt
 * export BROKER_MTLS_KEY_PATH=/path/to/workload.key
 * export BROKER_MTLS_CA_PATH=/path/to/ca-chain.pem
 * export NODE_OPTIONS="--import @broker-interceptor/interceptor-node/preload"
 * node app.js
 * ```
 *
 * Note: Session tokens are automatically acquired and refreshed using your mTLS
 * credentials. You can also provide a static BROKER_SESSION_TOKEN if preferred.
 */

import {fetchManifest, startManifestRefresh} from './manifest.js';
import {applyPatches, removePatches, updateState} from './patch-http.js';
import {applyFetchPatch, removeFetchPatch, updateFetchState} from './patch-fetch.js';
import {applyChildProcessPatches, removeChildProcessPatches, updateChildProcessState} from './patch-child-process.js';
import {SessionManager, canCreateSessionManager} from './session.js';
import {
  InterceptorConfigSchema,
  defaultLogger,
  type InterceptorConfig,
  type InterceptorState,
  type ManifestFailurePolicy,
  type ManifestStateKind,
  type ParsedManifest,
  type Logger,
  type SessionTokenProvider
} from './types.js';

// Re-export types for consumers
export type {Logger} from './types.js';
export {
  type InterceptorConfig,
  type ParsedManifest,
  type ExecuteRequest,
  type ExecuteResponse,
  type ExecuteResponseExecuted,
  type ExecuteResponseApprovalRequired,
  type MatchRule,
  type ManifestFailurePolicy,
  type ManifestRuntimeState
} from './types.js';

export {ApprovalRequiredError, RequestDeniedError, ManifestUnavailableError} from './broker-client.js';
export {matchUrl, shouldIntercept, type MatchResult, type RuleMismatchDetail} from './matcher.js';

// Global state
let globalState: InterceptorState | null = null;

/**
 * Result of initializing the interceptor.
 */
export type InitializeResult = {ok: true; manifest: ParsedManifest} | {ok: false; error: string};

function getManifestStateFromCurrentManifest(manifest: ParsedManifest | null): ManifestStateKind {
  if (!manifest) {
    return 'missing';
  }

  const expiresAt = new Date(manifest.expires_at);
  return expiresAt.getTime() > Date.now() ? 'valid' : 'expired';
}

function setCurrentManifest(state: InterceptorState, manifest: ParsedManifest): void {
  state.manifest = manifest;
  state.manifestRuntime.currentManifest = manifest;
  state.manifestRuntime.currentManifestExpiresAt = new Date(manifest.expires_at);
  state.manifestRuntime.lastRefreshAttemptAt = new Date();
  state.manifestRuntime.manifestState = getManifestStateFromCurrentManifest(manifest);
}

function markManifestRefreshFailure(state: InterceptorState, policy: ManifestFailurePolicy): void {
  state.manifestRuntime.lastRefreshAttemptAt = new Date();

  if (policy === 'fail_open') {
    state.manifestRuntime.manifestState = state.manifest ? 'stale' : 'missing';
    return;
  }

  if (policy === 'fail_closed') {
    state.manifestRuntime.manifestState = 'expired';
    return;
  }

  state.manifestRuntime.manifestState = getManifestStateFromCurrentManifest(state.manifest) === 'expired' ? 'expired' : 'stale';
}

/**
 * Initialize the broker interceptor.
 *
 * This patches Node's http, https, fetch, and child_process modules to intercept
 * outgoing requests that match the manifest rules.
 */
export async function initializeInterceptor(config: InterceptorConfig): Promise<InitializeResult> {
  // Validate and apply defaults (logger is separate from zod schema)
  const parseResult = InterceptorConfigSchema.safeParse(config);
  if (!parseResult.success) {
    return {ok: false, error: `Invalid config: ${parseResult.error.message}`};
  }

  // Logger is passed separately in config (not part of zod schema)
  const logger: Logger = config.logger ?? defaultLogger;

  // Build resolved config with logger
  const resolvedConfig = {
    ...parseResult.data,
    logger
  };

  // Check if already initialized
  if (globalState?.initialized) {
    logger.warn('Interceptor already initialized, skipping');
    return globalState.manifest
      ? {ok: true, manifest: globalState.manifest}
      : {ok: false, error: 'Already initialized but manifest is null'};
  }

  // Create session manager if mTLS credentials are provided
  let sessionManager: SessionTokenProvider | null = null;
  if (canCreateSessionManager(resolvedConfig)) {
    logger.debug('Creating session manager with mTLS credentials');
    sessionManager = new SessionManager(
      {
        brokerUrl: resolvedConfig.brokerUrl,
        mtlsCertPath: resolvedConfig.mtlsCertPath,
        mtlsKeyPath: resolvedConfig.mtlsKeyPath,
        mtlsCaPath: resolvedConfig.mtlsCaPath,
        sessionTtlSeconds: resolvedConfig.sessionTtlSeconds
      },
      logger
    );
  } else if (!resolvedConfig.sessionToken) {
    return {ok: false, error: 'Either sessionToken or mTLS credentials must be provided'};
  }

  // If we have a session manager but no static token, acquire token now
  if (sessionManager && !resolvedConfig.sessionToken) {
    try {
      logger.debug('Acquiring initial session token...');
      const token = await sessionManager.getToken();
      // Store the token in resolved config for manifest fetching
      resolvedConfig.sessionToken = token;
    } catch (err) {
      return {ok: false, error: `Failed to acquire session token: ${err instanceof Error ? err.message : String(err)}`};
    }
  }

  // Initialize state
  globalState = {
    config: resolvedConfig,
    manifest: null,
    manifestRuntime: {
      currentManifest: null,
      currentManifestExpiresAt: null,
      lastRefreshAttemptAt: null,
      manifestState: 'missing'
    },
    logger,
    refreshTimer: null,
    initialized: false,
    sessionManager
  };

  // Fetch manifest
  logger.debug('Fetching manifest...');
  const manifestResult = await fetchManifest(resolvedConfig, logger, sessionManager ?? undefined);

  if (!manifestResult.ok) {
    if (resolvedConfig.failOnManifestError) {
      return {ok: false, error: manifestResult.error};
    }
    logger.warn(`Manifest fetch failed: ${manifestResult.error}`);
    markManifestRefreshFailure(globalState, resolvedConfig.manifestFailurePolicy);
  } else {
    setCurrentManifest(globalState, manifestResult.manifest);
    logger.info(`Manifest loaded: ${manifestResult.manifest.match_rules.length} rules`);
  }

  // Apply patches - wrap in try-catch to make initialization resilient
  // Even if some patches fail, we want the interceptor to continue working
  // for the modules that were successfully patched
  try {
    applyPatches(globalState);
  } catch (err) {
    logger.warn(`HTTP patches failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  try {
    applyFetchPatch(globalState);
  } catch (err) {
    logger.warn(`fetch patch failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  try {
    applyChildProcessPatches(globalState);
  } catch (err) {
    logger.warn(`child_process patches failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Start manifest refresh
  globalState.refreshTimer = startManifestRefresh(
    resolvedConfig,
    logger,
    manifest => {
      if (globalState) {
        setCurrentManifest(globalState, manifest);
        updateState(globalState);
        updateFetchState(globalState);
        updateChildProcessState(globalState);
      }
    },
    error => {
      if (globalState) {
        markManifestRefreshFailure(globalState, resolvedConfig.manifestFailurePolicy);
        updateState(globalState);
        updateFetchState(globalState);
        updateChildProcessState(globalState);
      }
      logger.error(`Manifest refresh failed: ${error}`);
    },
    sessionManager ?? undefined
  );

  globalState.initialized = true;

  return globalState.manifest
    ? {ok: true, manifest: globalState.manifest}
    : {ok: false, error: 'Initialized without manifest'};
}

/**
 * Shutdown the interceptor and remove all patches.
 */
export function shutdownInterceptor(): void {
  if (!globalState) {
    return;
  }

  const logger = globalState.logger;

  // Stop refresh timer
  if (globalState.refreshTimer) {
    clearInterval(globalState.refreshTimer);
  }

  // Stop session manager
  if (globalState.sessionManager && 'stop' in globalState.sessionManager) {
    (globalState.sessionManager as SessionManager).stop();
  }

  // Remove patches
  removePatches();
  removeFetchPatch();
  removeChildProcessPatches();

  logger.info('Interceptor shutdown complete');
  globalState = null;
}

/**
 * Get the current manifest (if loaded).
 */
export function getManifest(): ParsedManifest | null {
  return globalState?.manifest || null;
}

/**
 * Check if the interceptor is initialized.
 */
export function isInitialized(): boolean {
  return globalState?.initialized || false;
}

/**
 * Force refresh the manifest.
 */
export async function refreshManifest(): Promise<InitializeResult> {
  if (!globalState) {
    return {ok: false, error: 'Interceptor not initialized'};
  }

  const result = await fetchManifest(globalState.config, globalState.logger, globalState.sessionManager ?? undefined);

  if (result.ok) {
    setCurrentManifest(globalState, result.manifest);
    updateState(globalState);
    updateFetchState(globalState);
    updateChildProcessState(globalState);
    return {ok: true, manifest: result.manifest};
  }

  markManifestRefreshFailure(globalState, globalState.config.manifestFailurePolicy);
  updateState(globalState);
  updateFetchState(globalState);
  updateChildProcessState(globalState);

  return {ok: false, error: result.error};
}

/**
 * Get the session token provider (if using auto session management).
 */
export function getSessionManager(): SessionTokenProvider | null {
  return globalState?.sessionManager || null;
}

// For backwards compatibility
export const packageName = 'interceptor-node';
