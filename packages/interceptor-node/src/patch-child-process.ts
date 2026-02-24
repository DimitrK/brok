/**
 * child_process module patching for propagating interception to child processes.
 *
 * This module patches spawn, exec, execFile, and fork to inject environment
 * variables that enable interception in child processes.
 *
 * For Node child processes: NODE_OPTIONS="--import ..." is injected
 * For other processes on Linux: LD_PRELOAD can be injected (if native lib available)
 */

import * as child_process from 'node:child_process';
import {createRequire, syncBuiltinESMExports} from 'node:module';
import * as path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import type {
  SpawnOptions,
  SpawnSyncOptions,
  ExecOptions,
  ExecFileOptions,
  ForkOptions,
  ChildProcess,
  SpawnSyncReturns
} from 'node:child_process';

import type {InterceptorState, ResolvedInterceptorConfig} from './types.js';

const require = createRequire(import.meta.url);
// eslint-disable-next-line security/detect-child-process -- loading mutable builtin module namespace for safe patching
const mutableChildProcess = require('node:child_process') as typeof import('node:child_process');

// Store original implementations
let originalSpawn: typeof child_process.spawn | null = null;
let originalSpawnSync: typeof child_process.spawnSync | null = null;
let originalExec: typeof child_process.exec | null = null;
let originalExecSync: typeof child_process.execSync | null = null;
let originalExecFile: typeof child_process.execFile | null = null;
let originalExecFileSync: typeof child_process.execFileSync | null = null;
let originalFork: typeof child_process.fork | null = null;

// Global state
let interceptorState: InterceptorState | null = null;

/**
 * Check if child_process patching has been applied.
 */
export function isChildProcessPatched(): boolean {
  return originalSpawn !== null;
}

/**
 * Get the path to the preload script.
 * This is the script that will be --import'ed in child Node processes.
 */
function getPreloadPath(): string {
  const currentFilePath = fileURLToPath(import.meta.url);
  return path.resolve(path.dirname(currentFilePath), 'preload.js');
}

function tokenizeNodeOptions(existingOptions: string): string[] {
  const matches = existingOptions.match(/"[^"]*"|'[^']*'|\S+/g);
  return matches ?? [];
}

function trimMatchingQuotes(token: string): string {
  if ((token.startsWith('"') && token.endsWith('"')) || (token.startsWith("'") && token.endsWith("'"))) {
    return token.slice(1, -1);
  }
  return token;
}

function hasImportSpecifier(existingOptions: string, importSpecifier: string): boolean {
  const tokens = tokenizeNodeOptions(existingOptions).map(trimMatchingQuotes);

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens.at(index);
    if (!token) {
      continue;
    }

    // eslint-disable-next-line security/detect-possible-timing-attacks -- comparison against a local CLI flag string
    if (token === `--import=${importSpecifier}`) {
      return true;
    }

    if (token === '--import' && tokens.at(index + 1) === importSpecifier) {
      return true;
    }
  }

  return false;
}

export function buildNodeOptionsWithImport(existingOptions: string, importSpecifier: string): string {
  const importFlag = `--import=${importSpecifier}`;
  if (hasImportSpecifier(existingOptions, importSpecifier)) {
    return existingOptions;
  }

  const trimmedOptions = existingOptions.trim();
  if (trimmedOptions.length === 0) {
    return importFlag;
  }

  return `${trimmedOptions} ${importFlag}`;
}

/**
 * Build environment variables to inject into child processes.
 */
function buildChildEnv(
  existingEnv: NodeJS.ProcessEnv | undefined,
  config: ResolvedInterceptorConfig
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...existingEnv
  };

  // Propagate broker configuration
  if (config.brokerUrl) {
    env.BROKER_URL = config.brokerUrl;
  }
  if (config.sessionToken) {
    env.BROKER_SESSION_TOKEN = config.sessionToken;
  }
  if (config.manifestPath) {
    env.BROKER_MANIFEST_PATH = config.manifestPath;
  }
  if (config.mtlsCertPath) {
    env.BROKER_MTLS_CERT_PATH = config.mtlsCertPath;
  }
  if (config.mtlsKeyPath) {
    env.BROKER_MTLS_KEY_PATH = config.mtlsKeyPath;
  }
  if (config.mtlsCaPath) {
    env.BROKER_MTLS_CA_PATH = config.mtlsCaPath;
  }

  // Inject NODE_OPTIONS for Node child processes
  const preloadPath = getPreloadPath();
  const preloadSpecifier = pathToFileURL(preloadPath).href;
  const nodeOptions = env.NODE_OPTIONS || '';
  env.NODE_OPTIONS = buildNodeOptionsWithImport(nodeOptions, preloadSpecifier);

  // On Linux, we could also inject LD_PRELOAD for native interception
  // This requires building a native shared library (future work)
  // if (process.platform === 'linux') {
  //   const nativeLibPath = getNativeLibPath()
  //   if (nativeLibPath) {
  //     const existingPreload = env.LD_PRELOAD || ''
  //     if (!existingPreload.includes('libbroker-intercept')) {
  //       env.LD_PRELOAD = existingPreload ? `${existingPreload}:${nativeLibPath}` : nativeLibPath
  //     }
  //   }
  // }

  return env;
}

/**
 * Merge options with injected environment.
 */
function mergeOptions<T extends SpawnOptions | SpawnSyncOptions | ExecOptions | ExecFileOptions | ForkOptions>(
  options: T | undefined,
  state: InterceptorState
): T {
  const mergedOptions = {...(options || {})} as T;
  mergedOptions.env = buildChildEnv(options?.env || process.env, state.config);
  return mergedOptions;
}

/**
 * Create patched spawn function.
 */
function createPatchedSpawn(): typeof child_process.spawn {
  return function patchedSpawn(
    command: string,
    argsOrOptions?: readonly string[] | SpawnOptions,
    maybeOptions?: SpawnOptions
  ): ChildProcess {
    if (!interceptorState || !interceptorState.initialized) {
      // Pass through to original with proper overload handling
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call
      return (originalSpawn as any)(command, argsOrOptions, maybeOptions);
    }

    // Handle overloaded signatures
    let args: readonly string[] | undefined;
    let options: SpawnOptions | undefined;

    if (Array.isArray(argsOrOptions)) {
      args = argsOrOptions;
      options = maybeOptions;
    } else {
      options = argsOrOptions as SpawnOptions;
    }

    const mergedOptions = mergeOptions(options, interceptorState);
    interceptorState.logger.debug(`spawn: ${command} (with interceptor env)`);

    if (args) {
      return originalSpawn!(command, args, mergedOptions);
    } else {
      return originalSpawn!(command, mergedOptions);
    }
  } as typeof child_process.spawn;
}

/**
 * Create patched spawnSync function.
 */
function createPatchedSpawnSync(): typeof child_process.spawnSync {
  return function patchedSpawnSync(
    command: string,
    argsOrOptions?: readonly string[] | SpawnSyncOptions,
    maybeOptions?: SpawnSyncOptions
  ): SpawnSyncReturns<Buffer | string> {
    if (!interceptorState || !interceptorState.initialized) {
      return originalSpawnSync!(command, argsOrOptions as readonly string[], maybeOptions);
    }

    // Handle overloaded signatures
    let args: readonly string[] | undefined;
    let options: SpawnSyncOptions | undefined;

    if (Array.isArray(argsOrOptions)) {
      args = argsOrOptions;
      options = maybeOptions;
    } else {
      options = argsOrOptions as SpawnSyncOptions;
    }

    const mergedOptions = mergeOptions(options, interceptorState);
    interceptorState.logger.debug(`spawnSync: ${command} (with interceptor env)`);

    if (args) {
      return originalSpawnSync!(command, args, mergedOptions);
    } else {
      return originalSpawnSync!(command, mergedOptions);
    }
  } as typeof child_process.spawnSync;
}

/**
 * Create patched exec function.
 */
function createPatchedExec(): typeof child_process.exec {
  return function patchedExec(
    command: string,
    optionsOrCallback?: ExecOptions | ((error: Error | null, stdout: string, stderr: string) => void),
    maybeCallback?: (error: Error | null, stdout: string, stderr: string) => void
  ): ChildProcess {
    if (!interceptorState || !interceptorState.initialized) {
      // Pass through to original preserving the exact signature
      if (typeof optionsOrCallback === 'function') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call
        return (originalExec as any)(command, optionsOrCallback);
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call
      return (originalExec as any)(command, optionsOrCallback, maybeCallback);
    }

    let options: ExecOptions | undefined;
    let callback: ((error: Error | null, stdout: string, stderr: string) => void) | undefined;

    if (typeof optionsOrCallback === 'function') {
      callback = optionsOrCallback;
    } else {
      options = optionsOrCallback;
      callback = maybeCallback;
    }

    const mergedOptions = mergeOptions(options, interceptorState);
    interceptorState.logger.debug(`exec: ${command} (with interceptor env)`);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call
    return (originalExec as any)(command, mergedOptions, callback);
  } as typeof child_process.exec;
}

/**
 * Create patched fork function.
 */
function createPatchedFork(): typeof child_process.fork {
  return function patchedFork(
    modulePath: string,
    argsOrOptions?: readonly string[] | ForkOptions,
    maybeOptions?: ForkOptions
  ): ChildProcess {
    if (!interceptorState || !interceptorState.initialized) {
      return originalFork!(modulePath, argsOrOptions as readonly string[], maybeOptions);
    }

    // Handle overloaded signatures
    let args: readonly string[] | undefined;
    let options: ForkOptions | undefined;

    if (Array.isArray(argsOrOptions)) {
      args = argsOrOptions;
      options = maybeOptions;
    } else {
      options = argsOrOptions as ForkOptions;
    }

    const mergedOptions = mergeOptions(options, interceptorState);
    interceptorState.logger.debug(`fork: ${modulePath} (with interceptor env)`);

    if (args) {
      return originalFork!(modulePath, args, mergedOptions);
    } else {
      return originalFork!(modulePath, mergedOptions);
    }
  } as typeof child_process.fork;
}

/**
 * Apply child_process patches.
 */
export function applyChildProcessPatches(state: InterceptorState): void {
  if (isChildProcessPatched()) {
    state.logger.warn('child_process already patched, skipping');
    return;
  }

  interceptorState = state;

  // Store originals
  originalSpawn = mutableChildProcess.spawn;
  originalSpawnSync = mutableChildProcess.spawnSync;
  originalExec = mutableChildProcess.exec;
  originalExecSync = mutableChildProcess.execSync;
  originalExecFile = mutableChildProcess.execFile;
  originalExecFileSync = mutableChildProcess.execFileSync;
  originalFork = mutableChildProcess.fork;

  // Helper to safely patch a property with fallback strategies
  const safePatch = (prop: string, value: unknown): boolean => {
    try {
      Object.defineProperty(mutableChildProcess, prop, {
        value,
        writable: true,
        configurable: true
      });
      return true;
    } catch {
      // Property might be non-configurable, try direct assignment
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, security/detect-object-injection
        (mutableChildProcess as any)[prop] = value;
        return true;
      } catch (err) {
        state.logger.warn(`Cannot patch child_process.${prop}: ${err instanceof Error ? err.message : String(err)}`);
        return false;
      }
    }
  };

  // Apply patches
  safePatch('spawn', createPatchedSpawn());
  safePatch('spawnSync', createPatchedSpawnSync());
  safePatch('exec', createPatchedExec());
  safePatch('fork', createPatchedFork());
  syncBuiltinESMExports();
  // execFile and execFileSync follow similar patterns but are less commonly used
  // We can add them later if needed

  state.logger.info('child_process patches applied');
}

/**
 * Remove child_process patches.
 */
export function removeChildProcessPatches(): void {
  if (!isChildProcessPatched()) {
    return;
  }

  // Helper to safely restore a property
  const safeRestore = (prop: string, value: unknown): void => {
    try {
      Object.defineProperty(mutableChildProcess, prop, {
        value,
        writable: true,
        configurable: true
      });
    } catch {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, security/detect-object-injection
        (mutableChildProcess as any)[prop] = value;
      } catch {
        // Ignore - we can't restore
      }
    }
  };

  if (originalSpawn) safeRestore('spawn', originalSpawn);
  if (originalSpawnSync) safeRestore('spawnSync', originalSpawnSync);
  if (originalExec) safeRestore('exec', originalExec);
  if (originalExecSync) safeRestore('execSync', originalExecSync);
  if (originalExecFile) safeRestore('execFile', originalExecFile);
  if (originalExecFileSync) safeRestore('execFileSync', originalExecFileSync);
  if (originalFork) safeRestore('fork', originalFork);
  syncBuiltinESMExports();

  originalSpawn = null;
  originalSpawnSync = null;
  originalExec = null;
  originalExecSync = null;
  originalExecFile = null;
  originalExecFileSync = null;
  originalFork = null;
  interceptorState = null;
}

/**
 * Update state (called when config changes).
 */
export function updateChildProcessState(state: InterceptorState): void {
  interceptorState = state;
}
