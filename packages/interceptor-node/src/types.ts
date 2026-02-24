/**
 * Configuration types for the broker interceptor.
 *
 * These types define the contract between the interceptor and the broker.
 * The same concepts will apply to the eBPF implementation.
 */

import {z} from 'zod';
import type {
  OpenApiExecuteRequest,
  OpenApiExecuteResponseApprovalRequired,
  OpenApiExecuteResponseExecuted,
  OpenApiManifest
} from '@broker-interceptor/schemas/dist/generated/schemas.js';

/**
 * Logger interface for the interceptor.
 * Defined as a plain interface (not zod) since functions don't need runtime validation.
 */
export interface Logger {
  debug(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

/**
 * Default console logger.
 */
export const defaultLogger: Logger = {
  debug: msg => console.debug(`[broker-interceptor] ${msg}`),
  info: msg => console.info(`[broker-interceptor] ${msg}`),
  warn: msg => console.warn(`[broker-interceptor] ${msg}`),
  error: msg => console.error(`[broker-interceptor] ${msg}`)
};

/**
 * Interceptor configuration provided at initialization.
 * Uses zod for runtime validation of untrusted config input.
 *
 * Session token is optional when mTLS credentials are provided - the interceptor
 * will automatically acquire and refresh session tokens using the certificates.
 */
export const InterceptorConfigSchema = z
  .object({
    /** Base URL of the broker API (e.g., https://broker.example.com) */
    brokerUrl: z.string().url(),

    /** Workload ID for this interceptor instance (required for manifest fetch) */
    workloadId: z.string().min(1),

    /** Path to the manifest file (optional, will fetch from broker if not provided) */
    manifestPath: z.string().optional(),

    /**
     * Session token for authenticating with the broker.
     * Optional when mTLS credentials are provided (auto-acquired).
     */
    sessionToken: z.string().min(1).optional(),

    /** mTLS certificate path (PEM format) */
    mtlsCertPath: z.string().optional(),

    /** mTLS private key path (PEM format) */
    mtlsKeyPath: z.string().optional(),

    /** mTLS CA certificate path (PEM format) - the broker's CA */
    mtlsCaPath: z.string().optional(),

    /** Session TTL in seconds when auto-acquiring (default: 3600 = 1 hour) */
    sessionTtlSeconds: z.number().int().positive().default(3600),

    /** How often to refresh the manifest (in milliseconds, default: 5 minutes) */
    manifestRefreshIntervalMs: z
      .number()
      .int()
      .positive()
      .default(5 * 60 * 1000),

    /** Whether to fail if manifest cannot be fetched (default: true) */
    failOnManifestError: z.boolean().default(true),

    /** How interceptor behaves when manifest refresh fails */
    manifestFailurePolicy: z.enum(['use_last_valid', 'fail_closed', 'fail_open']).default('use_last_valid')
  })
  .refine(
    data => {
      // Must have either sessionToken OR mTLS credentials (cert + key)
      const hasSessionToken = Boolean(data.sessionToken);
      const hasMtlsCreds = Boolean(data.mtlsCertPath && data.mtlsKeyPath);
      return hasSessionToken || hasMtlsCreds;
    },
    {
      message: 'Either sessionToken or mTLS credentials (mtlsCertPath + mtlsKeyPath) must be provided'
    }
  );

/** Input type for InterceptorConfig (before defaults applied) */
export type InterceptorConfig = z.input<typeof InterceptorConfigSchema> & {
  /** Custom logger (optional, not validated by zod) */
  logger?: Logger;
};

/** Resolved config type (after defaults applied) */
export type ResolvedInterceptorConfig = z.output<typeof InterceptorConfigSchema> & {
  logger?: Logger;
};

/**
 * Match rule from the manifest - determines which requests to intercept.
 */
export type MatchRule = OpenApiManifest['match_rules'][number];

/**
 * Parsed manifest with match rules.
 */
export type ParsedManifest = OpenApiManifest;

/**
 * Execute request payload sent to the broker.
 */
export type ExecuteRequest = OpenApiExecuteRequest;

/**
 * Execute response from the broker when request was executed.
 */
export type ExecuteResponseExecuted = OpenApiExecuteResponseExecuted;

/**
 * Execute response from the broker when approval is required.
 */
export type ExecuteResponseApprovalRequired = OpenApiExecuteResponseApprovalRequired;

/**
 * Union of all possible execute responses.
 */
export type ExecuteResponse = ExecuteResponseExecuted | ExecuteResponseApprovalRequired;

export type ManifestFailurePolicy = 'use_last_valid' | 'fail_closed' | 'fail_open';
export type ManifestStateKind = 'missing' | 'valid' | 'stale' | 'expired';

export interface ManifestRuntimeState {
  currentManifest: ParsedManifest | null;
  currentManifestExpiresAt: Date | null;
  lastRefreshAttemptAt: Date | null;
  manifestState: ManifestStateKind;
}

/**
 * Session manager interface for getting tokens.
 */
export interface SessionTokenProvider {
  getToken(): Promise<string>;
  getMtlsCredentials(): {cert: Buffer; key: Buffer; ca?: Buffer};
}

/**
 * Internal state of the interceptor.
 */
export interface InterceptorState {
  config: ResolvedInterceptorConfig;
  manifest: ParsedManifest | null;
  manifestRuntime: ManifestRuntimeState;
  logger: Logger;
  refreshTimer: ReturnType<typeof setInterval> | null;
  initialized: boolean;
  sessionManager: SessionTokenProvider | null;
}
