/**
 * Configuration types for the broker interceptor.
 *
 * These types define the contract between the interceptor and the broker.
 * The same concepts will apply to the eBPF implementation.
 */

import {z} from 'zod';

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
    failOnManifestError: z.boolean().default(true)
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
export interface MatchRule {
  integration_id: string;
  provider: string;
  match: {
    hosts: string[];
    schemes: Array<'https'>;
    ports: number[];
    path_groups: string[];
  };
  rewrite: {
    mode: 'execute';
    send_intended_url: boolean;
  };
}

/**
 * Parsed manifest with match rules.
 */
export interface ParsedManifest {
  manifest_version: number;
  issued_at: string;
  expires_at: string;
  broker_execute_url: string;
  dpop_required?: boolean;
  dpop_ath_required?: boolean;
  match_rules: MatchRule[];
  signature: {
    alg: string;
    kid: string;
    jws: string;
  };
}

/**
 * Execute request payload sent to the broker.
 */
export interface ExecuteRequest {
  integration_id: string;
  request: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    url: string;
    headers: Array<{name: string; value: string}>;
    body_base64?: string;
  };
  client_context?: {
    request_id?: string;
    idempotency_key?: string;
    source?: string;
  };
}

/**
 * Execute response from the broker when request was executed.
 */
export interface ExecuteResponseExecuted {
  status: 'executed';
  correlation_id: string;
  upstream: {
    status_code: number;
    headers: Array<{name: string; value: string}>;
    body_base64: string;
  };
}

/**
 * Execute response from the broker when approval is required.
 */
export interface ExecuteResponseApprovalRequired {
  status: 'approval_required';
  approval_id: string;
  expires_at: string;
  correlation_id: string;
  summary: {
    integration_id: string;
    action_group: string;
    risk_tier: 'low' | 'medium' | 'high';
    destination_host: string;
    method: string;
    path: string;
  };
}

/**
 * Execute response from the broker when request was denied.
 */
export interface ExecuteResponseDenied {
  status: 'denied';
  correlation_id: string;
  reason: string;
}

/**
 * Union of all possible execute responses.
 */
export type ExecuteResponse = ExecuteResponseExecuted | ExecuteResponseApprovalRequired | ExecuteResponseDenied;

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
  logger: Logger;
  refreshTimer: ReturnType<typeof setInterval> | null;
  initialized: boolean;
  sessionManager: SessionTokenProvider | null;
}
