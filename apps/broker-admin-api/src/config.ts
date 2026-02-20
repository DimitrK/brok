import {randomBytes} from 'node:crypto';
import * as fs from 'node:fs';

import {OpenApiManifestKeysSchema, type OpenApiManifestKeys} from '@broker-interceptor/schemas';
import {LogLevelSchema, type LogLevel} from '@broker-interceptor/logging';
import {z} from 'zod';

import {staticAdminTokenSchema, type StaticAdminToken} from './contracts';

const numberFromEnv = z.preprocess(value => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return value;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? value : parsed;
}, z.number().int().positive());

const booleanFromEnv = z.preprocess(value => {
  if (typeof value !== 'string') {
    return value;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1') {
    return true;
  }
  if (normalized === 'false' || normalized === '0') {
    return false;
  }

  return value;
}, z.boolean());

const optionalString = z.preprocess(value => {
  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}, z.string().optional());

const parseCorsAllowedOrigins = ({raw, envVarName}: {raw: string | undefined; envVarName: string}) => {
  if (!raw) {
    return [];
  }

  const origins = raw
    .split(',')
    .map(value => value.trim())
    .filter(value => value.length > 0);

  for (const origin of origins) {
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error(`${envVarName} contains an invalid URL origin: ${origin}`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`${envVarName} contains an unsupported origin protocol: ${origin}`);
    }
  }

  return origins;
};

const parseCommaSeparatedKeys = (raw: string | undefined) => {
  if (!raw) {
    return [];
  }

  return raw
    .split(',')
    .map(value => value.trim())
    .filter(value => value.length > 0);
};

const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    BROKER_ADMIN_API_HOST: z.string().default('0.0.0.0'),
    BROKER_ADMIN_API_PORT: numberFromEnv.default(8080),
    BROKER_ADMIN_API_STATE_PATH: optionalString,
    BROKER_ADMIN_API_MAX_BODY_BYTES: numberFromEnv.default(1024 * 1024),
    BROKER_ADMIN_API_AUTH_MODE: z.enum(['static', 'oidc']).default('static'),
    BROKER_ADMIN_API_STATIC_TOKENS_JSON: optionalString,
    BROKER_ADMIN_API_OIDC_ISSUER: optionalString,
    BROKER_ADMIN_API_OIDC_AUDIENCE: optionalString,
    BROKER_ADMIN_API_OIDC_JWKS_URI: optionalString,
    BROKER_ADMIN_API_OIDC_CLIENT_ID: optionalString,
    BROKER_ADMIN_API_OIDC_CLIENT_SECRET: optionalString,
    BROKER_ADMIN_API_OIDC_AUTHORIZATION_URL: optionalString,
    BROKER_ADMIN_API_OIDC_TOKEN_URL: optionalString,
    BROKER_ADMIN_API_OIDC_SCOPE: z.string().default('openid profile email'),
    BROKER_ADMIN_API_OIDC_GOOGLE_CONNECTION: optionalString,
    BROKER_ADMIN_API_OIDC_GITHUB_CONNECTION: optionalString,
    BROKER_ADMIN_API_OAUTH_STATE_TTL_SECONDS: numberFromEnv.default(600),
    BROKER_ADMIN_API_OIDC_ROLE_CLAIM: z.string().default('roles'),
    BROKER_ADMIN_API_OIDC_TENANT_CLAIM: z.string().default('tenant_ids'),
    BROKER_ADMIN_API_OIDC_EMAIL_CLAIM: z.string().default('email'),
    BROKER_ADMIN_API_OIDC_NAME_CLAIM: z.string().default('name'),
    BROKER_ADMIN_API_SECRET_KEY_B64: optionalString,
    BROKER_ADMIN_API_SECRET_KEY_ID: z.string().default('v1'),
    BROKER_ADMIN_API_ENROLLMENT_TOKEN_TTL_SECONDS: numberFromEnv.default(900),
    BROKER_ADMIN_API_CLIENT_CERT_TTL_SECONDS_MAX: numberFromEnv.default(60 * 60 * 24 * 30),
    BROKER_ADMIN_API_CERT_ISSUER_MODE: z.enum(['mock', 'local', 'vault']).optional(),
    BROKER_ADMIN_API_MTLS_CA_PEM: optionalString,
    BROKER_ADMIN_API_LOCAL_CA_CERT_PATH: optionalString,
    BROKER_ADMIN_API_LOCAL_CA_KEY_PATH: optionalString,
    BROKER_ADMIN_API_VAULT_ADDR: optionalString,
    BROKER_ADMIN_API_VAULT_TOKEN: optionalString,
    BROKER_ADMIN_API_VAULT_PKI_MOUNT: z.string().default('pki'),
    BROKER_ADMIN_API_VAULT_PKI_ROLE: optionalString,
    BROKER_ADMIN_API_VAULT_REQUEST_TIMEOUT_MS: numberFromEnv.default(5_000),
    BROKER_ADMIN_API_MANIFEST_KEYS_JSON: optionalString,
    BROKER_ADMIN_API_INFRA_ENABLED: booleanFromEnv.optional(),
    BROKER_ADMIN_API_DATABASE_URL: optionalString,
    BROKER_ADMIN_API_REDIS_URL: optionalString,
    BROKER_ADMIN_API_CORS_ALLOWED_ORIGINS: optionalString,
    BROKER_ADMIN_API_REDIS_CONNECT_TIMEOUT_MS: numberFromEnv.default(2_000),
    BROKER_ADMIN_API_REDIS_KEY_PREFIX: z.string().default('broker-admin-api:control-plane'),
    BROKER_ADMIN_API_LOG_LEVEL: LogLevelSchema.optional(),
    BROKER_ADMIN_API_LOG_REDACT_EXTRA_KEYS: optionalString
  })
  .strict();

export type OidcAuthConfig = {
  mode: 'oidc';
  issuer: string;
  audience: string;
  jwksUri: string;
  oauth: {
    clientId?: string;
    clientSecret?: string;
    authorizationUrl: string;
    tokenUrl: string;
    scope: string;
    stateTtlSeconds: number;
    providerConnections: Partial<Record<'google' | 'github', string>>;
  };
  roleClaim: string;
  tenantClaim: string;
  emailClaim: string;
  nameClaim: string;
};

export type StaticAuthConfig = {
  mode: 'static';
  tokens: StaticAdminToken[];
};

export type AuthConfig = OidcAuthConfig | StaticAuthConfig;

export type MockCertificateIssuerConfig = {
  mode: 'mock';
  mtlsCaPem: string;
};

export type VaultCertificateIssuerConfig = {
  mode: 'vault';
  mtlsCaPem: string;
  vaultAddr: string;
  vaultToken: string;
  vaultPkiMount: string;
  vaultPkiRole: string;
  vaultRequestTimeoutMs: number;
};

export type LocalCertificateIssuerConfig = {
  mode: 'local';
  mtlsCaPem: string;
  caCertPath: string;
  caKeyPath: string;
};

export type CertificateIssuerConfig =
  | MockCertificateIssuerConfig
  | LocalCertificateIssuerConfig
  | VaultCertificateIssuerConfig;

export type ServiceConfig = {
  nodeEnv: 'development' | 'test' | 'production';
  host: string;
  port: number;
  statePath?: string;
  maxBodyBytes: number;
  secretKey: Buffer;
  secretKeyId: string;
  auth: AuthConfig;
  enrollmentTokenTtlSeconds: number;
  clientCertTtlSecondsMax: number;
  certificateIssuer: CertificateIssuerConfig;
  manifestKeys: OpenApiManifestKeys;
  corsAllowedOrigins?: string[];
  infrastructure: {
    enabled: boolean;
    databaseUrl?: string;
    redisUrl?: string;
    redisConnectTimeoutMs: number;
    redisKeyPrefix: string;
  };
  logging: {
    level: LogLevel;
    redactExtraKeys: string[];
  };
};

const DEFAULT_MOCK_CA_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'TU9DS19NVE1MX0NBX0NFUlRfVkFMTVVFX0ZPUl9ERVZFTE9QTUVOVF9BTkRfVEVTVA==',
  '-----END CERTIFICATE-----'
].join('\n');

const parseStaticTokens = (raw?: string): StaticAdminToken[] => {
  if (!raw) {
    throw new Error('BROKER_ADMIN_API_STATIC_TOKENS_JSON is required when auth mode is static');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error('BROKER_ADMIN_API_STATIC_TOKENS_JSON must be valid JSON');
  }

  const tokenSchema = z.array(staticAdminTokenSchema).min(1);
  return tokenSchema.parse(parsed);
};

const parseSecretKey = ({
  encodedKey,
  statePath,
  nodeEnv
}: {
  encodedKey?: string;
  statePath?: string;
  nodeEnv: ServiceConfig['nodeEnv'];
}) => {
  if (encodedKey) {
    const decoded = Buffer.from(encodedKey, 'base64');
    if (decoded.length !== 32) {
      throw new Error('BROKER_ADMIN_API_SECRET_KEY_B64 must decode to exactly 32 bytes');
    }

    return decoded;
  }

  if (statePath || nodeEnv === 'production') {
    throw new Error('BROKER_ADMIN_API_SECRET_KEY_B64 is required for persistent or production deployments');
  }

  return randomBytes(32);
};

const parseManifestKeys = (raw?: string): OpenApiManifestKeys => {
  if (!raw) {
    return OpenApiManifestKeysSchema.parse({keys: []});
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error('BROKER_ADMIN_API_MANIFEST_KEYS_JSON must be valid JSON');
  }

  return OpenApiManifestKeysSchema.parse(parsed);
};

const parseAuthConfig = ({
  mode,
  staticTokens,
  issuer,
  audience,
  jwksUri,
  clientId,
  clientSecret,
  authorizationUrl,
  tokenUrl,
  scope,
  oauthStateTtlSeconds,
  googleConnection,
  githubConnection,
  roleClaim,
  tenantClaim,
  emailClaim,
  nameClaim
}: {
  mode: 'static' | 'oidc';
  staticTokens?: string;
  issuer?: string;
  audience?: string;
  jwksUri?: string;
  clientId?: string;
  clientSecret?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  scope: string;
  oauthStateTtlSeconds: number;
  googleConnection?: string;
  githubConnection?: string;
  roleClaim: string;
  tenantClaim: string;
  emailClaim: string;
  nameClaim: string;
}): AuthConfig => {
  if (mode === 'static') {
    return {
      mode,
      tokens: parseStaticTokens(staticTokens)
    };
  }

  if (!issuer || !audience || !jwksUri) {
    throw new Error(
      'BROKER_ADMIN_API_OIDC_ISSUER, BROKER_ADMIN_API_OIDC_AUDIENCE, and BROKER_ADMIN_API_OIDC_JWKS_URI are required in oidc mode'
    );
  }

  return {
    mode,
    issuer,
    audience,
    jwksUri,
    oauth: {
      ...(clientId ? {clientId} : {}),
      ...(clientSecret ? {clientSecret} : {}),
      authorizationUrl: authorizationUrl ?? new URL('/authorize', issuer).toString(),
      tokenUrl: tokenUrl ?? new URL('/oauth/token', issuer).toString(),
      scope,
      stateTtlSeconds: oauthStateTtlSeconds,
      providerConnections: {
        ...(googleConnection ? {google: googleConnection} : {}),
        ...(githubConnection ? {github: githubConnection} : {})
      }
    },
    roleClaim,
    tenantClaim,
    emailClaim,
    nameClaim
  };
};

const parseCertificateIssuerConfig = ({
  mode,
  nodeEnv,
  mtlsCaPem,
  localCaCertPath,
  localCaKeyPath,
  vaultAddr,
  vaultToken,
  vaultPkiMount,
  vaultPkiRole,
  vaultRequestTimeoutMs
}: {
  mode?: 'mock' | 'local' | 'vault';
  nodeEnv: ServiceConfig['nodeEnv'];
  mtlsCaPem?: string;
  localCaCertPath?: string;
  localCaKeyPath?: string;
  vaultAddr?: string;
  vaultToken?: string;
  vaultPkiMount: string;
  vaultPkiRole?: string;
  vaultRequestTimeoutMs: number;
}): CertificateIssuerConfig => {
  const effectiveMode = mode ?? (nodeEnv === 'production' ? 'vault' : 'mock');
  const effectiveCaPem = mtlsCaPem ?? DEFAULT_MOCK_CA_PEM;

  if (effectiveMode === 'mock') {
    if (nodeEnv === 'production') {
      throw new Error('Mock certificate issuer mode is not allowed in production');
    }

    return {
      mode: 'mock',
      mtlsCaPem: effectiveCaPem
    };
  }

  if (effectiveMode === 'local') {
    if (nodeEnv === 'production') {
      throw new Error('Local certificate issuer mode is not allowed in production');
    }

    if (!localCaCertPath || !localCaKeyPath) {
      throw new Error(
        'BROKER_ADMIN_API_LOCAL_CA_CERT_PATH and BROKER_ADMIN_API_LOCAL_CA_KEY_PATH are required in local certificate mode'
      );
    }

    // Auto-read CA PEM from file if not explicitly provided
    let resolvedMtlsCaPem = mtlsCaPem;
    if (!resolvedMtlsCaPem) {
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- Local CA path is an explicit service configuration boundary.
        resolvedMtlsCaPem = fs.readFileSync(localCaCertPath, 'utf-8');
      } catch (err) {
        throw new Error(
          `Failed to read CA certificate from ${localCaCertPath}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    return {
      mode: 'local',
      mtlsCaPem: resolvedMtlsCaPem,
      caCertPath: localCaCertPath,
      caKeyPath: localCaKeyPath
    };
  }

  if (!vaultAddr || !vaultToken || !vaultPkiRole) {
    throw new Error(
      'BROKER_ADMIN_API_VAULT_ADDR, BROKER_ADMIN_API_VAULT_TOKEN, and BROKER_ADMIN_API_VAULT_PKI_ROLE are required in vault certificate mode'
    );
  }

  if (!mtlsCaPem) {
    throw new Error('BROKER_ADMIN_API_MTLS_CA_PEM is required in vault certificate mode');
  }

  if (nodeEnv === 'production') {
    let parsedVaultUrl: URL;
    try {
      parsedVaultUrl = new URL(vaultAddr);
    } catch {
      throw new Error('BROKER_ADMIN_API_VAULT_ADDR must be a valid URL in vault certificate mode');
    }

    if (parsedVaultUrl.protocol !== 'https:') {
      throw new Error('BROKER_ADMIN_API_VAULT_ADDR must use https in production');
    }
  }

  return {
    mode: 'vault',
    mtlsCaPem: effectiveCaPem,
    vaultAddr,
    vaultToken,
    vaultPkiMount,
    vaultPkiRole,
    vaultRequestTimeoutMs
  };
};

const toEnvInput = (env: NodeJS.ProcessEnv) => ({
  NODE_ENV: env.NODE_ENV,
  BROKER_ADMIN_API_HOST: env.BROKER_ADMIN_API_HOST,
  BROKER_ADMIN_API_PORT: env.BROKER_ADMIN_API_PORT,
  BROKER_ADMIN_API_STATE_PATH: env.BROKER_ADMIN_API_STATE_PATH,
  BROKER_ADMIN_API_MAX_BODY_BYTES: env.BROKER_ADMIN_API_MAX_BODY_BYTES,
  BROKER_ADMIN_API_AUTH_MODE: env.BROKER_ADMIN_API_AUTH_MODE,
  BROKER_ADMIN_API_STATIC_TOKENS_JSON: env.BROKER_ADMIN_API_STATIC_TOKENS_JSON,
  BROKER_ADMIN_API_OIDC_ISSUER: env.BROKER_ADMIN_API_OIDC_ISSUER,
  BROKER_ADMIN_API_OIDC_AUDIENCE: env.BROKER_ADMIN_API_OIDC_AUDIENCE,
  BROKER_ADMIN_API_OIDC_JWKS_URI: env.BROKER_ADMIN_API_OIDC_JWKS_URI,
  BROKER_ADMIN_API_OIDC_CLIENT_ID: env.BROKER_ADMIN_API_OIDC_CLIENT_ID,
  BROKER_ADMIN_API_OIDC_CLIENT_SECRET: env.BROKER_ADMIN_API_OIDC_CLIENT_SECRET,
  BROKER_ADMIN_API_OIDC_AUTHORIZATION_URL: env.BROKER_ADMIN_API_OIDC_AUTHORIZATION_URL,
  BROKER_ADMIN_API_OIDC_TOKEN_URL: env.BROKER_ADMIN_API_OIDC_TOKEN_URL,
  BROKER_ADMIN_API_OIDC_SCOPE: env.BROKER_ADMIN_API_OIDC_SCOPE,
  BROKER_ADMIN_API_OIDC_GOOGLE_CONNECTION: env.BROKER_ADMIN_API_OIDC_GOOGLE_CONNECTION,
  BROKER_ADMIN_API_OIDC_GITHUB_CONNECTION: env.BROKER_ADMIN_API_OIDC_GITHUB_CONNECTION,
  BROKER_ADMIN_API_OAUTH_STATE_TTL_SECONDS: env.BROKER_ADMIN_API_OAUTH_STATE_TTL_SECONDS,
  BROKER_ADMIN_API_OIDC_ROLE_CLAIM: env.BROKER_ADMIN_API_OIDC_ROLE_CLAIM,
  BROKER_ADMIN_API_OIDC_TENANT_CLAIM: env.BROKER_ADMIN_API_OIDC_TENANT_CLAIM,
  BROKER_ADMIN_API_OIDC_EMAIL_CLAIM: env.BROKER_ADMIN_API_OIDC_EMAIL_CLAIM,
  BROKER_ADMIN_API_OIDC_NAME_CLAIM: env.BROKER_ADMIN_API_OIDC_NAME_CLAIM,
  BROKER_ADMIN_API_SECRET_KEY_B64: env.BROKER_ADMIN_API_SECRET_KEY_B64,
  BROKER_ADMIN_API_SECRET_KEY_ID: env.BROKER_ADMIN_API_SECRET_KEY_ID,
  BROKER_ADMIN_API_ENROLLMENT_TOKEN_TTL_SECONDS: env.BROKER_ADMIN_API_ENROLLMENT_TOKEN_TTL_SECONDS,
  BROKER_ADMIN_API_CLIENT_CERT_TTL_SECONDS_MAX: env.BROKER_ADMIN_API_CLIENT_CERT_TTL_SECONDS_MAX,
  BROKER_ADMIN_API_CERT_ISSUER_MODE: env.BROKER_ADMIN_API_CERT_ISSUER_MODE,
  BROKER_ADMIN_API_MTLS_CA_PEM: env.BROKER_ADMIN_API_MTLS_CA_PEM,
  BROKER_ADMIN_API_LOCAL_CA_CERT_PATH: env.BROKER_ADMIN_API_LOCAL_CA_CERT_PATH,
  BROKER_ADMIN_API_LOCAL_CA_KEY_PATH: env.BROKER_ADMIN_API_LOCAL_CA_KEY_PATH,
  BROKER_ADMIN_API_VAULT_ADDR: env.BROKER_ADMIN_API_VAULT_ADDR,
  BROKER_ADMIN_API_VAULT_TOKEN: env.BROKER_ADMIN_API_VAULT_TOKEN,
  BROKER_ADMIN_API_VAULT_PKI_MOUNT: env.BROKER_ADMIN_API_VAULT_PKI_MOUNT,
  BROKER_ADMIN_API_VAULT_PKI_ROLE: env.BROKER_ADMIN_API_VAULT_PKI_ROLE,
  BROKER_ADMIN_API_VAULT_REQUEST_TIMEOUT_MS: env.BROKER_ADMIN_API_VAULT_REQUEST_TIMEOUT_MS,
  BROKER_ADMIN_API_MANIFEST_KEYS_JSON: env.BROKER_ADMIN_API_MANIFEST_KEYS_JSON,
  BROKER_ADMIN_API_INFRA_ENABLED: env.BROKER_ADMIN_API_INFRA_ENABLED,
  BROKER_ADMIN_API_DATABASE_URL: env.BROKER_ADMIN_API_DATABASE_URL,
  BROKER_ADMIN_API_REDIS_URL: env.BROKER_ADMIN_API_REDIS_URL,
  BROKER_ADMIN_API_CORS_ALLOWED_ORIGINS: env.BROKER_ADMIN_API_CORS_ALLOWED_ORIGINS,
  BROKER_ADMIN_API_REDIS_CONNECT_TIMEOUT_MS: env.BROKER_ADMIN_API_REDIS_CONNECT_TIMEOUT_MS,
  BROKER_ADMIN_API_REDIS_KEY_PREFIX: env.BROKER_ADMIN_API_REDIS_KEY_PREFIX,
  BROKER_ADMIN_API_LOG_LEVEL: env.BROKER_ADMIN_API_LOG_LEVEL,
  BROKER_ADMIN_API_LOG_REDACT_EXTRA_KEYS: env.BROKER_ADMIN_API_LOG_REDACT_EXTRA_KEYS
});

export const loadConfig = (env: NodeJS.ProcessEnv = process.env): ServiceConfig => {
  const parsed = envSchema.parse(toEnvInput(env));
  const auth = parseAuthConfig({
    mode: parsed.BROKER_ADMIN_API_AUTH_MODE,
    staticTokens: parsed.BROKER_ADMIN_API_STATIC_TOKENS_JSON,
    issuer: parsed.BROKER_ADMIN_API_OIDC_ISSUER,
    audience: parsed.BROKER_ADMIN_API_OIDC_AUDIENCE,
    jwksUri: parsed.BROKER_ADMIN_API_OIDC_JWKS_URI,
    clientId: parsed.BROKER_ADMIN_API_OIDC_CLIENT_ID,
    clientSecret: parsed.BROKER_ADMIN_API_OIDC_CLIENT_SECRET,
    authorizationUrl: parsed.BROKER_ADMIN_API_OIDC_AUTHORIZATION_URL,
    tokenUrl: parsed.BROKER_ADMIN_API_OIDC_TOKEN_URL,
    scope: parsed.BROKER_ADMIN_API_OIDC_SCOPE,
    oauthStateTtlSeconds: parsed.BROKER_ADMIN_API_OAUTH_STATE_TTL_SECONDS,
    googleConnection: parsed.BROKER_ADMIN_API_OIDC_GOOGLE_CONNECTION,
    githubConnection: parsed.BROKER_ADMIN_API_OIDC_GITHUB_CONNECTION,
    roleClaim: parsed.BROKER_ADMIN_API_OIDC_ROLE_CLAIM,
    tenantClaim: parsed.BROKER_ADMIN_API_OIDC_TENANT_CLAIM,
    emailClaim: parsed.BROKER_ADMIN_API_OIDC_EMAIL_CLAIM,
    nameClaim: parsed.BROKER_ADMIN_API_OIDC_NAME_CLAIM
  });
  const infrastructureEnabled = parsed.BROKER_ADMIN_API_INFRA_ENABLED ?? parsed.NODE_ENV !== 'test';
  if (infrastructureEnabled && (!parsed.BROKER_ADMIN_API_DATABASE_URL || !parsed.BROKER_ADMIN_API_REDIS_URL)) {
    throw new Error(
      'BROKER_ADMIN_API_DATABASE_URL and BROKER_ADMIN_API_REDIS_URL are required when infrastructure is enabled'
    );
  }
  const corsAllowedOrigins = parseCorsAllowedOrigins({
    raw:
      parsed.BROKER_ADMIN_API_CORS_ALLOWED_ORIGINS ??
      (parsed.NODE_ENV === 'production' ? undefined : 'http://localhost:4173'),
    envVarName: 'BROKER_ADMIN_API_CORS_ALLOWED_ORIGINS'
  });
  const loggingLevel = parsed.BROKER_ADMIN_API_LOG_LEVEL ?? (parsed.NODE_ENV === 'test' ? 'silent' : 'info');
  const loggingRedactExtraKeys = parseCommaSeparatedKeys(parsed.BROKER_ADMIN_API_LOG_REDACT_EXTRA_KEYS);

  return {
    nodeEnv: parsed.NODE_ENV,
    host: parsed.BROKER_ADMIN_API_HOST,
    port: parsed.BROKER_ADMIN_API_PORT,
    ...(parsed.BROKER_ADMIN_API_STATE_PATH ? {statePath: parsed.BROKER_ADMIN_API_STATE_PATH} : {}),
    maxBodyBytes: parsed.BROKER_ADMIN_API_MAX_BODY_BYTES,
    secretKey: parseSecretKey({
      encodedKey: parsed.BROKER_ADMIN_API_SECRET_KEY_B64,
      statePath: parsed.BROKER_ADMIN_API_STATE_PATH,
      nodeEnv: parsed.NODE_ENV
    }),
    secretKeyId: parsed.BROKER_ADMIN_API_SECRET_KEY_ID,
    auth,
    enrollmentTokenTtlSeconds: parsed.BROKER_ADMIN_API_ENROLLMENT_TOKEN_TTL_SECONDS,
    clientCertTtlSecondsMax: parsed.BROKER_ADMIN_API_CLIENT_CERT_TTL_SECONDS_MAX,
    certificateIssuer: parseCertificateIssuerConfig({
      mode: parsed.BROKER_ADMIN_API_CERT_ISSUER_MODE,
      nodeEnv: parsed.NODE_ENV,
      mtlsCaPem: parsed.BROKER_ADMIN_API_MTLS_CA_PEM,
      localCaCertPath: parsed.BROKER_ADMIN_API_LOCAL_CA_CERT_PATH,
      localCaKeyPath: parsed.BROKER_ADMIN_API_LOCAL_CA_KEY_PATH,
      vaultAddr: parsed.BROKER_ADMIN_API_VAULT_ADDR,
      vaultToken: parsed.BROKER_ADMIN_API_VAULT_TOKEN,
      vaultPkiMount: parsed.BROKER_ADMIN_API_VAULT_PKI_MOUNT,
      vaultPkiRole: parsed.BROKER_ADMIN_API_VAULT_PKI_ROLE,
      vaultRequestTimeoutMs: parsed.BROKER_ADMIN_API_VAULT_REQUEST_TIMEOUT_MS
    }),
    manifestKeys: parseManifestKeys(parsed.BROKER_ADMIN_API_MANIFEST_KEYS_JSON),
    corsAllowedOrigins,
    infrastructure: {
      enabled: infrastructureEnabled,
      ...(parsed.BROKER_ADMIN_API_DATABASE_URL ? {databaseUrl: parsed.BROKER_ADMIN_API_DATABASE_URL} : {}),
      ...(parsed.BROKER_ADMIN_API_REDIS_URL ? {redisUrl: parsed.BROKER_ADMIN_API_REDIS_URL} : {}),
      redisConnectTimeoutMs: parsed.BROKER_ADMIN_API_REDIS_CONNECT_TIMEOUT_MS,
      redisKeyPrefix: parsed.BROKER_ADMIN_API_REDIS_KEY_PREFIX
    },
    logging: {
      level: loggingLevel,
      redactExtraKeys: loggingRedactExtraKeys
    }
  };
};
