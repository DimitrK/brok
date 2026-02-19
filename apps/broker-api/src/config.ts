import {z} from 'zod'
import {randomBytes} from 'node:crypto'

const numberFromEnv = z.preprocess(value => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return value
  }

  const parsed = Number.parseInt(value, 10)
  return Number.isNaN(parsed) ? value : parsed
}, z.number().int().positive())

const booleanFromEnv = z.preprocess(value => {
  if (typeof value !== 'string') {
    return value
  }

  const normalized = value.trim().toLowerCase()
  if (normalized === 'true' || normalized === '1') {
    return true
  }
  if (normalized === 'false' || normalized === '0') {
    return false
  }

  return value
}, z.boolean())

const optionalString = z.preprocess(value => {
  if (typeof value !== 'string') {
    return undefined
  }

  const trimmed = value.trim()
  return trimmed.length === 0 ? undefined : trimmed
}, z.string().optional())

const optionalJson = z.preprocess(value => {
  if (typeof value !== 'string') {
    return undefined
  }

  const trimmed = value.trim()
  if (trimmed.length === 0) {
    return undefined
  }

  try {
    return JSON.parse(trimmed) as unknown
  } catch {
    return Symbol('invalid_json')
  }
}, z.unknown().optional())

const parseCorsAllowedOrigins = ({
  raw,
  envVarName
}: {
  raw: string | undefined
  envVarName: string
}) => {
  if (!raw) {
    return []
  }

  const origins = raw
    .split(',')
    .map(value => value.trim())
    .filter(value => value.length > 0)

  for (const origin of origins) {
    let parsed: URL
    try {
      parsed = new URL(origin)
    } catch {
      throw new Error(`${envVarName} contains an invalid URL origin: ${origin}`)
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`${envVarName} contains an unsupported origin protocol: ${origin}`)
    }
  }

  return origins
}

const parseSecretKey = ({encodedKey, requireConfiguredKey}: {encodedKey?: string; requireConfiguredKey: boolean}) => {
  if (encodedKey) {
    const decoded = Buffer.from(encodedKey, 'base64');
    if (decoded.length !== 32) {
      throw new Error('BROKER_API_SECRET_KEY_B64 must decode to exactly 32 bytes');
    }
    return decoded;
  }

  if (requireConfiguredKey) {
    throw new Error('BROKER_API_SECRET_KEY_B64 is required when production shared infrastructure is enabled');
  }

  return randomBytes(32);
};

const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    BROKER_API_HOST: z.string().default('0.0.0.0'),
    BROKER_API_PORT: numberFromEnv.default(8081),
    BROKER_API_PUBLIC_BASE_URL: z.string().url().default('https://broker.example'),
    BROKER_API_MAX_BODY_BYTES: numberFromEnv.default(1024 * 1024),
    BROKER_API_SESSION_DEFAULT_TTL_SECONDS: z
      .preprocess(
        value => (typeof value === 'string' && value.trim().length > 0 ? Number.parseInt(value, 10) : value),
        z.number().int().gte(60).lte(3600)
      )
      .default(900),
    BROKER_API_APPROVAL_TTL_SECONDS: numberFromEnv.default(300),
    BROKER_API_MANIFEST_TTL_SECONDS: z
      .preprocess(
        value => (typeof value === 'string' && value.trim().length > 0 ? Number.parseInt(value, 10) : value),
        z.number().int().gte(30).lte(300)
      )
      .default(300),
    BROKER_API_DPOP_MAX_SKEW_SECONDS: numberFromEnv.default(300),
    BROKER_API_FORWARDER_TOTAL_TIMEOUT_MS: numberFromEnv.default(15_000),
    BROKER_API_FORWARDER_MAX_REQUEST_BODY_BYTES: numberFromEnv.default(2 * 1024 * 1024),
    BROKER_API_FORWARDER_MAX_RESPONSE_BYTES: numberFromEnv.default(2 * 1024 * 1024),
    BROKER_API_DNS_TIMEOUT_MS: numberFromEnv.default(2_000),
    BROKER_API_EXPECTED_SAN_URI_PREFIX: optionalString,
    BROKER_API_STATE_PATH: optionalString,
    BROKER_API_INITIAL_STATE_JSON: optionalJson,
    BROKER_API_INFRA_ENABLED: booleanFromEnv.optional(),
    BROKER_API_DATABASE_URL: optionalString,
    BROKER_API_REDIS_URL: optionalString,
    BROKER_API_CORS_ALLOWED_ORIGINS: optionalString,
    BROKER_API_REDIS_CONNECT_TIMEOUT_MS: numberFromEnv.default(2_000),
    BROKER_API_REDIS_KEY_PREFIX: z.string().default('broker-api:data-plane'),
    BROKER_API_TLS_ENABLED: booleanFromEnv.default(false),
    BROKER_API_TLS_KEY_PATH: optionalString,
    BROKER_API_TLS_CERT_PATH: optionalString,
    BROKER_API_TLS_CLIENT_CA_PATH: optionalString,
    BROKER_API_TLS_REQUIRE_CLIENT_CERT: booleanFromEnv.optional(),
    BROKER_API_TLS_REJECT_UNAUTHORIZED_CLIENT_CERT: booleanFromEnv.optional(),
    BROKER_API_SECRET_KEY_B64: optionalString,
    BROKER_API_SECRET_KEY_ID: z.string().trim().min(1).default('v1')
  })
  .strict();

export type ServiceConfig = {
  nodeEnv: 'development' | 'test' | 'production'
  host: string
  port: number
  publicBaseUrl: string
  maxBodyBytes: number
  sessionDefaultTtlSeconds: number
  approvalTtlSeconds: number
  manifestTtlSeconds: number
  dpopMaxSkewSeconds: number
  forwarder: {
    total_timeout_ms: number
    max_request_body_bytes: number
    max_response_bytes: number
  }
  dns_timeout_ms: number
  expectedSanUriPrefix?: string
  statePath?: string
  initialState?: unknown
  corsAllowedOrigins?: string[]
  infrastructure: {
    enabled: boolean
    databaseUrl?: string
    redisUrl?: string
    redisConnectTimeoutMs: number
    redisKeyPrefix: string
  }
  tls?: {
    enabled: true
    keyPath: string
    certPath: string
    clientCaPath?: string
    requireClientCert: boolean
    rejectUnauthorizedClientCert: boolean
  }
  secretKey: Buffer
  secretKeyId: string
}

const toEnvInput = (env: NodeJS.ProcessEnv) => ({
  NODE_ENV: env.NODE_ENV,
  BROKER_API_HOST: env.BROKER_API_HOST,
  BROKER_API_PORT: env.BROKER_API_PORT,
  BROKER_API_PUBLIC_BASE_URL: env.BROKER_API_PUBLIC_BASE_URL,
  BROKER_API_MAX_BODY_BYTES: env.BROKER_API_MAX_BODY_BYTES,
  BROKER_API_SESSION_DEFAULT_TTL_SECONDS: env.BROKER_API_SESSION_DEFAULT_TTL_SECONDS,
  BROKER_API_APPROVAL_TTL_SECONDS: env.BROKER_API_APPROVAL_TTL_SECONDS,
  BROKER_API_MANIFEST_TTL_SECONDS: env.BROKER_API_MANIFEST_TTL_SECONDS,
  BROKER_API_DPOP_MAX_SKEW_SECONDS: env.BROKER_API_DPOP_MAX_SKEW_SECONDS,
  BROKER_API_FORWARDER_TOTAL_TIMEOUT_MS: env.BROKER_API_FORWARDER_TOTAL_TIMEOUT_MS,
  BROKER_API_FORWARDER_MAX_REQUEST_BODY_BYTES: env.BROKER_API_FORWARDER_MAX_REQUEST_BODY_BYTES,
  BROKER_API_FORWARDER_MAX_RESPONSE_BYTES: env.BROKER_API_FORWARDER_MAX_RESPONSE_BYTES,
  BROKER_API_DNS_TIMEOUT_MS: env.BROKER_API_DNS_TIMEOUT_MS,
  BROKER_API_EXPECTED_SAN_URI_PREFIX: env.BROKER_API_EXPECTED_SAN_URI_PREFIX,
  BROKER_API_STATE_PATH: env.BROKER_API_STATE_PATH,
  BROKER_API_INITIAL_STATE_JSON: env.BROKER_API_INITIAL_STATE_JSON,
  BROKER_API_INFRA_ENABLED: env.BROKER_API_INFRA_ENABLED,
  BROKER_API_DATABASE_URL: env.BROKER_API_DATABASE_URL,
  BROKER_API_REDIS_URL: env.BROKER_API_REDIS_URL,
  BROKER_API_CORS_ALLOWED_ORIGINS: env.BROKER_API_CORS_ALLOWED_ORIGINS,
  BROKER_API_REDIS_CONNECT_TIMEOUT_MS: env.BROKER_API_REDIS_CONNECT_TIMEOUT_MS,
  BROKER_API_REDIS_KEY_PREFIX: env.BROKER_API_REDIS_KEY_PREFIX,
  BROKER_API_TLS_ENABLED: env.BROKER_API_TLS_ENABLED,
  BROKER_API_TLS_KEY_PATH: env.BROKER_API_TLS_KEY_PATH,
  BROKER_API_TLS_CERT_PATH: env.BROKER_API_TLS_CERT_PATH,
  BROKER_API_TLS_CLIENT_CA_PATH: env.BROKER_API_TLS_CLIENT_CA_PATH,
  BROKER_API_TLS_REQUIRE_CLIENT_CERT: env.BROKER_API_TLS_REQUIRE_CLIENT_CERT,
  BROKER_API_TLS_REJECT_UNAUTHORIZED_CLIENT_CERT: env.BROKER_API_TLS_REJECT_UNAUTHORIZED_CLIENT_CERT,
  BROKER_API_SECRET_KEY_B64: env.BROKER_API_SECRET_KEY_B64,
  BROKER_API_SECRET_KEY_ID: env.BROKER_API_SECRET_KEY_ID
})

export const loadConfig = (env: NodeJS.ProcessEnv = process.env): ServiceConfig => {
  const parsed = envSchema.parse(toEnvInput(env))
  if (typeof parsed.BROKER_API_INITIAL_STATE_JSON === 'symbol') {
    throw new Error('BROKER_API_INITIAL_STATE_JSON must be valid JSON')
  }

  const statePath = parsed.BROKER_API_STATE_PATH
  const initialState = parsed.BROKER_API_INITIAL_STATE_JSON
  if (parsed.NODE_ENV === 'production' && !statePath && !initialState) {
    throw new Error('Production requires BROKER_API_STATE_PATH or BROKER_API_INITIAL_STATE_JSON')
  }

  const infrastructureEnabled = parsed.BROKER_API_INFRA_ENABLED ?? parsed.NODE_ENV !== 'test'
  if (infrastructureEnabled && (!parsed.BROKER_API_DATABASE_URL || !parsed.BROKER_API_REDIS_URL)) {
    throw new Error('BROKER_API_DATABASE_URL and BROKER_API_REDIS_URL are required when infrastructure is enabled')
  }

  const secretKey = parseSecretKey({
    encodedKey: parsed.BROKER_API_SECRET_KEY_B64,
    requireConfiguredKey: parsed.NODE_ENV === 'production' && infrastructureEnabled
  });

  const tlsRequireClientCert = parsed.BROKER_API_TLS_REQUIRE_CLIENT_CERT ?? parsed.NODE_ENV !== 'development'
  const tlsRejectUnauthorizedClientCert =
    parsed.BROKER_API_TLS_REJECT_UNAUTHORIZED_CLIENT_CERT ?? parsed.NODE_ENV !== 'development'
  if (parsed.BROKER_API_TLS_ENABLED) {
    if (!parsed.BROKER_API_TLS_KEY_PATH || !parsed.BROKER_API_TLS_CERT_PATH) {
      throw new Error('BROKER_API_TLS_KEY_PATH and BROKER_API_TLS_CERT_PATH are required when TLS is enabled')
    }

    if ((tlsRequireClientCert || tlsRejectUnauthorizedClientCert) && !parsed.BROKER_API_TLS_CLIENT_CA_PATH) {
      throw new Error(
        'BROKER_API_TLS_CLIENT_CA_PATH is required when TLS is configured to verify client certificates'
      )
    }
  }
  const corsAllowedOrigins = parseCorsAllowedOrigins({
    raw:
      parsed.BROKER_API_CORS_ALLOWED_ORIGINS ??
      (parsed.NODE_ENV === 'production' ? undefined : 'http://localhost:4173'),
    envVarName: 'BROKER_API_CORS_ALLOWED_ORIGINS'
  })

  return {
    nodeEnv: parsed.NODE_ENV,
    host: parsed.BROKER_API_HOST,
    port: parsed.BROKER_API_PORT,
    publicBaseUrl: parsed.BROKER_API_PUBLIC_BASE_URL,
    maxBodyBytes: parsed.BROKER_API_MAX_BODY_BYTES,
    sessionDefaultTtlSeconds: parsed.BROKER_API_SESSION_DEFAULT_TTL_SECONDS,
    approvalTtlSeconds: parsed.BROKER_API_APPROVAL_TTL_SECONDS,
    manifestTtlSeconds: parsed.BROKER_API_MANIFEST_TTL_SECONDS,
    dpopMaxSkewSeconds: parsed.BROKER_API_DPOP_MAX_SKEW_SECONDS,
    forwarder: {
      total_timeout_ms: parsed.BROKER_API_FORWARDER_TOTAL_TIMEOUT_MS,
      max_request_body_bytes: parsed.BROKER_API_FORWARDER_MAX_REQUEST_BODY_BYTES,
      max_response_bytes: parsed.BROKER_API_FORWARDER_MAX_RESPONSE_BYTES
    },
    dns_timeout_ms: parsed.BROKER_API_DNS_TIMEOUT_MS,
    corsAllowedOrigins,
    infrastructure: {
      enabled: infrastructureEnabled,
      ...(parsed.BROKER_API_DATABASE_URL ? {databaseUrl: parsed.BROKER_API_DATABASE_URL} : {}),
      ...(parsed.BROKER_API_REDIS_URL ? {redisUrl: parsed.BROKER_API_REDIS_URL} : {}),
      redisConnectTimeoutMs: parsed.BROKER_API_REDIS_CONNECT_TIMEOUT_MS,
      redisKeyPrefix: parsed.BROKER_API_REDIS_KEY_PREFIX
    },
    ...(parsed.BROKER_API_EXPECTED_SAN_URI_PREFIX
      ? {expectedSanUriPrefix: parsed.BROKER_API_EXPECTED_SAN_URI_PREFIX}
      : {}),
    ...(statePath ? {statePath} : {}),
    ...(initialState ? {initialState} : {}),
    secretKey,
    secretKeyId: parsed.BROKER_API_SECRET_KEY_ID,
    ...(parsed.BROKER_API_TLS_ENABLED
      ? {
          tls: {
            enabled: true as const,
            keyPath: parsed.BROKER_API_TLS_KEY_PATH as string,
            certPath: parsed.BROKER_API_TLS_CERT_PATH as string,
            ...(parsed.BROKER_API_TLS_CLIENT_CA_PATH ? {clientCaPath: parsed.BROKER_API_TLS_CLIENT_CA_PATH} : {}),
            requireClientCert: tlsRequireClientCert,
            rejectUnauthorizedClientCert: tlsRejectUnauthorizedClientCert
          }
        }
      : {})
  };
}
