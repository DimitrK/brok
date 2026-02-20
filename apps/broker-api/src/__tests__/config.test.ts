import {describe, expect, it} from 'vitest'

import {loadConfig} from '../config'

describe('broker-api config', () => {
  it('loads defaults from minimal env input', () => {
    const config = loadConfig({
      NODE_ENV: 'test'
    })

    expect(config).toMatchObject({
      nodeEnv: 'test',
      host: '0.0.0.0',
      port: 8081,
      publicBaseUrl: 'https://broker.example',
      maxBodyBytes: 1024 * 1024,
      sessionDefaultTtlSeconds: 900,
      approvalTtlSeconds: 300,
      manifestTtlSeconds: 300,
      dpopMaxSkewSeconds: 300,
      dns_timeout_ms: 2_000,
      corsAllowedOrigins: ['http://localhost:4173'],
      infrastructure: {
        enabled: false,
        redisConnectTimeoutMs: 2_000,
        redisKeyPrefix: 'broker-api:data-plane'
      }
    })
    expect(config.forwarder).toEqual({
      total_timeout_ms: 15_000,
      max_request_body_bytes: 2 * 1024 * 1024,
      max_response_bytes: 2 * 1024 * 1024
    })
    expect(config.logging).toEqual({
      level: 'silent',
      redactExtraKeys: []
    })
    expect(config.tls).toBeUndefined()
  })

  it('parses explicit overrides and ignores unrelated env vars', () => {
    const config = loadConfig({
      NODE_ENV: 'development',
      BROKER_API_HOST: '127.0.0.1',
      BROKER_API_PORT: '9100',
      BROKER_API_PUBLIC_BASE_URL: 'https://broker.internal.example',
      BROKER_API_MAX_BODY_BYTES: '2048',
      BROKER_API_SESSION_DEFAULT_TTL_SECONDS: '1200',
      BROKER_API_APPROVAL_TTL_SECONDS: '45',
      BROKER_API_MANIFEST_TTL_SECONDS: '120',
      BROKER_API_DPOP_MAX_SKEW_SECONDS: '120',
      BROKER_API_FORWARDER_TOTAL_TIMEOUT_MS: '1200',
      BROKER_API_FORWARDER_MAX_REQUEST_BODY_BYTES: '4096',
      BROKER_API_FORWARDER_MAX_RESPONSE_BYTES: '8192',
      BROKER_API_DNS_TIMEOUT_MS: '900',
      BROKER_API_EXPECTED_SAN_URI_PREFIX: 'spiffe://broker/tenants/',
      BROKER_API_STATE_PATH: '/tmp/broker-api-state.json',
      BROKER_API_INITIAL_STATE_JSON: '{"workloads":[],"integrations":[]}',
      BROKER_API_INFRA_ENABLED: 'true',
      BROKER_API_DATABASE_URL: 'postgresql://broker:broker@127.0.0.1:5432/broker',
      BROKER_API_REDIS_URL: 'redis://127.0.0.1:6379',
      BROKER_API_CORS_ALLOWED_ORIGINS: 'http://localhost:4173,https://broker-ui.example',
      BROKER_API_REDIS_CONNECT_TIMEOUT_MS: '1500',
      BROKER_API_REDIS_KEY_PREFIX: 'broker-api:shared',
      BROKER_API_TLS_ENABLED: 'true',
      BROKER_API_TLS_KEY_PATH: '/certs/server.key',
      BROKER_API_TLS_CERT_PATH: '/certs/server.crt',
      BROKER_API_TLS_CLIENT_CA_PATH: '/certs/ca.crt',
      BROKER_API_TLS_REQUIRE_CLIENT_CERT: 'true',
      BROKER_API_TLS_REJECT_UNAUTHORIZED_CLIENT_CERT: 'true',
      UNRELATED_ENV: 'ignored'
    } as NodeJS.ProcessEnv)

    expect(config).toMatchObject({
      nodeEnv: 'development',
      host: '127.0.0.1',
      port: 9100,
      publicBaseUrl: 'https://broker.internal.example',
      maxBodyBytes: 2048,
      sessionDefaultTtlSeconds: 1200,
      approvalTtlSeconds: 45,
      manifestTtlSeconds: 120,
      dpopMaxSkewSeconds: 120,
      dns_timeout_ms: 900,
      corsAllowedOrigins: ['http://localhost:4173', 'https://broker-ui.example'],
      infrastructure: {
        enabled: true,
        databaseUrl: 'postgresql://broker:broker@127.0.0.1:5432/broker',
        redisUrl: 'redis://127.0.0.1:6379',
        redisConnectTimeoutMs: 1500,
        redisKeyPrefix: 'broker-api:shared'
      },
      tls: {
        enabled: true,
        keyPath: '/certs/server.key',
        certPath: '/certs/server.crt',
        clientCaPath: '/certs/ca.crt',
        requireClientCert: true,
        rejectUnauthorizedClientCert: true
      },
      expectedSanUriPrefix: 'spiffe://broker/tenants/',
      statePath: '/tmp/broker-api-state.json',
      initialState: {
        workloads: [],
        integrations: []
      }
    })
    expect(config.forwarder).toEqual({
      total_timeout_ms: 1200,
      max_request_body_bytes: 4096,
      max_response_bytes: 8192
    })
    expect(config.logging).toEqual({
      level: 'info',
      redactExtraKeys: []
    })
  })

  it('rejects invalid initial state json', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'test',
        BROKER_API_INITIAL_STATE_JSON: '{invalid'
      })
    ).toThrow('BROKER_API_INITIAL_STATE_JSON must be valid JSON')
  })

  it('requires state path or initial state in production', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'production',
        BROKER_API_DATABASE_URL: 'postgresql://broker:broker@127.0.0.1:5432/broker',
        BROKER_API_REDIS_URL: 'redis://127.0.0.1:6379',
        BROKER_API_SECRET_KEY_B64: 'yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8='
      })
    ).toThrow('Production requires BROKER_API_STATE_PATH or BROKER_API_INITIAL_STATE_JSON')

    const withStatePath = loadConfig({
      NODE_ENV: 'production',
      BROKER_API_STATE_PATH: '/var/lib/broker-api/state.json',
      BROKER_API_DATABASE_URL: 'postgresql://broker:broker@127.0.0.1:5432/broker',
      BROKER_API_REDIS_URL: 'redis://127.0.0.1:6379',
      BROKER_API_SECRET_KEY_B64: 'yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8='
    })
    expect(withStatePath.statePath).toBe('/var/lib/broker-api/state.json')
  })

  it('requires database and redis urls when infrastructure is enabled', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'development',
        BROKER_API_INFRA_ENABLED: 'true'
      })
    ).toThrow('BROKER_API_DATABASE_URL and BROKER_API_REDIS_URL are required when infrastructure is enabled')
  })

  it('requires TLS key/cert and client CA in mTLS mode when TLS is enabled', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'test',
        BROKER_API_TLS_ENABLED: 'true'
      })
    ).toThrow('BROKER_API_TLS_KEY_PATH and BROKER_API_TLS_CERT_PATH are required when TLS is enabled')

    expect(() =>
      loadConfig({
        NODE_ENV: 'test',
        BROKER_API_TLS_ENABLED: 'true',
        BROKER_API_TLS_KEY_PATH: '/certs/server.key',
        BROKER_API_TLS_CERT_PATH: '/certs/server.crt',
        BROKER_API_TLS_REQUIRE_CLIENT_CERT: 'true'
      })
    ).toThrow('BROKER_API_TLS_CLIENT_CA_PATH is required when TLS is configured to verify client certificates')
  })

  it('does not require client cert verification by default in development TLS mode', () => {
    const config = loadConfig({
      NODE_ENV: 'development',
      BROKER_API_INFRA_ENABLED: 'false',
      BROKER_API_TLS_ENABLED: 'true',
      BROKER_API_TLS_KEY_PATH: '/certs/server.key',
      BROKER_API_TLS_CERT_PATH: '/certs/server.crt'
    })

    expect(config.tls).toMatchObject({
      enabled: true,
      keyPath: '/certs/server.key',
      certPath: '/certs/server.crt',
      requireClientCert: false,
      rejectUnauthorizedClientCert: false
    })
    expect(config.tls?.clientCaPath).toBeUndefined()
  })

  it('defaults to empty CORS origins in production', () => {
    const config = loadConfig({
      NODE_ENV: 'production',
      BROKER_API_STATE_PATH: '/var/lib/broker-api/state.json',
      BROKER_API_DATABASE_URL: 'postgresql://broker:broker@127.0.0.1:5432/broker',
      BROKER_API_REDIS_URL: 'redis://127.0.0.1:6379',
      BROKER_API_SECRET_KEY_B64: 'yOCF/8/MDF8pKtg/UaGstwJ8w8ncBxQ4xcVeO7yXSC8='
    })

    expect(config.corsAllowedOrigins).toEqual([])
  })

  it('parses logging configuration overrides', () => {
    const config = loadConfig({
      NODE_ENV: 'development',
      BROKER_API_INFRA_ENABLED: 'false',
      BROKER_API_LOG_LEVEL: 'debug',
      BROKER_API_LOG_REDACT_EXTRA_KEYS: 'foo,bar , baz'
    })

    expect(config.logging).toEqual({
      level: 'debug',
      redactExtraKeys: ['foo', 'bar', 'baz']
    })
  })
})
