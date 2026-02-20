import {describe, expect, it} from 'vitest';

import {loadConfig} from '../config';

const staticTokenJson = JSON.stringify([
  {
    token: 'owner-token-0123456789abcdef',
    subject: 'owner-user',
    roles: ['owner']
  }
]);

const baseEnv = {
  NODE_ENV: 'test',
  BROKER_ADMIN_API_AUTH_MODE: 'static',
  BROKER_ADMIN_API_STATIC_TOKENS_JSON: staticTokenJson,
  BROKER_ADMIN_API_SECRET_KEY_B64: Buffer.alloc(32, 4).toString('base64')
} as const;

describe('config', () => {
  it('loads static auth configuration', () => {
    const config = loadConfig({...baseEnv});
    expect(config.auth.mode).toBe('static');
    if (config.auth.mode === 'static') {
      expect(config.auth.tokens).toHaveLength(1);
    } else {
      throw new Error('expected static auth config');
    }
    expect(config.secretKey.length).toBe(32);
    expect(config.port).toBe(8080);
    expect(config.infrastructure.enabled).toBe(false);
    expect(config.corsAllowedOrigins).toEqual(['http://localhost:4173']);
    expect(config.logging).toEqual({
      level: 'silent',
      redactExtraKeys: []
    });
  });

  it('loads oidc auth configuration', () => {
    const config = loadConfig({
      ...baseEnv,
      BROKER_ADMIN_API_AUTH_MODE: 'oidc',
      BROKER_ADMIN_API_OIDC_ISSUER: 'https://issuer.example',
      BROKER_ADMIN_API_OIDC_AUDIENCE: 'broker-admin-api',
      BROKER_ADMIN_API_OIDC_JWKS_URI: 'https://issuer.example/jwks',
      BROKER_ADMIN_API_OIDC_CLIENT_ID: 'oidc-client-id',
      BROKER_ADMIN_API_STATIC_TOKENS_JSON: undefined
    });

    expect(config.auth.mode).toBe('oidc');
    if (config.auth.mode === 'oidc') {
      expect(config.auth.issuer).toBe('https://issuer.example');
      expect(config.auth.oauth.clientId).toBe('oidc-client-id');
      expect(config.auth.oauth.authorizationUrl).toBe('https://issuer.example/authorize');
      expect(config.auth.oauth.tokenUrl).toBe('https://issuer.example/oauth/token');
    }
  });

  it('rejects persistent deployments without encryption key', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        BROKER_ADMIN_API_SECRET_KEY_B64: undefined,
        BROKER_ADMIN_API_STATE_PATH: '/tmp/state.json'
      })
    ).toThrow('BROKER_ADMIN_API_SECRET_KEY_B64 is required');
  });

  it('rejects invalid static token json', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        BROKER_ADMIN_API_STATIC_TOKENS_JSON: 'not-json'
      })
    ).toThrow('BROKER_ADMIN_API_STATIC_TOKENS_JSON must be valid JSON');
  });

  it('rejects mock certificate issuer mode in production', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        NODE_ENV: 'production',
        BROKER_ADMIN_API_CERT_ISSUER_MODE: 'mock',
        BROKER_ADMIN_API_INFRA_ENABLED: 'false'
      })
    ).toThrow('Mock certificate issuer mode is not allowed in production');
  });

  it('requires database and redis urls when infrastructure is enabled', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        BROKER_ADMIN_API_INFRA_ENABLED: 'true'
      })
    ).toThrow(
      'BROKER_ADMIN_API_DATABASE_URL and BROKER_ADMIN_API_REDIS_URL are required when infrastructure is enabled'
    );
  });

  it('loads infrastructure connection settings when provided', () => {
    const config = loadConfig({
      ...baseEnv,
      BROKER_ADMIN_API_INFRA_ENABLED: 'true',
      BROKER_ADMIN_API_DATABASE_URL: 'postgresql://broker:broker@127.0.0.1:5432/broker',
      BROKER_ADMIN_API_REDIS_URL: 'redis://127.0.0.1:6379/0',
      BROKER_ADMIN_API_CORS_ALLOWED_ORIGINS: 'http://localhost:4173,https://admin.example',
      BROKER_ADMIN_API_REDIS_CONNECT_TIMEOUT_MS: '3500',
      BROKER_ADMIN_API_REDIS_KEY_PREFIX: 'broker-admin-api:test'
    });

    expect(config.infrastructure.enabled).toBe(true);
    expect(config.infrastructure.databaseUrl).toBe('postgresql://broker:broker@127.0.0.1:5432/broker');
    expect(config.infrastructure.redisUrl).toBe('redis://127.0.0.1:6379/0');
    expect(config.infrastructure.redisConnectTimeoutMs).toBe(3500);
    expect(config.infrastructure.redisKeyPrefix).toBe('broker-admin-api:test');
    expect(config.corsAllowedOrigins).toEqual(['http://localhost:4173', 'https://admin.example']);
  });

  it('parses logging configuration overrides', () => {
    const config = loadConfig({
      ...baseEnv,
      BROKER_ADMIN_API_INFRA_ENABLED: 'false',
      BROKER_ADMIN_API_LOG_LEVEL: 'debug',
      BROKER_ADMIN_API_LOG_REDACT_EXTRA_KEYS: 'foo, bar,baz'
    });

    expect(config.logging).toEqual({
      level: 'debug',
      redactExtraKeys: ['foo', 'bar', 'baz']
    });
  });

  it('ignores unrelated environment variables', () => {
    const config = loadConfig({
      ...baseEnv,
      UNRELATED_VARIABLE: 'value'
    } as unknown as NodeJS.ProcessEnv);

    expect(config.auth.mode).toBe('static');
    expect(config.port).toBe(8080);
  });

  it('loads vault certificate issuer timeout defaults', () => {
    const config = loadConfig({
      ...baseEnv,
      BROKER_ADMIN_API_CERT_ISSUER_MODE: 'vault',
      BROKER_ADMIN_API_MTLS_CA_PEM: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
      BROKER_ADMIN_API_VAULT_ADDR: 'https://vault.example',
      BROKER_ADMIN_API_VAULT_TOKEN: 'vault-token',
      BROKER_ADMIN_API_VAULT_PKI_ROLE: 'broker-workload',
      BROKER_ADMIN_API_INFRA_ENABLED: 'false'
    });

    expect(config.certificateIssuer.mode).toBe('vault');
    if (config.certificateIssuer.mode === 'vault') {
      expect(config.certificateIssuer.vaultRequestTimeoutMs).toBe(5000);
    }
  });

  it('loads custom vault request timeout configuration', () => {
    const config = loadConfig({
      ...baseEnv,
      BROKER_ADMIN_API_CERT_ISSUER_MODE: 'vault',
      BROKER_ADMIN_API_MTLS_CA_PEM: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
      BROKER_ADMIN_API_VAULT_ADDR: 'https://vault.example',
      BROKER_ADMIN_API_VAULT_TOKEN: 'vault-token',
      BROKER_ADMIN_API_VAULT_PKI_ROLE: 'broker-workload',
      BROKER_ADMIN_API_VAULT_REQUEST_TIMEOUT_MS: '2500',
      BROKER_ADMIN_API_INFRA_ENABLED: 'false'
    });

    expect(config.certificateIssuer.mode).toBe('vault');
    if (config.certificateIssuer.mode === 'vault') {
      expect(config.certificateIssuer.vaultRequestTimeoutMs).toBe(2500);
    }
  });

  it('rejects non-https vault address in production', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        NODE_ENV: 'production',
        BROKER_ADMIN_API_CERT_ISSUER_MODE: 'vault',
        BROKER_ADMIN_API_MTLS_CA_PEM: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
        BROKER_ADMIN_API_VAULT_ADDR: 'http://vault.example',
        BROKER_ADMIN_API_VAULT_TOKEN: 'vault-token',
        BROKER_ADMIN_API_VAULT_PKI_ROLE: 'broker-workload',
        BROKER_ADMIN_API_INFRA_ENABLED: 'false'
      })
    ).toThrow('BROKER_ADMIN_API_VAULT_ADDR must use https in production');
  });

  it('defaults to empty CORS origins in production', () => {
    const config = loadConfig({
      ...baseEnv,
      NODE_ENV: 'production',
      BROKER_ADMIN_API_INFRA_ENABLED: 'false',
      BROKER_ADMIN_API_CERT_ISSUER_MODE: 'vault',
      BROKER_ADMIN_API_MTLS_CA_PEM: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
      BROKER_ADMIN_API_VAULT_ADDR: 'https://vault.example',
      BROKER_ADMIN_API_VAULT_TOKEN: 'vault-token',
      BROKER_ADMIN_API_VAULT_PKI_ROLE: 'broker-workload'
    });

    expect(config.corsAllowedOrigins).toEqual([]);
  });

  it('loads local certificate issuer configuration', () => {
    const config = loadConfig({
      ...baseEnv,
      BROKER_ADMIN_API_CERT_ISSUER_MODE: 'local',
      BROKER_ADMIN_API_MTLS_CA_PEM: '-----BEGIN CERTIFICATE-----\nLOCAL\n-----END CERTIFICATE-----',
      BROKER_ADMIN_API_LOCAL_CA_CERT_PATH: '/path/to/ca.crt',
      BROKER_ADMIN_API_LOCAL_CA_KEY_PATH: '/path/to/ca.key',
      BROKER_ADMIN_API_INFRA_ENABLED: 'false'
    });

    expect(config.certificateIssuer.mode).toBe('local');
    if (config.certificateIssuer.mode === 'local') {
      expect(config.certificateIssuer.caCertPath).toBe('/path/to/ca.crt');
      expect(config.certificateIssuer.caKeyPath).toBe('/path/to/ca.key');
    }
  });

  it('rejects local certificate issuer mode without CA paths', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        BROKER_ADMIN_API_CERT_ISSUER_MODE: 'local',
        BROKER_ADMIN_API_MTLS_CA_PEM: '-----BEGIN CERTIFICATE-----\nLOCAL\n-----END CERTIFICATE-----',
        BROKER_ADMIN_API_INFRA_ENABLED: 'false'
      })
    ).toThrow(
      'BROKER_ADMIN_API_LOCAL_CA_CERT_PATH and BROKER_ADMIN_API_LOCAL_CA_KEY_PATH are required in local certificate mode'
    );
  });

  it('auto-reads CA PEM from file path in local mode when MTLS_CA_PEM not provided', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        BROKER_ADMIN_API_CERT_ISSUER_MODE: 'local',
        BROKER_ADMIN_API_LOCAL_CA_CERT_PATH: '/nonexistent/ca.crt',
        BROKER_ADMIN_API_LOCAL_CA_KEY_PATH: '/path/to/ca.key',
        BROKER_ADMIN_API_INFRA_ENABLED: 'false'
      })
    ).toThrow('Failed to read CA certificate from /nonexistent/ca.crt');
  });

  it('rejects local certificate issuer mode in production', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        NODE_ENV: 'production',
        BROKER_ADMIN_API_CERT_ISSUER_MODE: 'local',
        BROKER_ADMIN_API_MTLS_CA_PEM: '-----BEGIN CERTIFICATE-----\nLOCAL\n-----END CERTIFICATE-----',
        BROKER_ADMIN_API_LOCAL_CA_CERT_PATH: '/path/to/ca.crt',
        BROKER_ADMIN_API_LOCAL_CA_KEY_PATH: '/path/to/ca.key',
        BROKER_ADMIN_API_INFRA_ENABLED: 'false'
      })
    ).toThrow('Local certificate issuer mode is not allowed in production');
  });
});
