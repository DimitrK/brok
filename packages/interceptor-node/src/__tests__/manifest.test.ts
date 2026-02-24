import {describe, expect, it, vi} from 'vitest';
import {generateKeyPairSync, sign as signPayload} from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type {OpenApiManifest, OpenApiManifestKeys} from '@broker-interceptor/schemas/dist/generated/schemas.js';

import {
  fetchManifest,
  shouldRefreshManifest,
  startManifestRefresh,
  validateManifestForInterception,
  verifyManifestSignature
} from '../manifest.js';
import type {Logger, ResolvedInterceptorConfig} from '../types.js';

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

function createSignedManifestFixture(options?: {expiresAt?: string; kid?: string}): {
  manifest: OpenApiManifest;
  keys: OpenApiManifestKeys;
} {
  const keyPair = generateKeyPairSync('ed25519');
  const kid = options?.kid ?? 'key-1';

  const unsignedManifest: Omit<OpenApiManifest, 'signature'> = {
    manifest_version: 1,
    issued_at: new Date().toISOString(),
    expires_at: options?.expiresAt ?? new Date(Date.now() + 60_000).toISOString(),
    broker_execute_url: 'https://broker.example.com/v1/execute',
    match_rules: [
      {
        integration_id: 'int_openai',
        provider: 'openai',
        match: {
          hosts: ['api.openai.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/v1/*']
        },
        rewrite: {
          mode: 'execute',
          send_intended_url: true
        }
      }
    ]
  };

  const payload = canonicalJson(unsignedManifest);
  const protectedHeader = Buffer.from(JSON.stringify({alg: 'EdDSA', kid}), 'utf-8').toString('base64url');
  const payloadSegment = Buffer.from(payload, 'utf-8').toString('base64url');
  const signingInput = Buffer.from(`${protectedHeader}.${payloadSegment}`, 'utf-8');
  const signatureSegment = signPayload(null, signingInput, keyPair.privateKey).toString('base64url');
  const jws = `${protectedHeader}.${payloadSegment}.${signatureSegment}`;
  const publicJwk = keyPair.publicKey.export({format: 'jwk'}) as {x: string};

  return {
    manifest: {
      ...unsignedManifest,
      signature: {
        alg: 'EdDSA',
        kid,
        jws
      }
    },
    keys: {
      keys: [
        {
          kid,
          kty: 'OKP',
          crv: 'Ed25519',
          x: publicJwk.x,
          alg: 'EdDSA',
          use: 'sig'
        }
      ]
    }
  };
}

function createSignedManifestFixtureEs256(): {manifest: OpenApiManifest; keys: OpenApiManifestKeys} {
  const keyPair = generateKeyPairSync('ec', {namedCurve: 'P-256'});
  const kid = 'ec-key-1';

  const unsignedManifest: Omit<OpenApiManifest, 'signature'> = {
    manifest_version: 1,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    broker_execute_url: 'https://broker.example.com/v1/execute',
    match_rules: [
      {
        integration_id: 'int_openai',
        provider: 'openai',
        match: {
          hosts: ['api.openai.com'],
          schemes: ['https'],
          ports: [443],
          path_groups: ['/v1/*']
        },
        rewrite: {
          mode: 'execute',
          send_intended_url: true
        }
      }
    ]
  };

  const payload = canonicalJson(unsignedManifest);
  const protectedHeader = Buffer.from(JSON.stringify({alg: 'ES256', kid}), 'utf-8').toString('base64url');
  const payloadSegment = Buffer.from(payload, 'utf-8').toString('base64url');
  const signingInput = Buffer.from(`${protectedHeader}.${payloadSegment}`, 'utf-8');
  const signatureSegment = signPayload('sha256', signingInput, {
    key: keyPair.privateKey,
    dsaEncoding: 'ieee-p1363'
  }).toString('base64url');
  const jws = `${protectedHeader}.${payloadSegment}.${signatureSegment}`;
  const publicJwk = keyPair.publicKey.export({format: 'jwk'}) as {x: string; y: string};

  return {
    manifest: {
      ...unsignedManifest,
      signature: {
        alg: 'ES256',
        kid,
        jws
      }
    },
    keys: {
      keys: [
        {
          kid,
          kty: 'EC',
          crv: 'P-256',
          x: publicJwk.x,
          y: publicJwk.y,
          alg: 'ES256',
          use: 'sig'
        }
      ]
    }
  };
}

function createLoggerCollector(): {
  logger: Logger;
  messages: string[];
} {
  const messages: string[] = [];
  const capture = (message: string) => {
    messages.push(message);
  };

  return {
    logger: {
      debug: capture,
      info: capture,
      warn: capture,
      error: capture
    },
    messages
  };
}

function createConfig(overrides?: Partial<ResolvedInterceptorConfig>): ResolvedInterceptorConfig {
  return {
    brokerUrl: 'https://broker.example.com',
    workloadId: 'w_test',
    sessionToken: 'tok_test',
    sessionTtlSeconds: 3600,
    manifestRefreshIntervalMs: 100,
    failOnManifestError: true,
    manifestFailurePolicy: 'use_last_valid',
    ...overrides
  };
}

describe('verifyManifestSignature', () => {
  it('accepts a valid signed manifest', () => {
    const fixture = createSignedManifestFixture();
    const result = verifyManifestSignature(fixture.manifest, fixture.keys);
    expect(result.ok).toBe(true);
  });

  it('rejects manifests with unknown kid', () => {
    const fixture = createSignedManifestFixture();
    const result = verifyManifestSignature(fixture.manifest, {
      keys: [
        {
          ...fixture.keys.keys[0],
          kid: 'unknown-key'
        }
      ]
    });

    expect(result.ok).toBe(false);
  });

  it('rejects manifests with payload mismatch', () => {
    const fixture = createSignedManifestFixture();
    const tamperedManifest: OpenApiManifest = {
      ...fixture.manifest,
      broker_execute_url: 'https://malicious.example.com/v1/execute'
    };

    const result = verifyManifestSignature(tamperedManifest, fixture.keys);
    expect(result.ok).toBe(false);
  });

  it('supports ES256 signed manifests', () => {
    const fixture = createSignedManifestFixtureEs256();
    const result = verifyManifestSignature(fixture.manifest, fixture.keys);
    expect(result.ok).toBe(true);
  });

  it('rejects manifests when signature algorithm metadata mismatches key metadata', () => {
    const fixture = createSignedManifestFixture();
    const result = verifyManifestSignature(
      {
        ...fixture.manifest,
        signature: {
          ...fixture.manifest.signature,
          alg: 'ES256'
        }
      },
      fixture.keys
    );
    expect(result.ok).toBe(false);
  });

  it('rejects manifests with invalid JWS signature bytes', () => {
    const fixture = createSignedManifestFixture();
    const [headerSegment, payloadSegment] = fixture.manifest.signature.jws.split('.');
    const result = verifyManifestSignature(
      {
        ...fixture.manifest,
        signature: {
          ...fixture.manifest.signature,
          jws: `${headerSegment}.${payloadSegment}.${Buffer.from('invalid-signature').toString('base64url')}`
        }
      },
      fixture.keys
    );

    expect(result.ok).toBe(false);
  });

  it('rejects manifests with malformed protected header JSON', () => {
    const fixture = createSignedManifestFixture();
    const [, payloadSegment, signatureSegment] = fixture.manifest.signature.jws.split('.');
    const badHeader = Buffer.from('{not-json}', 'utf-8').toString('base64url');
    const result = verifyManifestSignature(
      {
        ...fixture.manifest,
        signature: {
          ...fixture.manifest.signature,
          jws: `${badHeader}.${payloadSegment}.${signatureSegment}`
        }
      },
      fixture.keys
    );
    expect(result.ok).toBe(false);
  });

  it('rejects malformed JWS payloads', () => {
    const fixture = createSignedManifestFixture();
    const result = verifyManifestSignature(
      {
        ...fixture.manifest,
        signature: {...fixture.manifest.signature, jws: 'not-a-jws'}
      },
      fixture.keys
    );
    expect(result.ok).toBe(false);
  });

  it('rejects signatures where protected header mismatches manifest metadata', () => {
    const fixture = createSignedManifestFixture();
    const [headerSegment, payloadSegment, signatureSegment] = fixture.manifest.signature.jws.split('.');
    const wrongHeaderSegment = Buffer.from(JSON.stringify({alg: 'EdDSA', kid: 'different-kid'}), 'utf-8').toString(
      'base64url'
    );

    const result = verifyManifestSignature(
      {
        ...fixture.manifest,
        signature: {
          ...fixture.manifest.signature,
          jws: `${wrongHeaderSegment}.${payloadSegment}.${signatureSegment}`
        }
      },
      fixture.keys
    );

    // Keep variable used for readability when debugging failures
    expect(headerSegment.length).toBeGreaterThan(0);
    expect(result.ok).toBe(false);
  });
});

describe('validateManifestForInterception', () => {
  it('rejects wildcard hosts', () => {
    const fixture = createSignedManifestFixture();
    const manifest: OpenApiManifest = {
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            hosts: ['*.openai.com']
          }
        }
      ]
    };

    const result = validateManifestForInterception(manifest);
    expect(result.ok).toBe(false);
  });

  it('rejects invalid regex patterns in path groups', () => {
    const fixture = createSignedManifestFixture();
    const manifest: OpenApiManifest = {
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            path_groups: ['^/v1/(bad$']
          }
        }
      ]
    };

    const result = validateManifestForInterception(manifest);
    expect(result.ok).toBe(false);
  });

  it('rejects regex patterns that are not anchored', () => {
    const fixture = createSignedManifestFixture();
    const manifest: OpenApiManifest = {
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            path_groups: ['^/v1/.*']
          }
        }
      ]
    };

    const result = validateManifestForInterception(manifest);
    expect(result.ok).toBe(false);
  });

  it('rejects prefix patterns that do not start with /', () => {
    const fixture = createSignedManifestFixture();
    const result = validateManifestForInterception({
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            path_groups: ['v1/*']
          }
        }
      ]
    });

    expect(result.ok).toBe(false);
  });

  it('rejects non-root prefix wildcard patterns', () => {
    const fixture = createSignedManifestFixture();
    const result = validateManifestForInterception({
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            path_groups: ['/*']
          }
        }
      ]
    });

    expect(result.ok).toBe(false);
  });

  it('rejects exact patterns that do not start with /', () => {
    const fixture = createSignedManifestFixture();
    const result = validateManifestForInterception({
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            path_groups: ['v1/chat']
          }
        }
      ]
    });

    expect(result.ok).toBe(false);
  });

  it('rejects wildcards outside the suffix form /*', () => {
    const fixture = createSignedManifestFixture();
    const result = validateManifestForInterception({
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            path_groups: ['/v1/*/chat']
          }
        }
      ]
    });

    expect(result.ok).toBe(false);
  });
});

describe('fetchManifest', () => {
  it('accepts valid keys+manifest and does not log sensitive payloads', async () => {
    const fixture = createSignedManifestFixture();
    const {logger, messages} = createLoggerCollector();

    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: JSON.stringify(fixture.manifest)}
        )
    );

    const signingKeyX = fixture.keys.keys[0].x ?? '';
    expect(result.ok).toBe(true);
    expect(messages.some(message => message.includes(fixture.manifest.signature.jws))).toBe(false);
    expect(messages.some(message => message.includes(signingKeyX))).toBe(false);
    expect(messages.some(message => message.includes('"keys"'))).toBe(false);
  });

  it('rejects expired manifest', async () => {
    const fixture = createSignedManifestFixture({expiresAt: new Date(Date.now() - 60_000).toISOString()});
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: JSON.stringify(fixture.manifest)}
        )
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Manifest expired');
    }
  });

  it('rejects unknown kid at fetch time', async () => {
    const fixture = createSignedManifestFixture({kid: 'expected-kid'});
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {
                status: 200,
                body: JSON.stringify({
                  keys: [{...fixture.keys.keys[0], kid: 'other-kid'}]
                } satisfies OpenApiManifestKeys)
              }
            : {status: 200, body: JSON.stringify(fixture.manifest)}
        )
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('signing key not found');
    }
  });

  it('retries keys fetch once on kid mismatch and succeeds when refreshed keys include manifest kid', async () => {
    const fixture = createSignedManifestFixture({kid: 'expected-kid'});
    const staleKeys: OpenApiManifestKeys = {
      keys: [{...fixture.keys.keys[0], kid: 'stale-kid'}]
    };
    const {logger, messages} = createLoggerCollector();

    let keysCalls = 0;
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url => {
        if (url.endsWith('/v1/keys/manifest')) {
          keysCalls += 1;
          return Promise.resolve({
            status: 200,
            body: JSON.stringify(keysCalls === 1 ? staleKeys : fixture.keys)
          });
        }
        return Promise.resolve({status: 200, body: JSON.stringify(fixture.manifest)});
      }
    );

    expect(result.ok).toBe(true);
    expect(keysCalls).toBe(2);
    expect(messages.some(message => message.includes('refetching manifest keys once'))).toBe(true);
  });

  it('returns deterministic error when keys refetch fails after kid mismatch', async () => {
    const fixture = createSignedManifestFixture({kid: 'expected-kid'});
    const staleKeys: OpenApiManifestKeys = {
      keys: [{...fixture.keys.keys[0], kid: 'stale-kid'}]
    };
    const {logger} = createLoggerCollector();

    let keysCalls = 0;
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url => {
        if (url.endsWith('/v1/keys/manifest')) {
          keysCalls += 1;
          if (keysCalls === 1) {
            return Promise.resolve({status: 200, body: JSON.stringify(staleKeys)});
          }
          return Promise.resolve({status: 503, body: 'unavailable'});
        }
        return Promise.resolve({status: 200, body: JSON.stringify(fixture.manifest)});
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Manifest key refetch failed after kid mismatch');
      expect(result.error).toContain('HTTP 503');
    }
  });

  it('fails without keys refetch when signature failure is not a kid mismatch', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const [headerSegment, payloadSegment] = fixture.manifest.signature.jws.split('.');
    const badSignatureManifest: OpenApiManifest = {
      ...fixture.manifest,
      signature: {
        ...fixture.manifest.signature,
        jws: `${headerSegment}.${payloadSegment}.${Buffer.from('invalid-signature').toString('base64url')}`
      }
    };

    let keysCalls = 0;
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url => {
        if (url.endsWith('/v1/keys/manifest')) {
          keysCalls += 1;
          return Promise.resolve({status: 200, body: JSON.stringify(fixture.keys)});
        }
        return Promise.resolve({status: 200, body: JSON.stringify(badSignatureManifest)});
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Manifest signature verification failed');
    }
    expect(keysCalls).toBe(1);
  });

  it('rejects invalid path_groups during manifest load', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const badManifest: OpenApiManifest = {
      ...fixture.manifest,
      match_rules: [
        {
          ...fixture.manifest.match_rules[0],
          match: {
            ...fixture.manifest.match_rules[0].match,
            path_groups: ['/v1/*bad']
          }
        }
      ]
    };
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: JSON.stringify(badManifest)}
        )
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('path_groups');
    }
  });

  it('fails when manifest keys payload is invalid JSON', async () => {
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(createConfig(), logger, undefined, () => Promise.resolve({status: 200, body: '{'}));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Manifest keys response is not valid JSON');
    }
  });

  it('fails when manifest keys payload fails schema validation', async () => {
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      () => Promise.resolve({status: 200, body: JSON.stringify({not_keys: true})})
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Manifest keys response failed schema validation');
    }
  });

  it('fails when manifest payload is invalid JSON', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: '{'}
        )
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Manifest response is not valid JSON');
    }
  });

  it('fails when manifest payload fails schema validation', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: JSON.stringify({manifest_version: 1})}
        )
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Manifest response failed schema validation');
    }
  });

  it('fails when manifest endpoint returns non-200', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 503, body: 'unavailable'}
        )
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Failed to fetch manifest: HTTP 503');
    }
  });

  it('fails closed when session token provider throws', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig({sessionToken: undefined}),
      logger,
      {
        getToken: () => Promise.reject(new Error('token provider down')),
        getMtlsCredentials: () => ({cert: Buffer.from('c'), key: Buffer.from('k')})
      },
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: JSON.stringify(fixture.manifest)}
        )
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Failed to get session token');
    }
  });

  it('returns deterministic error when mTLS paths are invalid', async () => {
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(createConfig({mtlsCertPath: 'relative/cert.pem'}), logger);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Failed to load mTLS credentials');
    }
  });

  it('loads absolute mTLS cert/key/ca paths for manifest and keys fetches', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'manifest-mtls-test-'));
    const certPath = path.join(tempDir, 'workload.crt');
    const keyPath = path.join(tempDir, 'workload.key');
    const caPath = path.join(tempDir, 'ca.pem');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    fs.writeFileSync(certPath, 'cert');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    fs.writeFileSync(keyPath, 'key');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    fs.writeFileSync(caPath, 'ca');

    try {
      const result = await fetchManifest(
        createConfig({mtlsCertPath: certPath, mtlsKeyPath: keyPath, mtlsCaPath: caPath}),
        logger,
        undefined,
        (url, options) => {
          expect(options).toBeDefined();
          if (!options) {
            throw new Error('Expected request options to be defined');
          }
          expect(options.mtlsCert).toBeDefined();
          expect(options.mtlsKey).toBeDefined();
          expect(options.mtlsCa).toBeDefined();
          return Promise.resolve(
            url.endsWith('/v1/keys/manifest')
              ? {status: 200, body: JSON.stringify(fixture.keys)}
              : {status: 200, body: JSON.stringify(fixture.manifest)}
          );
        }
      );

      expect(result.ok).toBe(true);
    } finally {
      fs.rmSync(tempDir, {recursive: true, force: true});
    }
  });

  it('rejects suspicious mTLS paths containing traversal markers', async () => {
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(createConfig({mtlsCertPath: '/tmp/..unsafe/cert.pem'}), logger);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('contains path traversal');
    }
  });

  it('fails when neither static token nor provider is available', async () => {
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(createConfig({sessionToken: undefined}), logger);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('No session token available for manifest fetch');
    }
  });

  it('supports successful token provider flow', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig({sessionToken: undefined}),
      logger,
      {
        getToken: () => Promise.resolve('tok_from_provider'),
        getMtlsCredentials: () => ({cert: Buffer.from('c'), key: Buffer.from('k')})
      },
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: JSON.stringify(fixture.manifest)}
        )
    );
    expect(result.ok).toBe(true);
  });

  it('supports manifestPath local file loading', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'manifest-test-'));
    const manifestPath = path.join(tempDir, 'manifest.json');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    fs.writeFileSync(manifestPath, JSON.stringify(fixture.manifest), 'utf-8');

    try {
      const result = await fetchManifest(
        createConfig({manifestPath}),
        logger,
        undefined,
        () =>
          Promise.resolve({
            status: 200,
            body: JSON.stringify(fixture.keys)
          })
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.manifest.signature.kid).toBe(fixture.manifest.signature.kid);
      }
    } finally {
      fs.rmSync(tempDir, {recursive: true, force: true});
    }
  });

  it('fails when manifestPath file contents are invalid', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'manifest-test-invalid-'));
    const manifestPath = path.join(tempDir, 'manifest.json');
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    fs.writeFileSync(manifestPath, '{', 'utf-8');

    try {
      const result = await fetchManifest(
        createConfig({manifestPath}),
        logger,
        undefined,
        () =>
          Promise.resolve({
            status: 200,
            body: JSON.stringify(fixture.keys)
          })
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('Manifest response is not valid JSON');
      }
    } finally {
      fs.rmSync(tempDir, {recursive: true, force: true});
    }
  });

  it('fails when fetch throws unexpected error', async () => {
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const result = await fetchManifest(
      createConfig(),
      logger,
      undefined,
      url =>
        url.endsWith('/v1/keys/manifest')
          ? Promise.resolve({status: 200, body: JSON.stringify(fixture.keys)})
          : Promise.reject(new Error('transport down'))
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('Failed to fetch manifest: transport down');
    }
  });
});

describe('manifest refresh helpers', () => {
  it('shouldRefreshManifest returns true near expiry', () => {
    const fixture = createSignedManifestFixture({expiresAt: new Date(Date.now() + 1_000).toISOString()});
    expect(shouldRefreshManifest(fixture.manifest, 5)).toBe(true);
  });

  it('startManifestRefresh triggers update callback', async () => {
    vi.useFakeTimers();
    const fixture = createSignedManifestFixture();
    const {logger} = createLoggerCollector();
    const onUpdate = vi.fn();
    const onError = vi.fn();

    const timer = startManifestRefresh(
      createConfig({manifestRefreshIntervalMs: 10}),
      logger,
      onUpdate,
      onError,
      undefined,
      url =>
        Promise.resolve(
          url.endsWith('/v1/keys/manifest')
            ? {status: 200, body: JSON.stringify(fixture.keys)}
            : {status: 200, body: JSON.stringify(fixture.manifest)}
        )
    );

    await vi.advanceTimersByTimeAsync(20);
    clearInterval(timer);
    vi.useRealTimers();

    expect(onUpdate).toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  it('startManifestRefresh triggers error callback on refresh failure', async () => {
    vi.useFakeTimers();
    const {logger} = createLoggerCollector();
    const onUpdate = vi.fn();
    const onError = vi.fn();

    const timer = startManifestRefresh(
      createConfig({manifestRefreshIntervalMs: 10}),
      logger,
      onUpdate,
      onError,
      undefined,
      () => Promise.resolve({status: 500, body: 'boom'})
    );

    await vi.advanceTimersByTimeAsync(20);
    clearInterval(timer);
    vi.useRealTimers();

    expect(onUpdate).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalled();
  });
});
