import {createLocalJWKSet, exportJWK, generateKeyPair, SignJWT} from 'jose';
import {beforeAll, describe, expect, it} from 'vitest';

import {extractAdminClaims, validateIssuerAudience, verifyOidcAccessToken, type OidcJwtKeyResolver} from '../oidc';

const OIDC_ISSUER = 'https://idp.example';
const OIDC_AUDIENCE = 'broker-admin-api';
const OIDC_NOW = new Date('2026-02-14T00:00:00.000Z');
const OIDC_NOW_SECONDS = Math.floor(OIDC_NOW.getTime() / 1000);

const toBase64Url = (input: string) =>
  Buffer.from(input, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

describe('oidc', () => {
  let privateKey: CryptoKey;
  let keyResolver: OidcJwtKeyResolver;

  beforeAll(async () => {
    const generated = await generateKeyPair('RS256');
    privateKey = generated.privateKey;

    const publicJwk = await exportJWK(generated.publicKey);
    publicJwk.kid = 'kid-1';

    keyResolver = createLocalJWKSet({
      keys: [publicJwk]
    });
  });

  const signToken = async (
    {
      subject = 'admin-user',
      issuer = OIDC_ISSUER,
      audience = OIDC_AUDIENCE,
      expiresAt = OIDC_NOW_SECONDS + 300,
      claims = {}
    }: {
      subject?: string;
      issuer?: string;
      audience?: string | string[];
      expiresAt?: number;
      claims?: Record<string, unknown>;
    } = {}
  ) =>
    new SignJWT(claims)
      .setProtectedHeader({alg: 'RS256', kid: 'kid-1', typ: 'at+jwt'})
      .setSubject(subject)
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt(OIDC_NOW_SECONDS)
      .setExpirationTime(expiresAt)
      .sign(privateKey);

  describe('validateIssuerAudience', () => {
    it('validates issuer, audience, and azp requirements', () => {
      const result = validateIssuerAudience({
        issuer: OIDC_ISSUER,
        audience: [OIDC_AUDIENCE, 'another-aud'],
        authorizedParty: 'admin-web-client',
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        expectedAuthorizedParty: 'admin-web-client'
      });

      expect(result).toEqual({
        ok: true,
        issuer: OIDC_ISSUER,
        audience: [OIDC_AUDIENCE, 'another-aud'],
        authorizedParty: 'admin-web-client'
      });
    });

    it('rejects missing azp for multi-audience tokens by default', () => {
      const result = validateIssuerAudience({
        issuer: OIDC_ISSUER,
        audience: [OIDC_AUDIENCE, 'another-aud'],
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });

      expect(result).toEqual({ok: false, error: 'oidc_azp_missing'});
    });

    it('rejects issuer and audience mismatches', () => {
      const issuerMismatch = validateIssuerAudience({
        issuer: 'https://unexpected-idp.example',
        audience: OIDC_AUDIENCE,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });
      expect(issuerMismatch).toEqual({ok: false, error: 'oidc_issuer_mismatch'});

      const audienceMismatch = validateIssuerAudience({
        issuer: OIDC_ISSUER,
        audience: 'other-api',
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });
      expect(audienceMismatch).toEqual({ok: false, error: 'oidc_audience_mismatch'});
    });

    it('returns config errors for invalid verifier inputs', () => {
      const result = validateIssuerAudience({
        issuer: OIDC_ISSUER,
        audience: OIDC_AUDIENCE,
        expectedIssuer: '',
        expectedAudience: []
      });

      expect(result).toEqual({ok: false, error: 'oidc_verifier_config_invalid'});

      const invalidExpectedIssuer = validateIssuerAudience({
        issuer: OIDC_ISSUER,
        audience: OIDC_AUDIENCE,
        expectedIssuer: 'not-a-url',
        expectedAudience: OIDC_AUDIENCE
      });
      expect(invalidExpectedIssuer).toEqual({ok: false, error: 'oidc_verifier_config_invalid'});
    });

    it('can skip azp enforcement for multi-audience tokens when configured', () => {
      const result = validateIssuerAudience({
        issuer: OIDC_ISSUER,
        audience: [OIDC_AUDIENCE, 'another-aud'],
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        requireAzpWhenMultipleAudiences: false
      });

      expect(result).toEqual({
        ok: true,
        issuer: OIDC_ISSUER,
        audience: [OIDC_AUDIENCE, 'another-aud']
      });
    });

    it('rejects non-url issuer claims', () => {
      const result = validateIssuerAudience({
        issuer: 'not-a-url',
        audience: OIDC_AUDIENCE,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });

      expect(result).toEqual({ok: false, error: 'oidc_issuer_invalid'});
    });
  });

  describe('extractAdminClaims', () => {
    it('extracts and normalizes admin claims with default claim names', () => {
      const result = extractAdminClaims({
        payload: {
          sub: 'user-1',
          iss: OIDC_ISSUER,
          email: 'admin@example.com',
          name: 'Admin User',
          roles: ['owner', 'admin'],
          tenant_ids: ['tenant-a', 'tenant-b']
        }
      });

      expect(result).toEqual({
        ok: true,
        claims: {
          subject: 'user-1',
          issuer: OIDC_ISSUER,
          email: 'admin@example.com',
          name: 'Admin User',
          roles: ['owner', 'admin'],
          tenantIds: ['tenant-a', 'tenant-b']
        }
      });
    });

    it('supports custom claim mappings', () => {
      const result = extractAdminClaims({
        payload: {
          subject_id: 'user-2',
          token_issuer: OIDC_ISSUER,
          mail: 'admin2@example.com',
          display_name: 'Admin Two',
          groups: ['auditor'],
          tenant_scope: ['tenant-z']
        },
        subjectClaim: 'subject_id',
        issuerClaim: 'token_issuer',
        emailClaim: 'mail',
        nameClaim: 'display_name',
        roleClaim: 'groups',
        tenantClaim: 'tenant_scope'
      });

      expect(result).toEqual({
        ok: true,
        claims: {
          subject: 'user-2',
          issuer: OIDC_ISSUER,
          email: 'admin2@example.com',
          name: 'Admin Two',
          roles: ['auditor'],
          tenantIds: ['tenant-z']
        }
      });
    });

    it('rejects invalid claims with stable reason codes', () => {
      const invalidRole = extractAdminClaims({
        payload: {
          sub: 'user-1',
          iss: OIDC_ISSUER,
          email: 'admin@example.com',
          roles: ['super_admin']
        }
      });
      expect(invalidRole).toEqual({ok: false, error: 'admin_claims_roles_invalid'});

      const missingTenantScope = extractAdminClaims({
        payload: {
          sub: 'user-1',
          iss: OIDC_ISSUER,
          email: 'admin@example.com',
          roles: ['admin']
        },
        requireTenantScope: true
      });
      expect(missingTenantScope).toEqual({ok: false, error: 'admin_claims_tenant_scope_missing'});

      const invalidEmail = extractAdminClaims({
        payload: {
          sub: 'user-1',
          iss: OIDC_ISSUER,
          email: 'not-an-email',
          roles: ['admin']
        }
      });
      expect(invalidEmail).toEqual({ok: false, error: 'admin_claims_email_invalid'});
    });

    it('rejects invalid payload and claim mapping configuration', () => {
      const invalidPayload = extractAdminClaims({
        payload: 'not-an-object'
      } as unknown as Parameters<typeof extractAdminClaims>[0]);
      expect(invalidPayload).toEqual({ok: false, error: 'admin_claims_payload_invalid'});

      const invalidMapping = extractAdminClaims({
        payload: {
          sub: 'user-1',
          iss: OIDC_ISSUER,
          email: 'admin@example.com',
          roles: ['admin']
        },
        roleClaim: ' '
      });
      expect(invalidMapping).toEqual({ok: false, error: 'admin_claims_mapping_invalid'});
    });
  });

  describe('verifyOidcAccessToken', () => {
    it('verifies a signed OIDC token and returns payload/header', async () => {
      const token = await signToken({
        claims: {
          email: 'admin@example.com',
          roles: ['admin'],
          tenant_ids: ['tenant-a']
        }
      });

      const result = await verifyOidcAccessToken({
        token,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        now: OIDC_NOW
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.payload.sub).toBe('admin-user');
        expect(result.payload.iss).toBe(OIDC_ISSUER);
        expect(result.protectedHeader.alg).toBe('RS256');
      }
    });

    it('rejects malformed and forbidden-alg tokens', async () => {
      const malformed = await verifyOidcAccessToken({
        token: 'not-a-jwt',
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });
      expect(malformed).toEqual({ok: false, error: 'oidc_token_invalid'});

      const forbiddenHeader = toBase64Url(JSON.stringify({alg: 'HS256', typ: 'JWT'}));
      const payload = toBase64Url(
        JSON.stringify({
          sub: 'admin-user',
          iss: OIDC_ISSUER,
          aud: OIDC_AUDIENCE,
          exp: OIDC_NOW_SECONDS + 120
        })
      );

      const forbiddenAlg = await verifyOidcAccessToken({
        token: `${forbiddenHeader}.${payload}.sig`,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });
      expect(forbiddenAlg).toEqual({ok: false, error: 'oidc_alg_forbidden'});

      const forbiddenNoneHeader = toBase64Url(JSON.stringify({alg: 'NONE', typ: 'JWT'}));
      const forbiddenNoneAlg = await verifyOidcAccessToken({
        token: `${forbiddenNoneHeader}.${payload}.sig`,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });
      expect(forbiddenNoneAlg).toEqual({ok: false, error: 'oidc_alg_forbidden'});
    });

    it('rejects tampered signatures and expired tokens', async () => {
      const validToken = await signToken();
      const [header, payload, signature] = validToken.split('.');
      const tamperedSignature = `${signature.slice(0, -1)}${signature.endsWith('A') ? 'B' : 'A'}`;
      const tampered = `${header}.${payload}.${tamperedSignature}`;

      const signatureResult = await verifyOidcAccessToken({
        token: tampered,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        now: OIDC_NOW
      });
      expect(signatureResult).toEqual({ok: false, error: 'oidc_signature_invalid'});

      const expiredToken = await signToken({expiresAt: OIDC_NOW_SECONDS - 10});
      const expired = await verifyOidcAccessToken({
        token: expiredToken,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        now: OIDC_NOW,
        clockToleranceSeconds: 0
      });
      expect(expired).toEqual({ok: false, error: 'oidc_token_expired'});
    });

    it('rejects issuer/audience/azp mismatches after signature verification', async () => {
      const token = await signToken({
        audience: [OIDC_AUDIENCE, 'another-aud']
      });

      const issuerMismatch = await verifyOidcAccessToken({
        token,
        keyResolver,
        expectedIssuer: 'https://different-idp.example',
        expectedAudience: OIDC_AUDIENCE,
        now: OIDC_NOW
      });
      expect(issuerMismatch).toEqual({ok: false, error: 'oidc_issuer_mismatch'});

      const missingAzp = await verifyOidcAccessToken({
        token,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        now: OIDC_NOW
      });
      expect(missingAzp).toEqual({ok: false, error: 'oidc_azp_missing'});
    });

    it('rejects verifier config and algorithm policy violations', async () => {
      const token = await signToken();

      const missingResolver = await verifyOidcAccessToken({
        token,
        keyResolver: undefined as unknown as OidcJwtKeyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });
      expect(missingResolver).toEqual({ok: false, error: 'oidc_verifier_config_invalid'});

      const invalidNow = await verifyOidcAccessToken({
        token,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        now: new Date('invalid')
      });
      expect(invalidNow).toEqual({ok: false, error: 'oidc_now_invalid'});

      const invalidClockTolerance = await verifyOidcAccessToken({
        token,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        clockToleranceSeconds: 301
      });
      expect(invalidClockTolerance).toEqual({ok: false, error: 'oidc_verifier_config_invalid'});

      const invalidAllowedAlgs = await verifyOidcAccessToken({
        token,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        allowedAlgorithms: ['HS256']
      });
      expect(invalidAllowedAlgs).toEqual({ok: false, error: 'oidc_verifier_config_invalid'});

      const algNotAllowed = await verifyOidcAccessToken({
        token,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        allowedAlgorithms: ['RS512']
      });
      expect(algNotAllowed).toEqual({ok: false, error: 'oidc_alg_not_allowed'});
    });

    it('rejects missing alg header and future nbf claims', async () => {
      const payload = toBase64Url(
        JSON.stringify({
          sub: 'admin-user',
          iss: OIDC_ISSUER,
          aud: OIDC_AUDIENCE,
          exp: OIDC_NOW_SECONDS + 120
        })
      );
      const missingAlgHeader = toBase64Url(JSON.stringify({typ: 'JWT'}));

      const missingAlg = await verifyOidcAccessToken({
        token: `${missingAlgHeader}.${payload}.sig`,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE
      });
      expect(missingAlg).toEqual({ok: false, error: 'oidc_alg_invalid'});

      const futureNbfToken = await signToken({
        claims: {
          nbf: OIDC_NOW_SECONDS + 3600
        }
      });
      const futureNbf = await verifyOidcAccessToken({
        token: futureNbfToken,
        keyResolver,
        expectedIssuer: OIDC_ISSUER,
        expectedAudience: OIDC_AUDIENCE,
        now: OIDC_NOW
      });
      expect(futureNbf).toEqual({ok: false, error: 'oidc_token_claims_invalid'});
    });
  });
});
