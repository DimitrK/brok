import {beforeEach, describe, expect, it, vi} from 'vitest'

import {isAppError} from '../errors'

const jwtVerifyMock = vi.fn()

vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => ({kind: 'jwks'})),
  jwtVerify: (...args: unknown[]) => Promise.resolve(jwtVerifyMock(...args) as unknown)
}))

import {AdminAuthenticator} from '../auth'

const makeAuthenticator = () =>
  new AdminAuthenticator({
    mode: 'oidc',
    issuer: 'https://idp.example',
    audience: 'broker-admin-api',
    jwksUri: 'https://idp.example/.well-known/jwks.json',
    oauth: {
      clientId: 'oidc-client-id',
      authorizationUrl: 'https://idp.example/authorize',
      tokenUrl: 'https://idp.example/oauth/token',
      scope: 'openid profile email',
      stateTtlSeconds: 600,
      providerConnections: {}
    },
    roleClaim: 'roles',
    tenantClaim: 'tenant_ids',
    emailClaim: 'email',
    nameClaim: 'name'
  })

describe('admin auth oidc parsing', () => {
  beforeEach(() => {
    jwtVerifyMock.mockReset()
  })

  it('parses OIDC principal claims when token verification succeeds', async () => {
    jwtVerifyMock.mockResolvedValue({
      payload: {
        sub: 'oidc-user-1',
        iss: 'https://idp.example',
        email: 'oidc-user-1@example.com',
        name: 'OIDC User One',
        roles: ['admin', 'auditor'],
        tenant_ids: ['t_1'],
        amr: ['pwd', 123],
        acr: 'urn:acr:2fa',
        sid: 'sid_1'
      }
    })

    const principal = await makeAuthenticator().authenticate('Bearer good-token')

    expect(principal.subject).toBe('oidc-user-1')
    expect(principal.issuer).toBe('https://idp.example')
    expect(principal.email).toBe('oidc-user-1@example.com')
    expect(principal.name).toBe('OIDC User One')
    expect(principal.roles).toEqual(['admin', 'auditor'])
    expect(principal.tenantIds).toEqual(['t_1'])
    expect(principal.authContext).toEqual({
      mode: 'oidc',
      issuer: 'https://idp.example',
      amr: ['pwd'],
      acr: 'urn:acr:2fa',
      sid: 'sid_1'
    })
  })

  it('fails closed when OIDC claims are malformed', async () => {
    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        sub: '',
        roles: ['admin']
      }
    })
    await expect(makeAuthenticator().authenticate('Bearer bad-sub-token')).rejects.toMatchObject({
      code: 'admin_auth_invalid'
    })

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        sub: 'user-no-roles',
        email: 'user-no-roles@example.com',
        roles: []
      }
    })
    await expect(makeAuthenticator().authenticate('Bearer no-roles-token')).rejects.toMatchObject({
      code: 'admin_auth_invalid'
    })

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        sub: 'user-no-tenant-array',
        iss: 'https://idp.example',
        email: 'fallback-tenant@example.com',
        roles: ['admin'],
        tenant_ids: 'not-an-array',
        amr: ['pwd'],
        acr: 5
      }
    })
    const principal = await makeAuthenticator().authenticate('Bearer fallback-tenant-token')
    expect(principal.tenantIds).toBeUndefined()
    expect(principal.email).toBe('fallback-tenant@example.com')
    expect(principal.authContext.acr).toBeUndefined()
  })

  it('maps OIDC verifier failures to unauthorized errors', async () => {
    jwtVerifyMock.mockRejectedValue(new Error('jwks unavailable'))

    try {
      await makeAuthenticator().authenticate('Bearer failing-token')
      throw new Error('expected oidc verification to fail')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('admin_auth_invalid')
    }
  })

  it('accepts issuer values that only differ by trailing slash', async () => {
    jwtVerifyMock.mockResolvedValue({
      payload: {
        sub: 'oidc-user-2',
        iss: 'https://idp.example/',
        email: 'oidc-user-2@example.com',
        roles: ['admin']
      }
    })

    const principal = await makeAuthenticator().authenticate('Bearer slash-token')
    expect(principal.subject).toBe('oidc-user-2')
    expect(principal.issuer).toBe('https://idp.example/')
  })
})
