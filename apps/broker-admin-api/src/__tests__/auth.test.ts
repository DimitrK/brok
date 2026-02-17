import {describe, expect, it} from 'vitest'

import {
  AdminAuthenticator,
  requireAnyRole,
  requireTenantScope,
  type AdminPrincipal
} from '../auth'
import {isAppError} from '../errors'

const makePrincipal = (overrides?: Partial<AdminPrincipal>): AdminPrincipal => ({
  subject: 'user-1',
  issuer: 'https://broker-admin.local/static',
  email: 'user-1@local.invalid',
  roles: ['admin'],
  tenantIds: ['t_1'],
  authContext: {mode: 'static', issuer: 'https://broker-admin.local/static'},
  ...overrides
})

describe('admin auth', () => {
  it('authenticates static tokens and rejects missing/invalid values', async () => {
    const authenticator = new AdminAuthenticator({
      mode: 'static',
      tokens: [
        {
          token: 'valid-token-value-000000000',
          subject: 'admin@example.com',
          roles: ['owner']
        }
      ]
    })

    const principal = await authenticator.authenticate('Bearer valid-token-value-000000000')
    expect(principal.subject).toBe('admin@example.com')
    expect(principal.issuer).toBe('https://broker-admin.local/static')
    expect(principal.email).toBe('admin@example.com')
    expect(principal.roles).toEqual(['owner'])

    await expect(authenticator.authenticate(undefined)).rejects.toMatchObject({
      code: 'admin_auth_missing'
    })
    await expect(authenticator.authenticate('Bearer wrong')).rejects.toMatchObject({
      code: 'admin_auth_invalid'
    })
  })

  it('enforces role and tenant checks', () => {
    expect(() => requireAnyRole({principal: makePrincipal(), allowed: ['admin']})).not.toThrow()
    try {
      requireAnyRole({principal: makePrincipal(), allowed: ['auditor']})
      throw new Error('expected role check failure')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('admin_forbidden')
    }

    expect(() =>
      requireTenantScope({principal: makePrincipal(), tenantId: 't_1'})
    ).not.toThrow()
    try {
      requireTenantScope({principal: makePrincipal(), tenantId: 't_2'})
      throw new Error('expected tenant scope failure')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('admin_tenant_forbidden')
    }
  })

  it('allows owner principals across tenant scopes', () => {
    const ownerPrincipal = makePrincipal({
      roles: ['owner'],
      tenantIds: undefined
    })

    expect(() =>
      requireTenantScope({
        principal: ownerPrincipal,
        tenantId: 'any-tenant'
      })
    ).not.toThrow()
  })

  it('fails closed for OIDC setup with invalid token exchange', async () => {
    const authenticator = new AdminAuthenticator({
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

    try {
      await authenticator.authenticate('Bearer not-a-real-jwt')
      throw new Error('expected oidc validation failure')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('admin_auth_invalid')
    }
  })
})
