import {Controller, Get, Inject, Patch, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {randomBytes} from 'node:crypto'

import {
  OpenApiAdminAuthProviderListResponseSchema,
  OpenApiAdminOAuthCallbackRequestSchema,
  OpenApiAdminOAuthCallbackResponseSchema,
  OpenApiAdminOAuthStartRequestSchema,
  OpenApiAdminOAuthStartResponseSchema,
  OpenApiAdminSessionResponseSchema,
  OpenApiAdminSignupPolicySchema,
  OpenApiAdminSignupPolicyUpdateRequestSchema
} from '@broker-interceptor/schemas'
import {decodeJwt} from 'jose'

import {requireAnyRole} from '../../auth'
import {badRequest} from '../../errors'
import {parseJsonBody, sendJson, sendNoContent} from '../../http'
import {AdminApiControllerContext, resolveAuditTenantId} from '../controllerContext'

@Controller()
export class AdminAuthController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Get('/v1/admin/auth/providers')
  public async getProviders(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: ({correlationId}) => {
        const interactiveOauthEnabled = this.context.isOidcInteractiveOAuthEnabled()
        const payload = OpenApiAdminAuthProviderListResponseSchema.parse({
          providers: [
            {
              provider: 'google',
              enabled: interactiveOauthEnabled
            },
            {
              provider: 'github',
              enabled: interactiveOauthEnabled
            }
          ]
        })

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Post('/v1/admin/auth/oauth/start')
  public async startOauth(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const oidcAuth = this.context.getInteractiveOidcAuth()
        if (!oidcAuth) {
          throw badRequest('admin_oauth_not_configured', 'OIDC OAuth interactive login is not configured')
        }

        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminOAuthStartRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const now = new Date()
        const nonce = randomBytes(24).toString('base64url')
        const state = this.context.createAdminOAuthState({
          provider: body.provider,
          redirectUri: body.redirect_uri,
          nonce,
          now
        })

        const authorizationUrl = new URL(oidcAuth.oauth.authorizationUrl)
        authorizationUrl.searchParams.set('response_type', 'code')
        authorizationUrl.searchParams.set('client_id', oidcAuth.oauth.clientId)
        authorizationUrl.searchParams.set('redirect_uri', body.redirect_uri)
        authorizationUrl.searchParams.set('scope', oidcAuth.oauth.scope)
        authorizationUrl.searchParams.set('audience', oidcAuth.audience)
        authorizationUrl.searchParams.set('state', state)
        authorizationUrl.searchParams.set('nonce', nonce)
        authorizationUrl.searchParams.set('code_challenge', body.code_challenge)
        authorizationUrl.searchParams.set('code_challenge_method', body.code_challenge_method)

        const connectionHint = this.context.resolveProviderConnectionHint({
          provider: body.provider
        })
        if (connectionHint) {
          authorizationUrl.searchParams.set('connection', connectionHint)
        }

        const payload = OpenApiAdminOAuthStartResponseSchema.parse({
          authorization_url: authorizationUrl.toString(),
          state,
          nonce
        })

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Post('/v1/admin/auth/oauth/callback')
  public async completeOauth(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        if (!this.context.isOidcInteractiveOAuthEnabled()) {
          throw badRequest('admin_oauth_not_configured', 'OIDC OAuth interactive login is not configured')
        }

        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminOAuthCallbackRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const now = new Date()
        const statePayload = this.context.verifyAdminOAuthState({
          state: body.state,
          provider: body.provider,
          redirectUri: body.redirect_uri,
          now
        })

        const tokenExchange = await this.context.exchangeOAuthAuthorizationCode({
          code: body.code,
          redirectUri: body.redirect_uri,
          codeVerifier: body.code_verifier
        })

        let idTokenPayload: ReturnType<typeof decodeJwt> | undefined
        if (tokenExchange.idToken) {
          try {
            idTokenPayload = decodeJwt(tokenExchange.idToken)
          } catch {
            throw badRequest('admin_oauth_callback_invalid', 'OIDC id_token is malformed')
          }

          if (typeof idTokenPayload.nonce !== 'string' || idTokenPayload.nonce !== statePayload.nonce) {
            throw badRequest('admin_oauth_nonce_invalid', 'OIDC nonce validation failed')
          }
        }

        const principal = await this.context.authenticateFromAuthorizationHeader({
          authorizationHeader: `Bearer ${tokenExchange.sessionToken}`,
          context: 'oauth_callback',
          transformAuthenticatedPrincipal: authenticatedPrincipal =>
            this.context.enrichPrincipalWithIdTokenEmailVerification({
              principal: authenticatedPrincipal,
              idTokenPayload
            })
        })

        const payload = OpenApiAdminOAuthCallbackResponseSchema.parse({
          session_id: tokenExchange.sessionToken,
          expires_at: this.context.resolveSessionExpiration({
            idToken: tokenExchange.idToken,
            expiresIn: tokenExchange.expiresIn,
            now
          }),
          principal: {
            subject: principal.subject,
            issuer: principal.issuer,
            email: principal.email,
            ...(principal.name ? {name: principal.name} : {}),
            roles: principal.roles,
            tenant_ids: principal.tenantIds ?? []
          }
        })

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Get('/v1/admin/auth/session')
  public async getSession(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        const payload = OpenApiAdminSessionResponseSchema.parse({
          authenticated: true,
          ...(principal.authContext.sid ? {session_id: principal.authContext.sid} : {}),
          principal: {
            subject: principal.subject,
            issuer: principal.issuer,
            email: principal.email,
            ...(principal.name ? {name: principal.name} : {}),
            roles: principal.roles,
            tenant_ids: principal.tenantIds ?? []
          }
        })

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Post('/v1/admin/auth/logout')
  public async logout(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        sendNoContent({response, correlationId})

        this.context.appendAuditEventNonBlocking({
          correlationId,
          event: this.context.repository.createAdminAuditEvent({
            actor: principal,
            correlationId,
            action: 'admin.auth.logout',
            tenantId: resolveAuditTenantId({principal}),
            message: 'Admin logout acknowledged',
            metadata: {
              auth_mode: principal.authContext.mode,
              session_id: principal.authContext.sid ?? null
            }
          })
        })
      }
    })
  }

  @Get('/v1/admin/auth/signup-policy')
  public async getSignupPolicy(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner', 'admin']})

        const policy = await this.context.repository.getAdminSignupPolicy()
        const payload = OpenApiAdminSignupPolicySchema.parse(policy)

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Patch('/v1/admin/auth/signup-policy')
  public async patchSignupPolicy(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner', 'admin']})

        if (!principal.roles.includes('owner')) {
          throw badRequest('admin_signup_policy_forbidden', 'Only owner role can update admin signup policy')
        }

        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminSignupPolicyUpdateRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const updated =
          body.require_verified_email === undefined && body.allowed_email_domains === undefined
            ? await this.context.dependencyBridge.setAdminSignupMode({
                mode: body.new_user_mode,
                actor: principal
              })
            : await this.context.repository.setAdminSignupPolicy({
                policy: body,
                actor: principal.subject
              })

        const payload = OpenApiAdminSignupPolicySchema.parse(updated)
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })

        this.context.appendAuditEventNonBlocking({
          correlationId,
          event: this.context.repository.createAdminAuditEvent({
            actor: principal,
            correlationId,
            action: 'admin.signup_policy.update',
            tenantId: resolveAuditTenantId({principal}),
            message: `Admin signup mode updated to ${updated.new_user_mode}`
          })
        })
      }
    })
  }
}
