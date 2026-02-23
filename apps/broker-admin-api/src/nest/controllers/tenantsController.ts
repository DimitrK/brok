import {Controller, Get, Inject, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {OpenApiTenantCreateRequestSchema, OpenApiTenantCreateResponseSchema, OpenApiTenantListResponseSchema} from '@broker-interceptor/schemas'

import {requireAnyRole} from '../../auth'
import {badRequest} from '../../errors'
import {parseJsonBody, sendJson} from '../../http'
import {AdminApiControllerContext, listAccessRoles, resolveAuditTenantId, writeAccessRoles} from '../controllerContext'

@Controller()
export class TenantsController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Post('/v1/tenants')
  public async create(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})
        if (!principal.roles.includes('owner')) {
          throw badRequest('tenant_create_forbidden', 'Only owner role can create tenants')
        }

        const body = await parseJsonBody({
          request,
          schema: OpenApiTenantCreateRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const tenant = await this.context.repository.createTenant({name: body.name})
        const payload = OpenApiTenantCreateResponseSchema.parse({tenant_id: tenant.tenant_id})

        sendJson({
          response,
          status: 201,
          correlationId,
          payload
        })

        this.context.appendAuditEventNonBlocking({
          correlationId,
          event: this.context.repository.createAdminAuditEvent({
            actor: principal,
            correlationId,
            action: 'tenant.create',
            tenantId: resolveAuditTenantId({principal, tenantId: tenant.tenant_id}),
            message: `Tenant ${tenant.tenant_id} created`
          })
        })
      }
    })
  }

  @Get('/v1/tenants')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...listAccessRoles]})

        const tenants = (await this.context.repository.listTenants()).filter(tenant =>
          principal.roles.includes('owner') || !principal.tenantIds ? true : principal.tenantIds.includes(tenant.tenant_id)
        )

        const payload = OpenApiTenantListResponseSchema.parse({tenants})
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }
}
