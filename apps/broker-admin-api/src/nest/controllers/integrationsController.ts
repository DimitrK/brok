import {Controller, Get, Inject, Patch, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {
  OpenApiIntegrationCreateResponseSchema,
  OpenApiIntegrationListResponseSchema,
  OpenApiIntegrationSchema,
  OpenApiIntegrationUpdateRequestSchema,
  OpenApiIntegrationWriteSchema
} from '@broker-interceptor/schemas'

import {requireAnyRole, requireTenantScope} from '../../auth'
import {parseJsonBody, sendJson} from '../../http'
import {AdminApiControllerContext, decodePathParam, listAccessRoles, writeAccessRoles} from '../controllerContext'

@Controller()
export class IntegrationsController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Post('/v1/tenants/:tenantId/integrations')
  public async create(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        const tenantId = decodePathParam(request.params.tenantId as string)
        requireTenantScope({principal, tenantId})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const body = await parseJsonBody({
          request,
          schema: OpenApiIntegrationWriteSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const integration = await this.context.repository.createIntegration({
          tenantId,
          payload: body,
          secretKey: this.context.config.secretKey,
          secretKeyId: this.context.config.secretKeyId
        })

        const payload = OpenApiIntegrationCreateResponseSchema.parse({
          integration_id: integration.integration_id
        })

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
            action: 'integration.create',
            tenantId,
            integrationId: integration.integration_id,
            message: `Integration ${integration.integration_id} created`
          })
        })
      }
    })
  }

  @Get('/v1/tenants/:tenantId/integrations')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        const tenantId = decodePathParam(request.params.tenantId as string)
        requireTenantScope({principal, tenantId})
        requireAnyRole({principal, allowed: [...listAccessRoles]})

        const integrations = await this.context.repository.listIntegrations({tenantId})
        const payload = OpenApiIntegrationListResponseSchema.parse({integrations})

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Patch('/v1/integrations/:integrationId')
  public async patch(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const integrationId = decodePathParam(request.params.integrationId as string)
        const integration = await this.context.requireIntegrationTenantScope({principal, integrationId})

        const body = await parseJsonBody({
          request,
          schema: OpenApiIntegrationUpdateRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const updated = await this.context.repository.updateIntegration({
          integrationId,
          enabled: body.enabled,
          templateId: body.template_id
        })

        const payload = OpenApiIntegrationSchema.parse(updated)
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
            action: 'integration.update',
            tenantId: integration.tenant_id,
            integrationId,
            message: `Integration ${integrationId} updated`
          })
        })
      }
    })
  }
}
