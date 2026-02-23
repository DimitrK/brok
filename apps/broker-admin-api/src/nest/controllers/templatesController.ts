import {Controller, Get, Inject, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {
  OpenApiTemplateCreateResponseSchema,
  OpenApiTemplateListResponseSchema,
  OpenApiTemplateSchema
} from '@broker-interceptor/schemas'

import {requireAnyRole} from '../../auth'
import {badRequest} from '../../errors'
import {parseJsonBody, sendJson} from '../../http'
import {AdminApiControllerContext, decodePathParam, listAccessRoles, resolveAuditTenantId, writeAccessRoles} from '../controllerContext'

@Controller()
export class TemplatesController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Post('/v1/templates')
  public async create(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const body = await parseJsonBody({
          request,
          schema: OpenApiTemplateSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const created = await this.context.repository.createTemplate({payload: body})
        const payload = OpenApiTemplateCreateResponseSchema.parse(created)

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
            action: 'template.create',
            tenantId: resolveAuditTenantId({principal}),
            message: `Template ${created.template_id} v${created.version} created`
          })
        })
      }
    })
  }

  @Get('/v1/templates')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...listAccessRoles]})

        const templates = await this.context.repository.listTemplates()
        const payload = OpenApiTemplateListResponseSchema.parse({templates})
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Get('/v1/templates/:templateId/versions/:version')
  public async getVersion(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...listAccessRoles]})

        const templateId = decodePathParam(request.params.templateId as string)
        const versionValue = Number.parseInt(decodePathParam(request.params.version as string), 10)
        if (Number.isNaN(versionValue) || versionValue < 1) {
          throw badRequest('template_version_invalid', 'Template version must be a positive integer')
        }

        const template = await this.context.repository.getTemplateVersion({templateId, version: versionValue})
        const payload = OpenApiTemplateSchema.parse(template)
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
