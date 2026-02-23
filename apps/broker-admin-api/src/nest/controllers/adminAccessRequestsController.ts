import {Controller, Get, Inject, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {
  OpenApiAdminAccessRequestApproveRequestSchema,
  OpenApiAdminAccessRequestDenyRequestSchema,
  OpenApiAdminAccessRequestListResponseSchema,
  OpenApiAdminAccessRequestSchema
} from '@broker-interceptor/schemas'

import {requireAnyRole} from '../../auth'
import {parseJsonBody, parseQuery, sendJson} from '../../http'
import {
  AdminApiControllerContext,
  adminAccessRequestListQuerySchema,
  decodePathParam,
  resolveAuditTenantId
} from '../controllerContext'

@Controller()
export class AdminAccessRequestsController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Get('/v1/admin/access-requests')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId, url}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner']})

        const query = parseQuery({
          searchParams: url.searchParams,
          schema: adminAccessRequestListQuerySchema
        })
        const requests = await this.context.dependencyBridge.listAdminAccessRequests({
          actor: principal,
          ...(query.status ? {status: query.status} : {}),
          ...(query.tenant_id ? {tenantId: query.tenant_id} : {}),
          ...(query.role ? {role: query.role} : {}),
          ...(query.search ? {search: query.search} : {}),
          ...(typeof query.limit === 'number' ? {limit: query.limit} : {}),
          ...(query.cursor ? {cursor: query.cursor} : {})
        })

        const payload = OpenApiAdminAccessRequestListResponseSchema.parse(requests)
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Post('/v1/admin/access-requests/:requestId/approve')
  public async approve(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner']})

        const requestId = decodePathParam(request.params.requestId as string)
        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminAccessRequestApproveRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })
        const approved = await this.context.dependencyBridge.approveAdminAccessRequestWithOverrides({
          requestId,
          actor: principal,
          ...(body.roles !== undefined ? {roles: body.roles} : {}),
          ...(body.tenant_ids !== undefined ? {tenantIds: body.tenant_ids} : {}),
          ...(body.reason !== undefined ? {reason: body.reason} : {})
        })

        const payload = OpenApiAdminAccessRequestSchema.parse(approved)
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
            action: 'admin.access_request.approve',
            tenantId: resolveAuditTenantId({principal}),
            message: `Admin access request ${requestId} approved`
          })
        })
      }
    })
  }

  @Post('/v1/admin/access-requests/:requestId/deny')
  public async deny(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner']})

        const requestId = decodePathParam(request.params.requestId as string)
        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminAccessRequestDenyRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })
        const denied = await this.context.dependencyBridge.denyAdminAccessRequest({
          requestId,
          actor: principal,
          reason: body.reason
        })

        const payload = OpenApiAdminAccessRequestSchema.parse(denied)
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
            action: 'admin.access_request.deny',
            tenantId: resolveAuditTenantId({principal}),
            message: `Admin access request ${requestId} denied`
          })
        })
      }
    })
  }
}
