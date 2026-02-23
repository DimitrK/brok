import {Controller, Get, Inject, Patch, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {OpenApiAdminUserListResponseSchema, OpenApiAdminUserSchema, OpenApiAdminUserUpdateRequestSchema} from '@broker-interceptor/schemas'

import {requireAnyRole} from '../../auth'
import {badRequest} from '../../errors'
import {parseJsonBody, parseQuery, sendJson} from '../../http'
import {AdminApiControllerContext, adminUserListQuerySchema, decodePathParam, resolveAuditTenantId} from '../controllerContext'

@Controller()
export class AdminUsersController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Get('/v1/admin/users')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId, url}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner']})

        const query = parseQuery({
          searchParams: url.searchParams,
          schema: adminUserListQuerySchema
        })
        const users = await this.context.dependencyBridge.listAdminUsers({
          actor: principal,
          ...(query.status ? {status: query.status} : {}),
          ...(query.tenant_id ? {tenantId: query.tenant_id} : {}),
          ...(query.role ? {role: query.role} : {}),
          ...(query.search ? {search: query.search} : {}),
          ...(typeof query.limit === 'number' ? {limit: query.limit} : {}),
          ...(query.cursor ? {cursor: query.cursor} : {})
        })

        const payload = OpenApiAdminUserListResponseSchema.parse(users)
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Patch('/v1/admin/users/:identityId')
  public async update(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner']})

        const identityId = decodePathParam(request.params.identityId as string)
        const body = await parseJsonBody({
          request,
          schema: OpenApiAdminUserUpdateRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        if (body.status === undefined && body.roles === undefined && body.tenant_ids === undefined) {
          throw badRequest('admin_user_update_invalid', 'At least one of status, roles, or tenant_ids must be provided')
        }

        const updatedUser = await this.context.dependencyBridge.updateAdminUser({
          identityId,
          actor: principal,
          ...(body.status !== undefined ? {status: body.status} : {}),
          ...(body.roles !== undefined ? {roles: body.roles} : {}),
          ...(body.tenant_ids !== undefined ? {tenantIds: body.tenant_ids} : {})
        })

        const payload = OpenApiAdminUserSchema.parse(updatedUser)
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
            action: 'admin.user.update',
            tenantId: resolveAuditTenantId({principal}),
            message: `Admin user ${identityId} updated`
          })
        })
      }
    })
  }
}
