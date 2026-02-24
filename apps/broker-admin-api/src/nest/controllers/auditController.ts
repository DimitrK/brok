import {Controller, Get, Inject, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {OpenApiAuditEventListResponseSchema} from '@broker-interceptor/schemas'

import {auditListQuerySchema, paginateAuditEvents} from '../../auditPagination'
import {requireAnyRole} from '../../auth'
import {badRequest} from '../../errors'
import {parseQuery, sendJson} from '../../http'
import {AdminApiControllerContext, toDate} from '../controllerContext'

@Controller()
export class AuditController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Get('/v1/audit/events')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId, url}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: ['owner', 'admin', 'auditor']})

        const query = parseQuery({searchParams: url.searchParams, schema: auditListQuerySchema})
        const tenantId = this.context.normalizeTenantAuditFilter({
          principal,
          requestedTenantId: query.tenant_id
        })

        const timeMin = toDate(query.time_min)
        const timeMax = toDate(query.time_max)
        if (timeMin && timeMax && timeMin > timeMax) {
          throw badRequest('time_range_invalid', 'time_min must be <= time_max')
        }

        const events = await this.context.dependencyBridge.queryAuditEventsWithAuditPackage({
          query: {
            ...(query.time_min ? {time_min: query.time_min} : {}),
            ...(query.time_max ? {time_max: query.time_max} : {}),
            ...(tenantId ? {tenant_id: tenantId} : {}),
            ...(query.workload_id ? {workload_id: query.workload_id} : {}),
            ...(query.integration_id ? {integration_id: query.integration_id} : {}),
            ...(query.action_group ? {action_group: query.action_group} : {}),
            ...(query.decision ? {decision: query.decision} : {})
          }
        })

        const paged = paginateAuditEvents({
          events,
          limit: query.limit,
          cursor: query.cursor
        })
        const payload = OpenApiAuditEventListResponseSchema.parse(paged)
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
