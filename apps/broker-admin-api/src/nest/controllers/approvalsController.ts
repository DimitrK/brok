import {Controller, Get, Inject, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {
  OpenApiApprovalDecisionRequestSchema,
  OpenApiApprovalListResponseSchema,
  OpenApiApprovalResponseSchema
} from '@broker-interceptor/schemas'

import {requireAnyRole, requireTenantScope} from '../../auth'
import {parseJsonBody, parseQuery, sendJson} from '../../http'
import {
  AdminApiControllerContext,
  approvalDecisionRoles,
  approvalStatusQuerySchema,
  decodePathParam,
  listAccessRoles,
  type ApprovalStatusFilter
} from '../controllerContext'

@Controller()
export class ApprovalsController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Get('/v1/approvals')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId, url}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...listAccessRoles]})

        const query = parseQuery({searchParams: url.searchParams, schema: approvalStatusQuerySchema})
        const approvals = await this.context.repository.listApprovals({
          status: query.status as ApprovalStatusFilter | undefined
        })

        const scopedApprovals = approvals.filter(approval => {
          if (principal.roles.includes('owner')) {
            return true
          }

          if (!principal.tenantIds || principal.tenantIds.length === 0) {
            return false
          }

          return principal.tenantIds.includes(approval.canonical_descriptor.tenant_id)
        })

        const payload = OpenApiApprovalListResponseSchema.parse({approvals: scopedApprovals})

        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Post('/v1/approvals/:approvalId/approve')
  public async approve(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...approvalDecisionRoles]})

        const approvalId = decodePathParam(request.params.approvalId as string)
        const approval = await this.context.repository.getApproval({approvalId})
        requireTenantScope({
          principal,
          tenantId: approval.canonical_descriptor.tenant_id
        })

        const body = await parseJsonBody({
          request,
          schema: OpenApiApprovalDecisionRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const result = await this.context.repository.decideApproval({
          approvalId,
          decision: 'approved',
          request: body
        })

        const payload = OpenApiApprovalResponseSchema.parse({
          approval_id: result.approval.approval_id,
          status: 'approved'
        })

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
            action: 'approval.approve',
            tenantId: result.approval.canonical_descriptor.tenant_id,
            message: `Approval ${result.approval.approval_id} approved`
          })
        })

        if (result.derivedPolicy) {
          this.context.appendAuditEventNonBlocking({
            correlationId,
            event: this.context.repository.createPolicyAuditEvent({
              actor: principal,
              correlationId,
              tenantId: result.derivedPolicy.scope.tenant_id,
              policy: result.derivedPolicy,
              action: 'derived',
              message: `Policy ${result.derivedPolicy.policy_id} derived from approval ${result.approval.approval_id}`
            })
          })
        }
      }
    })
  }

  @Post('/v1/approvals/:approvalId/deny')
  public async deny(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...approvalDecisionRoles]})

        const approvalId = decodePathParam(request.params.approvalId as string)
        const approval = await this.context.repository.getApproval({approvalId})
        requireTenantScope({
          principal,
          tenantId: approval.canonical_descriptor.tenant_id
        })

        const body = await parseJsonBody({
          request,
          schema: OpenApiApprovalDecisionRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: false
        })

        const decisionPayload =
          body ??
          OpenApiApprovalDecisionRequestSchema.parse({
            mode: 'once'
          })

        const result = await this.context.repository.decideApproval({
          approvalId,
          decision: 'denied',
          request: decisionPayload
        })

        const payload = OpenApiApprovalResponseSchema.parse({
          approval_id: result.approval.approval_id,
          status: 'denied'
        })

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
            action: 'approval.deny',
            tenantId: result.approval.canonical_descriptor.tenant_id,
            message: `Approval ${result.approval.approval_id} denied`
          })
        })

        if (result.derivedPolicy) {
          this.context.appendAuditEventNonBlocking({
            correlationId,
            event: this.context.repository.createPolicyAuditEvent({
              actor: principal,
              correlationId,
              tenantId: result.derivedPolicy.scope.tenant_id,
              policy: result.derivedPolicy,
              action: 'derived',
              message: `Policy ${result.derivedPolicy.policy_id} derived from denied approval ${result.approval.approval_id}`
            })
          })
        }
      }
    })
  }
}
