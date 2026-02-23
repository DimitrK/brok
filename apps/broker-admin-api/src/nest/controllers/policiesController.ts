import {Controller, Delete, Get, Inject, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {
  OpenApiPolicyCreateResponseSchema,
  OpenApiPolicyListResponseSchema,
  OpenApiPolicyRuleSchema
} from '@broker-interceptor/schemas'

import {requireAnyRole, requireTenantScope} from '../../auth'
import {sendJson, sendNoContent, parseJsonBody} from '../../http'
import {AdminApiControllerContext, decodePathParam, listAccessRoles, writeAccessRoles} from '../controllerContext'

@Controller()
export class PoliciesController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Post('/v1/policies')
  public async create(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const body = await parseJsonBody({
          request,
          schema: OpenApiPolicyRuleSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const policyPayload = this.context.dependencyBridge.validatePolicyRuleWithPolicyEngine({
          policy: body
        })
        requireTenantScope({principal, tenantId: policyPayload.scope.tenant_id})
        const created = await this.context.repository.createPolicy({payload: policyPayload})

        const payload = OpenApiPolicyCreateResponseSchema.parse({
          policy_id: created.policy_id ?? ''
        })

        sendJson({
          response,
          status: 201,
          correlationId,
          payload
        })

        this.context.appendAuditEventNonBlocking({
          correlationId,
          event: this.context.repository.createPolicyAuditEvent({
            actor: principal,
            correlationId,
            tenantId: created.scope.tenant_id,
            policy: created,
            action: 'created',
            message: `Policy ${created.policy_id} created`
          })
        })
      }
    })
  }

  @Get('/v1/policies')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...listAccessRoles]})

        const policies = (await this.context.repository.listPolicies()).filter(policy =>
          principal.roles.includes('owner') || !principal.tenantIds
            ? true
            : principal.tenantIds.includes(policy.scope.tenant_id)
        )

        const payload = OpenApiPolicyListResponseSchema.parse({policies})
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Delete('/v1/policies/:policyId')
  public async remove(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const policyId = decodePathParam(request.params.policyId as string)
        const policy = await this.context.repository.getPolicy({policyId})
        requireTenantScope({principal, tenantId: policy.scope.tenant_id})
        await this.context.repository.deletePolicy({policyId})

        sendNoContent({response, correlationId})

        this.context.appendAuditEventNonBlocking({
          correlationId,
          event: this.context.repository.createPolicyAuditEvent({
            actor: principal,
            correlationId,
            tenantId: policy.scope.tenant_id,
            policy,
            action: 'deleted',
            message: `Policy ${policyId} deleted`
          })
        })
      }
    })
  }
}
