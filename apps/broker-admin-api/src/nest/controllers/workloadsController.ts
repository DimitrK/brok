import {Controller, Get, Inject, Patch, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {
  OpenApiWorkloadCreateRequestSchema,
  OpenApiWorkloadCreateResponseSchema,
  OpenApiWorkloadEnrollRequestSchema,
  OpenApiWorkloadEnrollResponseSchema,
  OpenApiWorkloadEnrollmentTokenIssueRequestSchema,
  OpenApiWorkloadEnrollmentTokenIssueResponseSchema,
  OpenApiWorkloadListResponseSchema,
  OpenApiWorkloadSchema,
  OpenApiWorkloadUpdateRequestSchema
} from '@broker-interceptor/schemas'

import {requireAnyRole, requireTenantScope} from '../../auth'
import {badRequest} from '../../errors'
import {parseJsonBody, sendJson} from '../../http'
import {AdminApiControllerContext, decodePathParam, writeAccessRoles, listAccessRoles} from '../controllerContext'

@Controller()
export class WorkloadsController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Post('/v1/tenants/:tenantId/workloads')
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
          schema: OpenApiWorkloadCreateRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })
        const enrollmentModeContext = await this.context.dependencyBridge.ensureEnrollmentModeSupported_INCOMPLETE({
          enrollmentMode: body.enrollment_mode,
          tenantId,
          workloadName: body.name
        })

        const created = await this.context.repository.createWorkload({
          tenantId,
          name: body.name,
          ipAllowlist: body.ip_allowlist,
          enrollmentMode: body.enrollment_mode
        })

        const payload = OpenApiWorkloadCreateResponseSchema.parse({
          workload_id: created.workload.workload_id,
          enrollment_token: created.enrollmentToken,
          mtls_ca_pem: enrollmentModeContext.mtlsCaPem ?? this.context.dependencyBridge.getMtlsCaPemFromAuthPackage()
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
            action: 'workload.create',
            tenantId,
            workloadId: created.workload.workload_id,
            message: `Workload ${created.workload.workload_id} created`
          })
        })
      }
    })
  }

  @Get('/v1/tenants/:tenantId/workloads')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        const tenantId = decodePathParam(request.params.tenantId as string)
        requireTenantScope({principal, tenantId})
        requireAnyRole({principal, allowed: [...listAccessRoles]})
        const workloads = await this.context.repository.listWorkloads({tenantId})
        const payload = OpenApiWorkloadListResponseSchema.parse({workloads})
        sendJson({
          response,
          status: 200,
          correlationId,
          payload
        })
      }
    })
  }

  @Patch('/v1/workloads/:workloadId')
  public async patch(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const workloadId = decodePathParam(request.params.workloadId as string)
        await this.context.requireWorkloadTenantScope({principal, workloadId})

        const body = await parseJsonBody({
          request,
          schema: OpenApiWorkloadUpdateRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const updated = await this.context.repository.updateWorkload({
          workloadId,
          enabled: body.enabled,
          ipAllowlist: body.ip_allowlist
        })

        const payload = OpenApiWorkloadSchema.parse(updated)
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
            action: 'workload.update',
            tenantId: updated.tenant_id,
            workloadId: updated.workload_id,
            message: `Workload ${updated.workload_id} updated`
          })
        })
      }
    })
  }

  @Post('/v1/workloads/:workloadId/enrollment-token')
  public async issueEnrollmentToken(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const workloadId = decodePathParam(request.params.workloadId as string)
        const workload = await this.context.requireWorkloadTenantScope({principal, workloadId})

        const body = await parseJsonBody({
          request,
          schema: OpenApiWorkloadEnrollmentTokenIssueRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        const issued = await this.context.repository.issueWorkloadEnrollmentToken({
          workloadId,
          rotationMode: body.rotation_mode
        })

        const payload = OpenApiWorkloadEnrollmentTokenIssueResponseSchema.parse({
          enrollment_token: issued.enrollmentToken,
          expires_at: issued.expiresAt
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
            action: 'workload.enrollment_token.issue',
            tenantId: workload.tenant_id,
            workloadId,
            message: `Enrollment token issued for workload ${workloadId}`,
            metadata: {
              rotation_mode: body.rotation_mode
            }
          })
        })
      }
    })
  }

  @Post('/v1/workloads/:workloadId/enroll')
  public async enroll(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...writeAccessRoles]})

        const workloadId = decodePathParam(request.params.workloadId as string)
        const workload = await this.context.requireWorkloadTenantScope({principal, workloadId})

        const body = await parseJsonBody({
          request,
          schema: OpenApiWorkloadEnrollRequestSchema,
          maxBodyBytes: this.context.config.maxBodyBytes,
          required: true
        })

        if (body.requested_ttl_seconds > this.context.config.clientCertTtlSecondsMax) {
          throw badRequest(
            'requested_ttl_exceeds_max',
            `requested_ttl_seconds must be <= ${this.context.config.clientCertTtlSecondsMax}`
          )
        }

        await this.context.repository.consumeEnrollmentToken({
          workloadId,
          enrollmentToken: body.enrollment_token
        })

        await this.context.dependencyBridge.validateEnrollmentCsrWithAuthPackage({
          csrPem: body.csr_pem,
          expectedSanUri: workload.mtls_san_uri,
          requireClientAuthEku: true
        })

        const issued = await this.context.dependencyBridge.issueWorkloadCertificateWithAuthPackage({
          input: {
            csrPem: body.csr_pem,
            workloadId,
            sanUri: workload.mtls_san_uri,
            ttlSeconds: body.requested_ttl_seconds
          }
        })

        const payload = OpenApiWorkloadEnrollResponseSchema.parse({
          client_cert_pem: issued.clientCertPem,
          ca_chain_pem: issued.caChainPem,
          expires_at: issued.expiresAt
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
            action: 'workload.enroll',
            tenantId: workload.tenant_id,
            workloadId,
            message: `Workload ${workloadId} enrolled with a new client certificate`
          })
        })
      }
    })
  }
}
