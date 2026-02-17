import type {AuditService} from '@broker-interceptor/audit'
import type {CanonicalRequestDescriptor, OpenApiAuditEvent, OpenApiIntegration, OpenApiPolicyRule, OpenApiTemplate, OpenApiWorkload} from '@broker-interceptor/schemas'
import type {Prisma} from '@prisma/client'

import {DataPlaneRepository} from './repository'

export class BrokerApiDependencyBridge {
  public constructor(
    private readonly dependencies: {
      repository: DataPlaneRepository
      auditService: AuditService
    }
  ) {}

  public getWorkloadBySanUri({sanUri}: {sanUri: string}): OpenApiWorkload | null {
    return this.dependencies.repository.getWorkloadBySanUri({sanUri})
  }

  public getIntegrationByTenantAndId({
    tenantId,
    integrationId
  }: {
    tenantId: string
    integrationId: string
  }): OpenApiIntegration | null {
    return this.dependencies.repository.getIntegrationByTenantAndId({tenantId, integrationId})
  }

  public getLatestTemplateById({templateId}: {templateId: string}): OpenApiTemplate | null {
    return this.dependencies.repository.getLatestTemplateById({templateId})
  }

  public listTenantPolicies({tenantId}: {tenantId: string}): OpenApiPolicyRule[] {
    return this.dependencies.repository.listTenantPolicies({tenantId})
  }

  public async createApprovalRequest({
    descriptor,
    summary,
    correlationId,
    now
  }: {
    descriptor: CanonicalRequestDescriptor
    summary: {
      integration_id: string
      action_group: string
      risk_tier: 'low' | 'medium' | 'high'
      destination_host: string
      method: string
      path: string
    }
    correlationId: string
    now?: Date
  }) {
    return this.dependencies.repository.createOrReuseApprovalRequest({
      descriptor,
      summary,
      correlationId,
      ...(now ? {now} : {})
    })
  }

  public async appendAuditEvent({event}: {event: OpenApiAuditEvent}) {
    const result = await this.dependencies.auditService.appendAuditEvent({event})
    if (!result.ok) {
      throw new Error(result.error.message)
    }

    return result.value
  }

  public isSharedInfrastructureEnabled() {
    return this.dependencies.repository.isSharedInfrastructureEnabled()
  }

  public async withSharedTransaction<T>(operation: (client: Prisma.TransactionClient) => Promise<T>) {
    return this.dependencies.repository.withSharedTransaction(operation)
  }
}
