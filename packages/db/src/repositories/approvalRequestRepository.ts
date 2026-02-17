import {
  ApprovalRequestSchema,
  ApprovalTransitionInputSchema,
  CanonicalRequestDescriptorSchema,
  type ApprovalRequest,
  type ApprovalStatus,
  type CanonicalRequestDescriptor
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient, RepositoryOperationContext} from '../types.js'
import {createDomainId, descriptorHash, normalizeHost, normalizeMethod, resolveRepositoryDbClient} from '../utils.js'

const toApprovalRequest = (value: unknown): ApprovalRequest => ApprovalRequestSchema.parse(value)

const allowedTransitions: Record<ApprovalStatus, ApprovalStatus[]> = {
  pending: ['approved', 'denied', 'expired', 'canceled'],
  approved: ['executed'],
  denied: [],
  expired: [],
  executed: [],
  canceled: []
}

const computeDescriptorHash = (descriptor: CanonicalRequestDescriptor): string => descriptorHash(descriptor)

export class ApprovalRequestRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async create(input: {approval: ApprovalRequest}, context?: RepositoryOperationContext): Promise<ApprovalRequest> {
    const approval = ApprovalRequestSchema.parse(input.approval)
    const canonicalDescriptor = CanonicalRequestDescriptorSchema.parse(approval.canonical_descriptor)

    if (approval.summary.integration_id !== canonicalDescriptor.integration_id) {
      throw new DbRepositoryError(
        'validation_error',
        'Approval summary.integration_id must match canonical descriptor integration_id'
      )
    }

    const hash = computeDescriptorHash(canonicalDescriptor)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'approvalRequest',
          method: 'create'
        }
      ])

      const created = await dbClient.approvalRequest.create({
        data: {
          approvalId: approval.approval_id,
          tenantId: canonicalDescriptor.tenant_id,
          status: approval.status,
          expiresAt: new Date(approval.expires_at),
          correlationId: approval.correlation_id,
          workloadId: canonicalDescriptor.workload_id,
          integrationId: canonicalDescriptor.integration_id,
          actionGroup: approval.summary.action_group,
          riskTier: approval.summary.risk_tier,
          destinationHost: normalizeHost(approval.summary.destination_host),
          method: normalizeMethod(approval.summary.method),
          path: approval.summary.path,
          descriptorSha256: hash,
          canonicalDescriptor,
          approvalJson: approval
        }
      })

      return toApprovalRequest(created.approvalJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async createApprovalRequestFromCanonicalDescriptor(input: {
    correlation_id: string
    expires_at: string
    summary: ApprovalRequest['summary']
    canonical_descriptor: CanonicalRequestDescriptor
    approval_id?: string
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }): Promise<ApprovalRequest> {
    const canonicalDescriptor = CanonicalRequestDescriptorSchema.parse(input.canonical_descriptor)

    const approval: ApprovalRequest = {
      approval_id: input.approval_id ?? createDomainId('apr_'),
      status: 'pending',
      expires_at: input.expires_at,
      correlation_id: input.correlation_id,
      summary: input.summary,
      canonical_descriptor: canonicalDescriptor
    }

    const operationContext =
      input.context ?? (input.transaction_client !== undefined
        ? {
            transaction_client: input.transaction_client
          }
        : undefined)

    return this.create({approval}, operationContext)
  }

  public async getById(input: {approval_id: string}): Promise<ApprovalRequest | null> {
    const approvalId = input.approval_id.trim()
    if (approvalId.length === 0) {
      throw new DbRepositoryError('validation_error', 'approval_id cannot be empty')
    }

    try {
      const record = await this.db.approvalRequest.findUnique({
        where: {
          approvalId
        },
        select: {
          approvalJson: true
        }
      })

      if (!record) {
        return null
      }

      return toApprovalRequest(record.approvalJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async list(input: {
    tenant_id?: string
    status?: ApprovalStatus
    limit?: number
  }): Promise<ApprovalRequest[]> {
    const limit = input.limit ?? 100
    if (limit < 1 || limit > 200) {
      throw new DbRepositoryError('validation_error', 'limit must be between 1 and 200')
    }

    const tenantId = input.tenant_id?.trim()
    if (input.tenant_id !== undefined && (!tenantId || tenantId.length === 0)) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty when provided')
    }

    try {
      const records = await this.db.approvalRequest.findMany({
        where: {
          ...(tenantId ? {tenantId} : {}),
          ...(input.status ? {status: input.status} : {})
        },
        orderBy: [
          {
            createdAt: 'desc'
          },
          {
            approvalId: 'desc'
          }
        ],
        take: limit,
        select: {
          approvalJson: true
        }
      })

      return records.map(record => toApprovalRequest(record.approvalJson))
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async transitionApprovalStatus(input: {
    approval_id: string
    status: ApprovalStatus
    decided_at?: string
  }): Promise<ApprovalRequest> {
    const parsedInput = ApprovalTransitionInputSchema.parse(input)

    try {
      const existing = await this.db.approvalRequest.findUnique({
        where: {
          approvalId: parsedInput.approval_id
        },
        select: {
          status: true,
          approvalJson: true
        }
      })

      if (!existing) {
        throw new DbRepositoryError('not_found', 'Approval request was not found')
      }

      const previousApproval = toApprovalRequest(existing.approvalJson)
      if (existing.status === parsedInput.status) {
        return previousApproval
      }

      const transitions = allowedTransitions[existing.status]
      if (!transitions.includes(parsedInput.status)) {
        throw new DbRepositoryError(
          'state_transition_invalid',
          `Invalid transition from ${existing.status} to ${parsedInput.status}`
        )
      }

      const updatedApproval = ApprovalRequestSchema.parse({
        ...previousApproval,
        status: parsedInput.status
      })

      const updated = await this.db.approvalRequest.update({
        where: {
          approvalId: parsedInput.approval_id
        },
        data: {
          status: parsedInput.status,
          decidedAt:
            parsedInput.status === 'pending'
              ? null
              : new Date(parsedInput.decided_at ?? new Date().toISOString()),
          approvalJson: updatedApproval
        },
        select: {
          approvalJson: true
        }
      })

      return toApprovalRequest(updated.approvalJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async findOpenApprovalByCanonicalDescriptor(input: {
    descriptor: CanonicalRequestDescriptor
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }): Promise<ApprovalRequest | null> {
    const descriptor = CanonicalRequestDescriptorSchema.parse(input.descriptor)
    const hash = computeDescriptorHash(descriptor)

    try {
      const operationContext =
        input.context ?? (input.transaction_client !== undefined
          ? {
              transaction_client: input.transaction_client
            }
          : undefined)

      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'approvalRequest',
          method: 'findFirst'
        }
      ])

      const record = await dbClient.approvalRequest.findFirst({
        where: {
          tenantId: descriptor.tenant_id,
          workloadId: descriptor.workload_id,
          integrationId: descriptor.integration_id,
          descriptorSha256: hash,
          status: 'pending',
          expiresAt: {
            gt: new Date()
          }
        },
        orderBy: {
          createdAt: 'desc'
        },
        select: {
          approvalJson: true
        }
      })

      if (!record) {
        return null
      }

      return toApprovalRequest(record.approvalJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
