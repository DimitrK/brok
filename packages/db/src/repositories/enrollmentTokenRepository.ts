import {
  ConsumeEnrollmentTokenInputSchema,
  EnrollmentTokenRecordSchema,
  HasConsumedEnrollmentTokenForWorkloadInputSchema,
  InvalidateActiveEnrollmentTokensInputSchema,
  IssueEnrollmentTokenInputSchema,
  type ConsumeEnrollmentTokenInput,
  type EnrollmentTokenRecord,
  type HasConsumedEnrollmentTokenForWorkloadInput,
  type InvalidateActiveEnrollmentTokensInput,
  type IssueEnrollmentTokenInput
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient, RepositoryOperationContext} from '../types.js'
import {resolveRepositoryDbClient} from '../utils.js'

const toEnrollmentTokenRecord = (record: {
  tokenHash: string
  workloadId: string
  tenantId: string
  expiresAt: Date
  usedAt: Date | null
  createdAt: Date
}): EnrollmentTokenRecord =>
  EnrollmentTokenRecordSchema.parse({
    token_hash: record.tokenHash,
    workload_id: record.workloadId,
    tenant_id: record.tenantId,
    expires_at: record.expiresAt.toISOString(),
    created_at: record.createdAt.toISOString(),
    ...(record.usedAt ? {used_at: record.usedAt.toISOString()} : {})
  })

export class EnrollmentTokenRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async issueEnrollmentToken(
    rawInput: IssueEnrollmentTokenInput,
    context?: RepositoryOperationContext
  ): Promise<EnrollmentTokenRecord> {
    const input = IssueEnrollmentTokenInputSchema.parse(rawInput)
    const expiresAt = new Date(input.expires_at)
    const createdAt = input.created_at ? new Date(input.created_at) : new Date()

    if (expiresAt.getTime() <= createdAt.getTime()) {
      throw new DbRepositoryError('validation_error', 'expires_at must be greater than created_at')
    }

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'workload',
          method: 'findUnique'
        },
        {
          model: 'enrollmentToken',
          method: 'create'
        }
      ])

      const workload = await dbClient.workload.findUnique({
        where: {
          workloadId: input.workload_id
        },
        select: {
          tenantId: true
        }
      })

      if (!workload) {
        throw new DbRepositoryError('not_found', 'Workload does not exist')
      }

      if (input.tenant_id !== workload.tenantId) {
        throw new DbRepositoryError('conflict', 'Workload tenant mismatch')
      }

      const record = await dbClient.enrollmentToken.create({
        data: {
          tokenHash: input.token_hash,
          workloadId: input.workload_id,
          tenantId: workload.tenantId,
          expiresAt,
          createdAt
        }
      })

      return toEnrollmentTokenRecord(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async consumeEnrollmentTokenOnce(
    rawInput: ConsumeEnrollmentTokenInput,
    context?: RepositoryOperationContext
  ): Promise<EnrollmentTokenRecord> {
    const input = ConsumeEnrollmentTokenInputSchema.parse(rawInput)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'enrollmentToken',
          method: 'updateMany'
        },
        {
          model: 'enrollmentToken',
          method: 'findUnique'
        }
      ])

      const now = new Date(input.now)
      const where = {
        tokenHash: input.token_hash,
        usedAt: null,
        expiresAt: {
          gt: now
        },
        ...(input.workload_id ? {workloadId: input.workload_id} : {})
      }

      const updated = await dbClient.enrollmentToken.updateMany({
        where,
        data: {
          usedAt: now
        }
      })

      if (updated.count === 0) {
        throw new DbRepositoryError('not_found', 'Enrollment token is not available')
      }

      const record = await dbClient.enrollmentToken.findUnique({
        where: {
          tokenHash: input.token_hash
        }
      })

      if (!record) {
        throw new DbRepositoryError('not_found', 'Enrollment token is not available')
      }

      return toEnrollmentTokenRecord(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async hasConsumedEnrollmentTokenForWorkload(
    rawInput: HasConsumedEnrollmentTokenForWorkloadInput,
    context?: RepositoryOperationContext
  ): Promise<boolean> {
    const input = HasConsumedEnrollmentTokenForWorkloadInputSchema.parse(rawInput)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'enrollmentToken',
          method: 'findFirst'
        }
      ])

      const record = await dbClient.enrollmentToken.findFirst({
        where: {
          workloadId: input.workload_id,
          usedAt: {
            not: null
          }
        },
        select: {
          tokenHash: true
        }
      })

      return Boolean(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async invalidateActiveEnrollmentTokens(
    rawInput: InvalidateActiveEnrollmentTokensInput,
    context?: RepositoryOperationContext
  ): Promise<number> {
    const input = InvalidateActiveEnrollmentTokensInputSchema.parse(rawInput)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'enrollmentToken',
          method: 'updateMany'
        }
      ])

      const now = new Date(input.now)
      const updated = await dbClient.enrollmentToken.updateMany({
        where: {
          workloadId: input.workload_id,
          usedAt: null,
          expiresAt: {
            gt: now
          }
        },
        data: {
          usedAt: now
        }
      })

      return updated.count
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
