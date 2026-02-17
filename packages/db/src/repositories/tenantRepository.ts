import {
  OpenApiTenantCreateRequestSchema,
  OpenApiTenantSummarySchema,
  type TenantCreateRequest,
  type TenantSummary
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient} from '../types.js'
import {assertNonEmptyString, createDomainId} from '../utils.js'

export class TenantRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async create(input: {request: TenantCreateRequest; tenant_id?: string}): Promise<TenantSummary> {
    const request = OpenApiTenantCreateRequestSchema.parse(input.request)
    const tenantId = input.tenant_id
      ? assertNonEmptyString(input.tenant_id, 'tenant_id')
      : createDomainId('t_')

    try {
      const created = await this.db.tenant.create({
        data: {
          tenantId,
          name: request.name
        }
      })

      return OpenApiTenantSummarySchema.parse({
        tenant_id: created.tenantId,
        name: created.name
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getById(input: {tenant_id: string}): Promise<TenantSummary | null> {
    const tenant_id = input.tenant_id.trim()
    if (tenant_id.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    try {
      const record = await this.db.tenant.findUnique({
        where: {
          tenantId: tenant_id
        }
      })

      if (!record) {
        return null
      }

      return OpenApiTenantSummarySchema.parse({
        tenant_id: record.tenantId,
        name: record.name
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async list(): Promise<TenantSummary[]> {
    try {
      const records = await this.db.tenant.findMany({
        orderBy: {
          createdAt: 'asc'
        }
      })

      return records.map(record =>
        OpenApiTenantSummarySchema.parse({
          tenant_id: record.tenantId,
          name: record.name
        })
      )
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
