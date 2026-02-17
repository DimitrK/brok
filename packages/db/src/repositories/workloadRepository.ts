import {
  OpenApiWorkloadCreateRequestSchema,
  OpenApiWorkloadSchema,
  OpenApiWorkloadUpdateRequestSchema,
  type Workload,
  type WorkloadCreateRequest,
  type WorkloadUpdateRequest
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient} from '../types.js'
import {createDomainId, normalizeIpAllowlist} from '../utils.js'

const toWorkload = (record: {
  workloadId: string
  tenantId: string
  name: string
  mtlsSanUri: string
  enabled: boolean
  ipAllowlist: string[]
  createdAt: Date
}): Workload =>
  OpenApiWorkloadSchema.parse({
    workload_id: record.workloadId,
    tenant_id: record.tenantId,
    name: record.name,
    mtls_san_uri: record.mtlsSanUri,
    enabled: record.enabled,
    ip_allowlist: record.ipAllowlist,
    created_at: record.createdAt.toISOString()
  })

const buildDefaultSanUri = ({tenantId, workloadId}: {tenantId: string; workloadId: string}) =>
  `spiffe://broker/tenants/${tenantId}/workloads/${workloadId}`

export class WorkloadRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async create(input: {
    tenant_id: string
    request: WorkloadCreateRequest
    workload_id?: string
    mtls_san_uri?: string
  }): Promise<Workload> {
    const request = OpenApiWorkloadCreateRequestSchema.parse(input.request)
    const tenantId = input.tenant_id.trim()

    if (tenantId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    const workloadId = input.workload_id ?? createDomainId('w_')
    const mtlsSanUri = input.mtls_san_uri?.trim() ?? buildDefaultSanUri({tenantId, workloadId})

    if (mtlsSanUri.length === 0) {
      throw new DbRepositoryError('validation_error', 'mtls_san_uri cannot be empty')
    }

    const ipAllowlist = request.ip_allowlist ? normalizeIpAllowlist(request.ip_allowlist) : []

    try {
      const created = await this.db.workload.create({
        data: {
          workloadId,
          tenantId,
          name: request.name,
          mtlsSanUri,
          enabled: true,
          ipAllowlist,
          enrollmentMode: request.enrollment_mode
        }
      })

      return toWorkload(created)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getById(input: {workload_id: string}): Promise<Workload | null> {
    const workloadId = input.workload_id.trim()
    if (workloadId.length === 0) {
      throw new DbRepositoryError('validation_error', 'workload_id cannot be empty')
    }

    try {
      const record = await this.db.workload.findUnique({
        where: {
          workloadId
        }
      })

      if (!record) {
        return null
      }

      return toWorkload(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getBySanUri(input: {san_uri: string}): Promise<Workload | null> {
    const sanUri = input.san_uri.trim()
    if (sanUri.length === 0) {
      throw new DbRepositoryError('validation_error', 'san_uri cannot be empty')
    }

    try {
      const record = await this.db.workload.findUnique({
        where: {
          mtlsSanUri: sanUri
        }
      })

      if (!record) {
        return null
      }

      return toWorkload(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listByTenant(input: {tenant_id: string}): Promise<Workload[]> {
    const tenantId = input.tenant_id.trim()
    if (tenantId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    try {
      const records = await this.db.workload.findMany({
        where: {
          tenantId
        },
        orderBy: {
          createdAt: 'asc'
        }
      })

      return records.map(toWorkload)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async update(input: {
    workload_id: string
    request: WorkloadUpdateRequest
  }): Promise<Workload> {
    const request = OpenApiWorkloadUpdateRequestSchema.parse(input.request)
    const workloadId = input.workload_id.trim()

    if (workloadId.length === 0) {
      throw new DbRepositoryError('validation_error', 'workload_id cannot be empty')
    }

    try {
      const ipAllowlist = request.ip_allowlist
        ? normalizeIpAllowlist(request.ip_allowlist)
        : undefined

      const updated = await this.db.workload.update({
        where: {
          workloadId
        },
        data: {
          ...(request.enabled !== undefined ? {enabled: request.enabled} : {}),
          ...(ipAllowlist !== undefined ? {ipAllowlist} : {})
        }
      })

      return toWorkload(updated)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async resolveTenantByWorkload(input: {workload_id: string}): Promise<string | null> {
    const workload = await this.getById(input)
    return workload?.tenant_id ?? null
  }
}
