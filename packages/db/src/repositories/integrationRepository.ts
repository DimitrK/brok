import {
  OpenApiIntegrationSchema,
  OpenApiIntegrationUpdateRequestSchema,
  OpenApiIntegrationWriteSchema,
  OpenApiTemplateSchema,
  type Integration,
  type IntegrationUpdateRequest,
  type IntegrationWrite,
  type Template
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient, RepositoryOperationContext} from '../types.js'
import {createDomainId, resolveRepositoryDbClient} from '../utils.js'

const toIntegration = (record: {
  integrationId: string
  tenantId: string
  provider: string
  name: string
  templateId: string
  enabled: boolean
  secretRef: string | null
  secretVersion: number | null
  lastRotatedAt: Date | null
}): Integration =>
  OpenApiIntegrationSchema.parse({
    integration_id: record.integrationId,
    tenant_id: record.tenantId,
    provider: record.provider,
    name: record.name,
    template_id: record.templateId,
    enabled: record.enabled,
    ...(record.secretRef ? {secret_ref: record.secretRef} : {}),
    ...(record.secretVersion !== null ? {secret_version: record.secretVersion} : {}),
    ...(record.lastRotatedAt ? {last_rotated_at: record.lastRotatedAt.toISOString()} : {})
  })

const parseTemplate = (value: unknown): Template => OpenApiTemplateSchema.parse(value)

export type IntegrationTemplateExecutionStatus =
  | 'executable'
  | 'workload_disabled'
  | 'integration_disabled'

export type IntegrationTemplateForExecute = {
  workload_enabled: boolean
  integration_enabled: boolean
  executable: boolean
  execution_status: IntegrationTemplateExecutionStatus
  template: Template
  template_id: string
  template_version: number
}

export type IntegrationTemplateBinding = {
  tenant_id: string
  integration_id: string
  enabled: boolean
  template_id: string
  template_version: number
}

export class IntegrationRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async create(input: {
    tenant_id: string
    payload: IntegrationWrite
    integration_id?: string
    secret_ref?: string
    secret_version?: number
    template_version?: number
    enabled?: boolean
  }): Promise<Integration> {
    const payload = OpenApiIntegrationWriteSchema.parse(input.payload)
    const tenantId = input.tenant_id.trim()

    if (tenantId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    if (input.template_version !== undefined && (!Number.isInteger(input.template_version) || input.template_version < 1)) {
      throw new DbRepositoryError('validation_error', 'template_version must be an integer >= 1 when provided')
    }

    if (input.secret_version !== undefined && (!Number.isInteger(input.secret_version) || input.secret_version < 1)) {
      throw new DbRepositoryError('validation_error', 'secret_version must be an integer >= 1 when provided')
    }

    if ((input.secret_ref === undefined) !== (input.secret_version === undefined)) {
      throw new DbRepositoryError(
        'validation_error',
        'secret_ref and secret_version must either both be provided or both be omitted'
      )
    }

    const secretRef = input.secret_ref?.trim()
    if (secretRef !== undefined && secretRef.length === 0) {
      throw new DbRepositoryError('validation_error', 'secret_ref cannot be empty')
    }

    try {
      const created = await this.db.integration.create({
        data: {
          integrationId: input.integration_id ?? createDomainId('int_'),
          tenantId,
          provider: payload.provider,
          name: payload.name,
          templateId: payload.template_id,
          templateVersion: input.template_version,
          enabled: input.enabled ?? true,
          secretRef,
          secretVersion: input.secret_version
        }
      })

      return toIntegration(created)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getById(input: {
    integration_id: string
    tenant_id?: string
  }): Promise<Integration | null> {
    const integrationId = input.integration_id.trim()
    if (integrationId.length === 0) {
      throw new DbRepositoryError('validation_error', 'integration_id cannot be empty')
    }

    const tenantId = input.tenant_id?.trim()
    if (input.tenant_id !== undefined && (!tenantId || tenantId.length === 0)) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty when provided')
    }

    try {
      const record = await this.db.integration.findFirst({
        where: {
          integrationId,
          ...(tenantId ? {tenantId} : {})
        }
      })

      if (!record) {
        return null
      }

      return toIntegration(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listByTenant(input: {tenant_id: string}): Promise<Integration[]> {
    const tenantId = input.tenant_id.trim()
    if (tenantId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    try {
      const records = await this.db.integration.findMany({
        where: {
          tenantId
        },
        orderBy: {
          createdAt: 'asc'
        }
      })

      return records.map(toIntegration)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async update(input: {
    integration_id: string
    request: IntegrationUpdateRequest
  }): Promise<Integration> {
    const request = OpenApiIntegrationUpdateRequestSchema.parse(input.request)
    const integrationId = input.integration_id.trim()

    if (integrationId.length === 0) {
      throw new DbRepositoryError('validation_error', 'integration_id cannot be empty')
    }

    try {
      const updated = await this.db.integration.update({
        where: {
          integrationId
        },
        data: {
          ...(request.enabled !== undefined ? {enabled: request.enabled} : {}),
          ...(request.template_id !== undefined
            ? {
                templateId: request.template_id,
                templateVersion: null
              }
            : {})
        }
      })

      return toIntegration(updated)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async bindSecret(input: {
    integration_id: string
    secret_ref: string
    secret_version: number
    last_rotated_at?: string
  }): Promise<Integration> {
    const integrationId = input.integration_id.trim()
    if (integrationId.length === 0) {
      throw new DbRepositoryError('validation_error', 'integration_id cannot be empty')
    }

    const secretRef = input.secret_ref.trim()
    if (secretRef.length === 0) {
      throw new DbRepositoryError('validation_error', 'secret_ref cannot be empty')
    }

    if (!Number.isInteger(input.secret_version) || input.secret_version < 1) {
      throw new DbRepositoryError('validation_error', 'secret_version must be >= 1')
    }

    const lastRotatedAt = input.last_rotated_at ? new Date(input.last_rotated_at) : new Date()
    if (Number.isNaN(lastRotatedAt.getTime())) {
      throw new DbRepositoryError('validation_error', 'last_rotated_at must be a valid ISO timestamp')
    }

    try {
      const updated = await this.db.integration.update({
        where: {
          integrationId
        },
        data: {
          secretRef,
          secretVersion: input.secret_version,
          lastRotatedAt
        }
      })

      return toIntegration(updated)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getIntegrationTemplateBindingByTenantAndId(input: {
    tenant_id: string
    integration_id: string
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }): Promise<IntegrationTemplateBinding | null> {
    const tenantId = input.tenant_id.trim()
    const integrationId = input.integration_id.trim()

    if (tenantId.length === 0 || integrationId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id and integration_id are required')
    }

    try {
      const operationContext =
        input.context ?? (input.transaction_client !== undefined
          ? {
              transaction_client: input.transaction_client
            }
          : undefined)

      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'integration',
          method: 'findFirst'
        },
        {
          model: 'templateVersion',
          method: 'findFirst'
        }
      ])

      const integration = await dbClient.integration.findFirst({
        where: {
          tenantId,
          integrationId
        },
        select: {
          enabled: true,
          templateId: true,
          templateVersion: true
        }
      })

      if (!integration) {
        return null
      }

      const templateRecord = integration.templateVersion
        ? await dbClient.templateVersion.findFirst({
            where: {
              tenantId,
              templateId: integration.templateId,
              version: integration.templateVersion,
              status: 'active'
            },
            orderBy: {
              version: 'desc'
            }
          })
        : await dbClient.templateVersion.findFirst({
            where: {
              tenantId,
              templateId: integration.templateId,
              status: 'active'
            },
            orderBy: {
              version: 'desc'
            }
          })

      if (!templateRecord) {
        return null
      }

      return {
        tenant_id: tenantId,
        integration_id: integrationId,
        enabled: integration.enabled,
        template_id: templateRecord.templateId,
        template_version: templateRecord.version
      }
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getIntegrationTemplateForPolicyEvaluation(input: {
    tenant_id: string
    workload_id: string
    integration_id: string
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }, context?: RepositoryOperationContext): Promise<{
    integration_enabled: boolean
    template: Template
  }> {
    const result = await this.getIntegrationTemplateForExecute(input, context)
    return {
      integration_enabled: result.integration_enabled,
      template: result.template
    }
  }

  public async getIntegrationTemplateForExecute(input: {
    tenant_id: string
    workload_id: string
    integration_id: string
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }, context?: RepositoryOperationContext): Promise<IntegrationTemplateForExecute> {
    const tenantId = input.tenant_id.trim()
    const workloadId = input.workload_id.trim()
    const integrationId = input.integration_id.trim()

    if (tenantId.length === 0 || workloadId.length === 0 || integrationId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id, workload_id and integration_id are required')
    }

    try {
      const operationContext =
        input.context ?? context ?? (input.transaction_client !== undefined
          ? {
              transaction_client: input.transaction_client
            }
          : undefined)

      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'workload',
          method: 'findFirst'
        },
        {
          model: 'integration',
          method: 'findFirst'
        },
        {
          model: 'templateVersion',
          method: 'findFirst'
        }
      ])

      const workload = await dbClient.workload.findFirst({
        where: {
          workloadId,
          tenantId
        },
        select: {
          enabled: true
        }
      })

      if (!workload) {
        throw new DbRepositoryError('not_found', 'Workload was not found for tenant')
      }

      const integration = await dbClient.integration.findFirst({
        where: {
          integrationId,
          tenantId
        },
        select: {
          enabled: true,
          templateId: true,
          templateVersion: true
        }
      })

      if (!integration) {
        throw new DbRepositoryError('not_found', 'Integration was not found for tenant')
      }

      const templateRecord = integration.templateVersion
        ? await dbClient.templateVersion.findFirst({
            where: {
              tenantId,
              templateId: integration.templateId,
              version: integration.templateVersion,
              status: 'active'
            },
            orderBy: {
              version: 'desc'
            }
          })
        : await dbClient.templateVersion.findFirst({
            where: {
              tenantId,
              templateId: integration.templateId,
              status: 'active'
            },
            orderBy: {
              version: 'desc'
            }
          })

      if (!templateRecord) {
        throw new DbRepositoryError('not_found', 'Template binding is missing or invalid')
      }

      const execution_status: IntegrationTemplateExecutionStatus =
        !workload.enabled
          ? 'workload_disabled'
          : !integration.enabled
            ? 'integration_disabled'
            : 'executable'

      return {
        workload_enabled: workload.enabled,
        integration_enabled: integration.enabled,
        executable: execution_status === 'executable',
        execution_status,
        template: parseTemplate(templateRecord.templateJson),
        template_id: templateRecord.templateId,
        template_version: templateRecord.version
      }
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
