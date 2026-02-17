import {
  PersistTemplateInvalidationOutboxInputSchema,
  TemplateInvalidationSignalSchema,
  OpenApiTemplateSchema,
  type PersistTemplateInvalidationOutboxInput,
  type Template
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient, RepositoryOperationContext} from '../types.js'
import {resolveRepositoryDbClient} from '../utils.js'

const parseTemplate = (value: unknown): Template => OpenApiTemplateSchema.parse(value)
const equivalentIsoTimestamp = (left: string, right: string): boolean => {
  const leftEpochMs = Date.parse(left)
  const rightEpochMs = Date.parse(right)
  return Number.isFinite(leftEpochMs) && Number.isFinite(rightEpochMs) && leftEpochMs === rightEpochMs
}

export class TemplateRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async createTemplateVersionImmutable(input: {
    tenant_id: string
    template: Template
    published_by?: string
  }): Promise<Template> {
    const template = OpenApiTemplateSchema.parse(input.template)
    const tenantId = input.tenant_id.trim()

    if (tenantId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    try {
      const existingVersions = await this.db.templateVersion.findMany({
        where: {
          tenantId,
          templateId: template.template_id
        },
        select: {
          version: true,
          provider: true
        },
        orderBy: {
          version: 'desc'
        }
      })

      if (existingVersions.length > 0) {
        const currentProvider = existingVersions[0]?.provider
        if (currentProvider !== template.provider) {
          throw new DbRepositoryError('conflict', 'Template provider cannot change across versions')
        }

        const highestVersion = existingVersions[0]?.version ?? 0
        if (template.version <= highestVersion) {
          throw new DbRepositoryError(
            'conflict',
            'Template version must strictly increase for immutable publish model'
          )
        }
      }

      const created = await this.db.templateVersion.create({
        data: {
          tenantId,
          templateId: template.template_id,
          version: template.version,
          provider: template.provider,
          status: 'active',
          templateJson: template,
          publishedBy: input.published_by
        }
      })

      return parseTemplate(created.templateJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getTemplateByTenantTemplateIdVersion(input: {
    tenant_id: string
    template_id: string
    version: number
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }, context?: RepositoryOperationContext): Promise<Template | null> {
    const tenantId = input.tenant_id.trim()
    const templateId = input.template_id.trim()

    if (tenantId.length === 0 || templateId.length === 0 || input.version < 1) {
      throw new DbRepositoryError('validation_error', 'Invalid template lookup input')
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
          model: 'templateVersion',
          method: 'findUnique'
        }
      ])

      const record = await dbClient.templateVersion.findUnique({
        where: {
          tenantId_templateId_version: {
            tenantId,
            templateId,
            version: input.version
          }
        }
      })

      if (!record || record.status !== 'active') {
        return null
      }

      return parseTemplate(record.templateJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getTemplateByIdVersion(input: {
    tenant_id: string
    template_id: string
    version: number
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }, context?: RepositoryOperationContext): Promise<Template | null> {
    return this.getTemplateByTenantTemplateIdVersion(input, context)
  }

  public async getLatestTemplateByTenantTemplateId(input: {
    tenant_id: string
    template_id: string
  }): Promise<Template | null> {
    const tenantId = input.tenant_id.trim()
    const templateId = input.template_id.trim()

    if (tenantId.length === 0 || templateId.length === 0) {
      throw new DbRepositoryError('validation_error', 'Invalid template lookup input')
    }

    try {
      const record = await this.db.templateVersion.findFirst({
        where: {
          tenantId,
          templateId,
          status: 'active'
        },
        orderBy: {
          version: 'desc'
        }
      })

      if (!record) {
        return null
      }

      return parseTemplate(record.templateJson)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listTemplateVersionsByTenantAndTemplateId(input: {
    tenant_id: string
    template_id: string
    context?: RepositoryOperationContext
    transaction_client?: unknown
  }, context?: RepositoryOperationContext): Promise<Template[]> {
    const operationContext =
      input.context ?? context ?? (input.transaction_client !== undefined
        ? {
            transaction_client: input.transaction_client
          }
        : undefined)

    const tenantId = input.tenant_id.trim()
    const templateId = input.template_id.trim()

    if (tenantId.length === 0 || templateId.length === 0) {
      throw new DbRepositoryError('validation_error', 'Invalid template list input')
    }

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'templateVersion',
          method: 'findMany'
        }
      ])

      const records = await dbClient.templateVersion.findMany({
        where: {
          tenantId,
          templateId
        },
        orderBy: {
          version: 'asc'
        }
      })

      return records.map(record => parseTemplate(record.templateJson))
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listLatestTemplatesByTenant(input: {tenant_id: string}): Promise<Template[]> {
    const tenantId = input.tenant_id.trim()
    if (tenantId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    try {
      const records = await this.db.templateVersion.findMany({
        where: {
          tenantId,
          status: 'active'
        },
        orderBy: [
          {
            templateId: 'asc'
          },
          {
            version: 'desc'
          }
        ]
      })

      const latestByTemplateId = new Map<string, Template>()
      for (const record of records) {
        if (!latestByTemplateId.has(record.templateId)) {
          latestByTemplateId.set(record.templateId, parseTemplate(record.templateJson))
        }
      }

      return [...latestByTemplateId.values()]
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async persistTemplateInvalidationOutbox(
    rawInput: PersistTemplateInvalidationOutboxInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<void> {
    const input = PersistTemplateInvalidationOutboxInputSchema.parse({
      signal: rawInput.signal
    })
    const operationContext =
      rawInput.context ?? context ?? (rawInput.transaction_client !== undefined
        ? {
            transaction_client: rawInput.transaction_client
          }
        : undefined)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'templateInvalidationOutbox',
          method: 'upsert'
        }
      ])

      const record = await dbClient.templateInvalidationOutbox.upsert({
        where: {
          tenantId_templateId_version_updatedAtSignal: {
            tenantId: input.signal.tenant_id,
            templateId: input.signal.template_id,
            version: input.signal.version,
            updatedAtSignal: new Date(input.signal.updated_at)
          }
        },
        create: {
          tenantId: input.signal.tenant_id,
          templateId: input.signal.template_id,
          version: input.signal.version,
          updatedAtSignal: new Date(input.signal.updated_at),
          payloadJson: input.signal,
          status: 'pending'
        },
        update: {}
      })

      const persistedSignal = TemplateInvalidationSignalSchema.parse(record.payloadJson)
      if (
        persistedSignal.tenant_id !== input.signal.tenant_id ||
        persistedSignal.template_id !== input.signal.template_id ||
        persistedSignal.version !== input.signal.version ||
        !equivalentIsoTimestamp(persistedSignal.updated_at, input.signal.updated_at)
      ) {
        throw new DbRepositoryError(
          'conflict',
          'Template invalidation outbox signal already exists with different payload'
        )
      }
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
