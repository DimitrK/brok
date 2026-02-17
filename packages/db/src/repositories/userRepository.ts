import {
  CreateHumanUserInputSchema,
  HumanUserSchema,
  UpdateHumanUserRolesInputSchema,
  UserRoleSchema,
  type CreateHumanUserInput,
  type HumanUser
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient} from '../types.js'
import {createDomainId, normalizeUniqueStringList} from '../utils.js'

const normalizeRoles = (roles: Array<(typeof UserRoleSchema)['enum'][keyof (typeof UserRoleSchema)['enum']]>) =>
  normalizeUniqueStringList(roles) as HumanUser['roles']

const toHumanUser = (record: {
  userId: string
  tenantId: string
  email: string
  enabled: boolean
  displayName: string | null
  oidcSubject: string | null
  oidcIssuer: string | null
  createdAt: Date
  roles: Array<{
    role: string
  }>
}): HumanUser =>
  HumanUserSchema.parse({
    user_id: record.userId,
    tenant_id: record.tenantId,
    email: record.email,
    roles: normalizeRoles(
      record.roles.map(roleRecord => UserRoleSchema.parse(roleRecord.role))
    ),
    enabled: record.enabled,
    ...(record.displayName ? {display_name: record.displayName} : {}),
    ...(record.oidcSubject ? {oidc_subject: record.oidcSubject} : {}),
    ...(record.oidcIssuer ? {oidc_issuer: record.oidcIssuer} : {}),
    created_at: record.createdAt.toISOString()
  })

export class UserRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async create(rawInput: CreateHumanUserInput): Promise<HumanUser> {
    const input = CreateHumanUserInputSchema.parse(rawInput)

    try {
      const created = await this.db.humanUser.create({
        data: {
          userId: input.user_id ?? createDomainId('u_'),
          tenantId: input.tenant_id,
          email: input.email,
          enabled: input.enabled ?? true,
          displayName: input.display_name,
          oidcSubject: input.oidc_subject,
          oidcIssuer: input.oidc_issuer,
          roles: {
            create: normalizeRoles(input.roles).map(role => ({
              role
            }))
          }
        },
        include: {
          roles: {
            select: {
              role: true
            }
          }
        }
      })

      return toHumanUser(created)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getById(input: {user_id: string}): Promise<HumanUser | null> {
    const userId = input.user_id.trim()
    if (userId.length === 0) {
      throw new DbRepositoryError('validation_error', 'user_id cannot be empty')
    }

    try {
      const record = await this.db.humanUser.findUnique({
        where: {
          userId
        },
        include: {
          roles: {
            select: {
              role: true
            }
          }
        }
      })

      if (!record) {
        return null
      }

      return toHumanUser(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listByTenant(input: {tenant_id: string}): Promise<HumanUser[]> {
    const tenantId = input.tenant_id.trim()
    if (tenantId.length === 0) {
      throw new DbRepositoryError('validation_error', 'tenant_id cannot be empty')
    }

    try {
      const records = await this.db.humanUser.findMany({
        where: {
          tenantId
        },
        include: {
          roles: {
            select: {
              role: true
            },
            orderBy: {
              role: 'asc'
            }
          }
        },
        orderBy: {
          createdAt: 'asc'
        }
      })

      return records.map(toHumanUser)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async updateRoles(rawInput: {user_id: string; roles: HumanUser['roles']}): Promise<HumanUser> {
    const input = UpdateHumanUserRolesInputSchema.parse(rawInput)

    try {
      const updated = await this.db.humanUser.update({
        where: {
          userId: input.user_id
        },
        data: {
          roles: {
            deleteMany: {},
            create: normalizeRoles(input.roles).map(role => ({
              role
            }))
          }
        },
        include: {
          roles: {
            select: {
              role: true
            }
          }
        }
      })

      return toHumanUser(updated)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}
