import {z} from 'zod'

import {
  AdminAccessRequestListResponseSchema,
  AdminAccessRequestSchema,
  AdminIdentityListResponseSchema,
  AdminIdentitySchema,
  AdminSignupPolicySchema,
  CreateAdminAccessRequestInputSchema,
  CreateAdminIdentityInputSchema,
  FindAdminIdentityByIssuerSubjectInputSchema,
  GetAdminIdentityByIdInputSchema,
  ListAdminAccessRequestsInputSchema,
  ListAdminIdentitiesInputSchema,
  SetAdminSignupPolicyInputSchema,
  TransitionAdminAccessRequestStatusInputSchema,
  UpdateAdminIdentityBindingsInputSchema,
  UpdateAdminIdentityStatusInputSchema,
  UpsertAdminRoleBindingsInputSchema,
  UserRoleSchema,
  type AdminAccessRequest,
  type AdminAccessRequestListResponse,
  type AdminIdentity,
  type AdminIdentityListResponse,
  type AdminSignupPolicy,
  type CreateAdminAccessRequestInput,
  type CreateAdminIdentityInput,
  type FindAdminIdentityByIssuerSubjectInput,
  type ListAdminAccessRequestsInput,
  type ListAdminIdentitiesInput,
  type SetAdminSignupPolicyInput,
  type TransitionAdminAccessRequestStatusInput,
  type UpdateAdminIdentityBindingsInput,
  type UpdateAdminIdentityStatusInput,
  type UpsertAdminRoleBindingsInput,
  type UserRole
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {
  AdminAccessRequestRow,
  AdminIdentityRowWithBindings,
  DatabaseClient,
  RepositoryOperationContext
} from '../types.js'
import {
  assertNonEmptyString,
  createDomainId,
  decodeCursor,
  encodeCursor,
  normalizeUniqueStringList,
  resolveRepositoryDbClient
} from '../utils.js'

const ADMIN_DEFAULT_LIST_LIMIT = 50

const EmailDomainSchema = z
  .string()
  .transform(value => value.trim().toLowerCase())
  .superRefine((domain, context) => {
    if (domain.length === 0) {
      context.addIssue({
        code: 'custom',
        message: 'allowed_email_domains contains an empty domain'
      })
      return
    }

    if (domain.includes('@')) {
      context.addIssue({
        code: 'custom',
        message: `allowed_email_domains entry must be a domain only: ${domain}`
      })
      return
    }

    try {
      const normalized = new URL(`https://${domain}`).hostname.toLowerCase()
      if (normalized !== domain || normalized.length === 0 || normalized.endsWith('.')) {
        context.addIssue({
          code: 'custom',
          message: `Invalid allowed_email_domains entry: ${domain}`
        })
      }
    } catch {
      context.addIssue({
        code: 'custom',
        message: `Invalid allowed_email_domains entry: ${domain}`
      })
    }
  })

const AdminIdentityCursorSchema = z
  .object({
    created_at: z.iso.datetime({offset: true}),
    identity_id: z.string().min(1)
  })
  .strict()

const AdminAccessRequestCursorSchema = z
  .object({
    created_at: z.iso.datetime({offset: true}),
    request_id: z.string().min(1)
  })
  .strict()

const adminIdentityInclude = {
  roleBindings: {
    select: {
      role: true
    },
    orderBy: {
      role: 'asc'
    }
  },
  tenantScopes: {
    select: {
      tenantId: true
    },
    orderBy: {
      tenantId: 'asc'
    }
  }
} as const

const normalizeRoles = (roles: readonly UserRole[]): AdminIdentity['roles'] =>
  normalizeUniqueStringList([...roles]) as AdminIdentity['roles']

const normalizeTenantIds = (tenantIds: readonly string[]): string[] => normalizeUniqueStringList([...tenantIds])

const normalizeAllowedEmailDomains = (domains: readonly string[]): string[] => {
  const parsed = z.array(EmailDomainSchema).safeParse(domains)
  if (!parsed.success) {
    throw new DbRepositoryError(
      'validation_error',
      parsed.error.issues[0]?.message ?? 'Invalid allowed_email_domains entry'
    )
  }

  return normalizeUniqueStringList(parsed.data)
}

const normalizeOptionalString = (value: string | undefined): string | undefined => {
  if (value === undefined) {
    return undefined
  }

  const normalized = value.trim()
  return normalized.length > 0 ? normalized : undefined
}

const resolveOperationContext = (
  context: RepositoryOperationContext | undefined,
  transactionClient: unknown,
  fallbackContext?: RepositoryOperationContext
): RepositoryOperationContext | undefined =>
  context ?? fallbackContext ?? (transactionClient !== undefined ? {transaction_client: transactionClient} : undefined)

const parseAdminIdentityCursor = (rawCursor: string): {createdAt: Date; identityId: string} => {
  const decoded = decodeCursor(rawCursor)
  const [created_at, identity_id] = decoded.split('|')

  const parsed = AdminIdentityCursorSchema.safeParse({
    created_at,
    identity_id
  })
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', 'Invalid admin user cursor')
  }

  return {
    createdAt: new Date(parsed.data.created_at),
    identityId: parsed.data.identity_id
  }
}

const buildAdminIdentityCursor = (record: {createdAt: Date; identityId: string}): string =>
  encodeCursor(`${record.createdAt.toISOString()}|${record.identityId}`)

const parseAdminAccessRequestCursor = (rawCursor: string): {createdAt: Date; requestId: string} => {
  const decoded = decodeCursor(rawCursor)
  const [created_at, request_id] = decoded.split('|')

  const parsed = AdminAccessRequestCursorSchema.safeParse({
    created_at,
    request_id
  })
  if (!parsed.success) {
    throw new DbRepositoryError('validation_error', 'Invalid admin access request cursor')
  }

  return {
    createdAt: new Date(parsed.data.created_at),
    requestId: parsed.data.request_id
  }
}

const buildAdminAccessRequestCursor = (record: {createdAt: Date; requestId: string}): string =>
  encodeCursor(`${record.createdAt.toISOString()}|${record.requestId}`)

const hasOwnerRole = (record: {roleBindings: Array<{role: string}>}): boolean =>
  record.roleBindings.some(binding => binding.role === 'owner')

const toAdminSignupPolicy = (record: {
  newUserMode: 'allowed' | 'blocked'
  requireVerifiedEmail: boolean
  allowedEmailDomains: string[]
  updatedAt: Date
  updatedBy: string
}): AdminSignupPolicy =>
  AdminSignupPolicySchema.parse({
    new_user_mode: record.newUserMode,
    require_verified_email: record.requireVerifiedEmail,
    allowed_email_domains: record.allowedEmailDomains,
    updated_at: record.updatedAt.toISOString(),
    updated_by: record.updatedBy
  })

const toAdminIdentity = (record: AdminIdentityRowWithBindings): AdminIdentity =>
  AdminIdentitySchema.parse({
    identity_id: record.identityId,
    issuer: record.issuer,
    subject: record.subject,
    email: record.email,
    ...(record.name ? {name: record.name} : {}),
    status: record.status,
    roles: normalizeRoles(record.roleBindings.map(binding => UserRoleSchema.parse(binding.role))),
    tenant_ids: normalizeTenantIds(record.tenantScopes.map(scope => scope.tenantId)),
    created_at: record.createdAt.toISOString(),
    updated_at: record.updatedAt.toISOString()
  })

const toAdminAccessRequest = (record: AdminAccessRequestRow): AdminAccessRequest =>
  AdminAccessRequestSchema.parse({
    request_id: record.requestId,
    issuer: record.issuer,
    subject: record.subject,
    email: record.email,
    ...(record.name ? {name: record.name} : {}),
    requested_roles: normalizeRoles(record.requestedRoles.map(role => UserRoleSchema.parse(role))),
    requested_tenant_ids: normalizeTenantIds(record.requestedTenantIds),
    status: record.status,
    ...(record.decisionReason ?? record.requestReason
      ? {
          reason: record.decisionReason ?? record.requestReason ?? undefined
        }
      : {}),
    ...(record.decidedBy ? {decided_by: record.decidedBy} : {}),
    ...(record.decidedAt ? {decided_at: record.decidedAt.toISOString()} : {}),
    created_at: record.createdAt.toISOString(),
    updated_at: record.updatedAt.toISOString()
  })

export class AdminAuthRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async getAdminSignupPolicy(context?: RepositoryOperationContext): Promise<AdminSignupPolicy> {
    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'adminSignupPolicy',
          method: 'upsert'
        }
      ])

      const policy = await dbClient.adminSignupPolicy.upsert({
        where: {
          id: 'default'
        },
        create: {
          id: 'default',
          newUserMode: 'blocked',
          requireVerifiedEmail: true,
          allowedEmailDomains: [],
          updatedBy: 'system'
        },
        update: {}
      })

      return toAdminSignupPolicy(policy)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async setAdminSignupPolicy(
    rawInput: SetAdminSignupPolicyInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminSignupPolicy> {
    const input = SetAdminSignupPolicyInputSchema.parse({
      policy: rawInput.policy,
      actor: rawInput.actor,
      updated_at: rawInput.updated_at
    })
    const actor = assertNonEmptyString(input.actor, 'actor')
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    const normalizedAllowedEmailDomains =
      input.policy.allowed_email_domains !== undefined
        ? normalizeAllowedEmailDomains(input.policy.allowed_email_domains)
        : undefined

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'adminSignupPolicy',
          method: 'upsert'
        }
      ])

      const policy = await dbClient.adminSignupPolicy.upsert({
        where: {
          id: 'default'
        },
        create: {
          id: 'default',
          newUserMode: input.policy.new_user_mode,
          requireVerifiedEmail: input.policy.require_verified_email ?? true,
          allowedEmailDomains: normalizedAllowedEmailDomains ?? [],
          updatedBy: actor,
          ...(input.updated_at ? {updatedAt: new Date(input.updated_at)} : {})
        },
        update: {
          newUserMode: input.policy.new_user_mode,
          ...(input.policy.require_verified_email !== undefined
            ? {
                requireVerifiedEmail: input.policy.require_verified_email
              }
            : {}),
          ...(normalizedAllowedEmailDomains !== undefined
            ? {
                allowedEmailDomains: normalizedAllowedEmailDomains
              }
            : {}),
          updatedBy: actor,
          ...(input.updated_at ? {updatedAt: new Date(input.updated_at)} : {})
        }
      })

      return toAdminSignupPolicy(policy)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listAdminIdentities(
    rawInput: Partial<ListAdminIdentitiesInput> & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    } = {},
    context?: RepositoryOperationContext
  ): Promise<AdminIdentityListResponse> {
    const input = ListAdminIdentitiesInputSchema.parse({
      status: rawInput.status,
      tenant_id: rawInput.tenant_id,
      role: rawInput.role,
      search: rawInput.search,
      limit: rawInput.limit ?? ADMIN_DEFAULT_LIST_LIMIT,
      cursor: rawInput.cursor
    })
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)
    const cursor = input.cursor ? parseAdminIdentityCursor(input.cursor) : undefined

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'adminIdentity',
          method: 'findMany'
        }
      ])

      const conditions: Record<string, unknown>[] = []

      if (input.status) {
        conditions.push({status: input.status})
      }

      if (input.tenant_id) {
        conditions.push({
          tenantScopes: {
            some: {
              tenantId: input.tenant_id
            }
          }
        })
      }

      if (input.role) {
        conditions.push({
          roleBindings: {
            some: {
              role: input.role
            }
          }
        })
      }

      if (input.search) {
        conditions.push({
          OR: [
            {
              email: {
                contains: input.search,
                mode: 'insensitive'
              }
            },
            {
              name: {
                contains: input.search,
                mode: 'insensitive'
              }
            },
            {
              subject: {
                contains: input.search,
                mode: 'insensitive'
              }
            }
          ]
        })
      }

      if (cursor) {
        conditions.push({
          OR: [
            {
              createdAt: {
                lt: cursor.createdAt
              }
            },
            {
              createdAt: cursor.createdAt,
              identityId: {
                lt: cursor.identityId
              }
            }
          ]
        })
      }

      const records = await dbClient.adminIdentity.findMany({
        ...(conditions.length > 0
          ? {
              where: {
                AND: conditions
              }
            }
          : {}),
        include: adminIdentityInclude,
        orderBy: [
          {
            createdAt: 'desc'
          },
          {
            identityId: 'desc'
          }
        ],
        take: input.limit + 1
      })

      const pageItems = records.slice(0, input.limit)
      const users = pageItems.map(toAdminIdentity)

      return AdminIdentityListResponseSchema.parse({
        users,
        ...(records.length > input.limit && pageItems.length > 0
          ? {
              next_cursor: buildAdminIdentityCursor(pageItems[pageItems.length - 1])
            }
          : {})
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getAdminIdentityById(
    rawInput: {
      identity_id: string
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminIdentity | null> {
    const input = GetAdminIdentityByIdInputSchema.parse({
      identity_id: rawInput.identity_id
    })
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    try {
      const identity = await this.getAdminIdentityRecordById(input.identity_id, operationContext)
      return identity ? toAdminIdentity(identity) : null
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async findAdminIdentityByIssuerSubject(
    rawInput: FindAdminIdentityByIssuerSubjectInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminIdentity | null> {
    const input = FindAdminIdentityByIssuerSubjectInputSchema.parse({
      issuer: rawInput.issuer,
      subject: rawInput.subject
    })
    const issuer = assertNonEmptyString(input.issuer, 'issuer')
    const subject = assertNonEmptyString(input.subject, 'subject')
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'adminIdentity',
          method: 'findUnique'
        }
      ])

      const identity = await dbClient.adminIdentity.findUnique({
        where: {
          issuer_subject: {
            issuer,
            subject
          }
        },
        include: adminIdentityInclude
      })

      if (!identity) {
        return null
      }

      return toAdminIdentity(identity)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async createAdminIdentity(
    rawInput: CreateAdminIdentityInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminIdentity> {
    const input = CreateAdminIdentityInputSchema.parse({
      identity_id: rawInput.identity_id,
      principal: rawInput.principal,
      status: rawInput.status
    })
    const principal = input.principal
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    const identityId =
      input.identity_id !== undefined ? assertNonEmptyString(input.identity_id, 'identity_id') : createDomainId('adm_')
    const issuer = assertNonEmptyString(principal.issuer, 'issuer')
    const subject = assertNonEmptyString(principal.subject, 'subject')
    const email = principal.email.trim().toLowerCase()
    const name = normalizeOptionalString(principal.name)
    const roles = normalizeRoles(principal.roles)
    const tenantIds = normalizeTenantIds(principal.tenant_ids)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'tenant',
          method: 'findMany'
        },
        {
          model: 'adminIdentity',
          method: 'create'
        }
      ])

      await this.assertTenantIdsExist(dbClient, tenantIds)

      const identity = await dbClient.adminIdentity.create({
        data: {
          identityId,
          issuer,
          subject,
          email,
          name,
          status: input.status ?? 'active',
          roleBindings: {
            create: roles.map(role => ({
              role
            }))
          },
          tenantScopes: {
            create: tenantIds.map(tenantId => ({
              tenantId
            }))
          }
        },
        include: adminIdentityInclude
      })

      return toAdminIdentity(identity)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async updateAdminIdentityStatus(
    rawInput: UpdateAdminIdentityStatusInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminIdentity> {
    const input = UpdateAdminIdentityStatusInputSchema.parse({
      identity_id: rawInput.identity_id,
      status: rawInput.status
    })
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'adminIdentity',
          method: 'findUnique'
        },
        {
          model: 'adminIdentity',
          method: 'count'
        },
        {
          model: 'adminIdentity',
          method: 'update'
        }
      ])

      const existing = await this.getAdminIdentityRecordById(input.identity_id, operationContext)
      if (!existing) {
        throw new DbRepositoryError('not_found', 'Admin identity not found')
      }

      if (existing.status === input.status) {
        return toAdminIdentity(existing)
      }

      if (existing.status === 'active' && hasOwnerRole(existing) && input.status !== 'active') {
        await this.assertNotLastActiveOwner(dbClient, existing.identityId)
      }

      const updated = await dbClient.adminIdentity.update({
        where: {
          identityId: existing.identityId
        },
        data: {
          status: input.status
        },
        include: adminIdentityInclude
      })

      return toAdminIdentity(updated)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async updateAdminIdentityBindings(
    rawInput: UpdateAdminIdentityBindingsInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminIdentity> {
    const input = UpdateAdminIdentityBindingsInputSchema.parse({
      identity_id: rawInput.identity_id,
      patch: rawInput.patch
    })
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    const requestedRoles = input.patch.roles ? normalizeRoles(input.patch.roles) : undefined
    const requestedTenantIds = input.patch.tenant_ids ? normalizeTenantIds(input.patch.tenant_ids) : undefined

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'tenant',
          method: 'findMany'
        },
        {
          model: 'adminIdentity',
          method: 'findUnique'
        },
        {
          model: 'adminIdentity',
          method: 'count'
        },
        {
          model: 'adminIdentity',
          method: 'update'
        }
      ])

      const existing = await this.getAdminIdentityRecordById(input.identity_id, operationContext)
      if (!existing) {
        throw new DbRepositoryError('not_found', 'Admin identity not found')
      }

      if (requestedTenantIds !== undefined) {
        await this.assertTenantIdsExist(dbClient, requestedTenantIds)
      }

      const currentRoles = normalizeRoles(existing.roleBindings.map(binding => UserRoleSchema.parse(binding.role)))
      const currentTenantIds = normalizeTenantIds(existing.tenantScopes.map(scope => scope.tenantId))

      const nextRoles = requestedRoles ?? currentRoles
      const nextTenantIds = requestedTenantIds ?? currentTenantIds

      if (existing.status === 'active' && currentRoles.includes('owner') && !nextRoles.includes('owner')) {
        await this.assertNotLastActiveOwner(dbClient, existing.identityId)
      }

      const rolesChanged = requestedRoles !== undefined && requestedRoles.join('|') !== currentRoles.join('|')
      const tenantIdsChanged = requestedTenantIds !== undefined && requestedTenantIds.join('|') !== currentTenantIds.join('|')
      if (!rolesChanged && !tenantIdsChanged) {
        return toAdminIdentity(existing)
      }

      const updated = await dbClient.adminIdentity.update({
        where: {
          identityId: existing.identityId
        },
        data: {
          ...(requestedRoles !== undefined
            ? {
                roleBindings: {
                  deleteMany: {},
                  create: nextRoles.map(role => ({
                    role
                  }))
                }
              }
            : {}),
          ...(requestedTenantIds !== undefined
            ? {
                tenantScopes: {
                  deleteMany: {},
                  create: nextTenantIds.map(tenantId => ({
                    tenantId
                  }))
                }
              }
            : {})
        },
        include: adminIdentityInclude
      })

      return toAdminIdentity(updated)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async createAdminAccessRequest(
    rawInput: CreateAdminAccessRequestInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminAccessRequest> {
    const input = CreateAdminAccessRequestInputSchema.parse({
      request_id: rawInput.request_id,
      principal: rawInput.principal,
      reason: rawInput.reason
    })
    const principal = input.principal
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    const requestId =
      input.request_id !== undefined ? assertNonEmptyString(input.request_id, 'request_id') : createDomainId('aar_')
    const issuer = assertNonEmptyString(principal.issuer, 'issuer')
    const subject = assertNonEmptyString(principal.subject, 'subject')
    const email = principal.email.trim().toLowerCase()
    const name = normalizeOptionalString(principal.name)
    const roles = normalizeRoles(principal.roles)
    const tenantIds = normalizeTenantIds(principal.tenant_ids)
    const requestReason = normalizeOptionalString(input.reason)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'adminAccessRequest',
          method: 'create'
        }
      ])

      const request = await dbClient.adminAccessRequest.create({
        data: {
          requestId,
          issuer,
          subject,
          email,
          name,
          requestedRoles: roles,
          requestedTenantIds: tenantIds,
          status: 'pending',
          requestReason
        }
      })

      return toAdminAccessRequest(request)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listAdminAccessRequests(
    rawInput: Partial<ListAdminAccessRequestsInput> & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    } = {},
    context?: RepositoryOperationContext
  ): Promise<AdminAccessRequestListResponse> {
    const input = ListAdminAccessRequestsInputSchema.parse({
      status: rawInput.status,
      tenant_id: rawInput.tenant_id,
      role: rawInput.role,
      search: rawInput.search,
      limit: rawInput.limit ?? ADMIN_DEFAULT_LIST_LIMIT,
      cursor: rawInput.cursor
    })
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)
    const cursor = input.cursor ? parseAdminAccessRequestCursor(input.cursor) : undefined

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'adminAccessRequest',
          method: 'findMany'
        }
      ])

      const conditions: Record<string, unknown>[] = []

      if (input.status) {
        conditions.push({status: input.status})
      }

      if (input.tenant_id) {
        conditions.push({
          requestedTenantIds: {
            has: input.tenant_id
          }
        })
      }

      if (input.role) {
        conditions.push({
          requestedRoles: {
            has: input.role
          }
        })
      }

      if (input.search) {
        conditions.push({
          OR: [
            {
              email: {
                contains: input.search,
                mode: 'insensitive'
              }
            },
            {
              name: {
                contains: input.search,
                mode: 'insensitive'
              }
            },
            {
              subject: {
                contains: input.search,
                mode: 'insensitive'
              }
            },
            {
              requestId: {
                contains: input.search,
                mode: 'insensitive'
              }
            }
          ]
        })
      }

      if (cursor) {
        conditions.push({
          OR: [
            {
              createdAt: {
                lt: cursor.createdAt
              }
            },
            {
              createdAt: cursor.createdAt,
              requestId: {
                lt: cursor.requestId
              }
            }
          ]
        })
      }

      const records = await dbClient.adminAccessRequest.findMany({
        ...(conditions.length > 0
          ? {
              where: {
                AND: conditions
              }
            }
          : {}),
        orderBy: [
          {
            createdAt: 'desc'
          },
          {
            requestId: 'desc'
          }
        ],
        take: input.limit + 1
      })

      const pageItems = records.slice(0, input.limit)
      const requests = pageItems.map(toAdminAccessRequest)

      return AdminAccessRequestListResponseSchema.parse({
        requests,
        ...(records.length > input.limit && pageItems.length > 0
          ? {
              next_cursor: buildAdminAccessRequestCursor(pageItems[pageItems.length - 1])
            }
          : {})
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async transitionAdminAccessRequestStatus(
    rawInput: TransitionAdminAccessRequestStatusInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminAccessRequest> {
    const input = TransitionAdminAccessRequestStatusInputSchema.parse({
      request_id: rawInput.request_id,
      status: rawInput.status,
      actor: rawInput.actor,
      reason: rawInput.reason,
      decided_at: rawInput.decided_at
    })
    const requestId = assertNonEmptyString(input.request_id, 'request_id')
    const actor = assertNonEmptyString(input.actor, 'actor')
    const decisionReason = normalizeOptionalString(input.reason)
    const decidedAt = input.decided_at ? new Date(input.decided_at) : new Date()
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, operationContext, [
        {
          model: 'adminAccessRequest',
          method: 'findUnique'
        },
        {
          model: 'adminAccessRequest',
          method: 'updateMany'
        }
      ])

      const transitionResult = await dbClient.adminAccessRequest.updateMany({
        where: {
          requestId,
          status: 'pending'
        },
        data: {
          status: input.status,
          decidedBy: actor,
          decidedAt,
          ...(decisionReason !== undefined ? {decisionReason} : {})
        }
      })

      if (transitionResult.count === 0) {
        const current = await dbClient.adminAccessRequest.findUnique({
          where: {
            requestId
          }
        })

        if (!current) {
          throw new DbRepositoryError('not_found', 'Admin access request not found')
        }

        if (current.status === input.status) {
          return toAdminAccessRequest(current)
        }

        throw new DbRepositoryError(
          'state_transition_invalid',
          'Admin access request status can only transition from pending to decided states'
        )
      }

      const updated = await dbClient.adminAccessRequest.findUnique({
        where: {
          requestId
        }
      })

      if (!updated) {
        throw new DbRepositoryError('not_found', 'Admin access request not found after transition')
      }

      return toAdminAccessRequest(updated)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async upsertAdminRoleBindings(
    rawInput: UpsertAdminRoleBindingsInput & {
      context?: RepositoryOperationContext
      transaction_client?: unknown
    },
    context?: RepositoryOperationContext
  ): Promise<AdminIdentity> {
    const input = UpsertAdminRoleBindingsInputSchema.parse({
      issuer: rawInput.issuer,
      subject: rawInput.subject,
      roles: rawInput.roles,
      tenant_ids: rawInput.tenant_ids
    })
    const operationContext = resolveOperationContext(rawInput.context, rawInput.transaction_client, context)

    const identity = await this.findAdminIdentityByIssuerSubject(
      {
        issuer: input.issuer,
        subject: input.subject,
        context: operationContext
      },
      operationContext
    )

    if (!identity) {
      throw new DbRepositoryError('not_found', 'Admin identity not found for role binding upsert')
    }

    return this.updateAdminIdentityBindings(
      {
        identity_id: identity.identity_id,
        patch: {
          roles: input.roles,
          ...(input.tenant_ids !== undefined ? {tenant_ids: input.tenant_ids} : {})
        },
        context: operationContext
      },
      operationContext
    )
  }

  private async getAdminIdentityRecordById(
    identityId: string,
    context?: RepositoryOperationContext
  ): Promise<AdminIdentityRowWithBindings | null> {
    const dbClient = resolveRepositoryDbClient(this.db, context, [
      {
        model: 'adminIdentity',
        method: 'findUnique'
      }
    ])

    return dbClient.adminIdentity.findUnique({
      where: {
        identityId
      },
      include: adminIdentityInclude
    })
  }

  private async assertTenantIdsExist(dbClient: DatabaseClient, tenantIds: string[]): Promise<void> {
    if (tenantIds.length === 0) {
      return
    }

    const existingTenants = await dbClient.tenant.findMany({
      where: {
        tenantId: {
          in: tenantIds
        }
      }
    })

    const existingTenantSet = new Set(existingTenants.map(tenant => tenant.tenantId))
    const missingTenantIds = tenantIds.filter(tenantId => !existingTenantSet.has(tenantId))

    if (missingTenantIds.length > 0) {
      throw new DbRepositoryError(
        'validation_error',
        `Unknown tenant_id values: ${missingTenantIds.join(', ')}`
      )
    }
  }

  private async assertNotLastActiveOwner(dbClient: DatabaseClient, identityIdToExclude: string): Promise<void> {
    const remainingActiveOwnerCount = await dbClient.adminIdentity.count({
      where: {
        status: 'active',
        identityId: {
          not: identityIdToExclude
        },
        roleBindings: {
          some: {
            role: 'owner'
          }
        }
      }
    })

    if (remainingActiveOwnerCount === 0) {
      throw new DbRepositoryError('state_transition_invalid', 'Operation would remove the last active owner')
    }
  }
}
