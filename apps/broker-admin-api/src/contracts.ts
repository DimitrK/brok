import {z} from 'zod'

export const adminRoleSchema = z.enum(['owner', 'admin', 'auditor', 'operator'])
export type AdminRole = z.infer<typeof adminRoleSchema>

export const staticAdminTokenSchema = z
  .object({
    token: z.string().min(20),
    subject: z.string().min(1),
    roles: z.array(adminRoleSchema).min(1),
    tenant_ids: z.array(z.string().min(1)).optional()
  })
  .strict()

export type StaticAdminToken = z.infer<typeof staticAdminTokenSchema>
