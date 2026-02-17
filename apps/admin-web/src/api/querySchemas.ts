import {z} from 'zod';
import {OpenApiAdminAccessRequestStatusSchema, OpenApiAdminRoleSchema, OpenApiAdminUserStatusSchema} from '@broker-interceptor/schemas';

export const approvalStatusFilterSchema = z.enum(['pending', 'approved', 'denied', 'expired']).optional();
export type ApprovalStatusFilter = z.infer<typeof approvalStatusFilterSchema>;

export const paginationFilterSchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).optional(),
    cursor: z.string().min(1).optional()
  })
  .strict();
export type PaginationFilter = z.infer<typeof paginationFilterSchema>;

export const adminUserFilterSchema = paginationFilterSchema
  .extend({
    status: OpenApiAdminUserStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: OpenApiAdminRoleSchema.optional(),
    search: z.string().min(1).optional()
  })
  .strict();
export type AdminUserFilter = z.infer<typeof adminUserFilterSchema>;

export const adminAccessRequestFilterSchema = paginationFilterSchema
  .extend({
    status: OpenApiAdminAccessRequestStatusSchema.optional(),
    tenant_id: z.string().min(1).optional(),
    role: OpenApiAdminRoleSchema.optional(),
    search: z.string().min(1).optional()
  })
  .strict();
export type AdminAccessRequestFilter = z.infer<typeof adminAccessRequestFilterSchema>;

export const auditFilterSchema = z
  .object({
    time_min: z.string().datetime({offset: true}).optional(),
    time_max: z.string().datetime({offset: true}).optional(),
    workload_id: z.string().min(1).optional(),
    tenant_id: z.string().min(1).optional(),
    integration_id: z.string().min(1).optional(),
    action_group: z.string().min(1).optional(),
    decision: z.enum(['allowed', 'denied', 'approval_required', 'throttled']).optional()
  })
  .strict();

export type AuditFilter = z.infer<typeof auditFilterSchema>;
