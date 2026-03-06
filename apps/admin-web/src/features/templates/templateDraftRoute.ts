import {z} from 'zod';

export const TEMPLATE_DRAFT_STORAGE_KEY = 'admin-web-template-draft';

const httpMethodSchema = z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

export const templateDraftRouteSchema = z
  .object({
    templateDraft: z
      .object({
        source: z.literal('audit'),
        provider: z.string(),
        template_name: z.string(),
        template_id_suffix: z.string().min(1),
        description: z.string().optional(),
        allowed_hosts: z.array(z.string().min(1)).min(1),
        path_groups: z
          .array(
            z
              .object({
                group_id: z.string(),
                risk_tier: z.enum(['low', 'medium', 'high']),
                approval_mode: z.enum(['none', 'required']),
                methods: z.array(httpMethodSchema).min(1),
                path_patterns: z.array(z.string().min(1)).min(1),
                query_allowlist: z.array(z.string()),
                header_forward_allowlist: z.array(z.string()),
                max_body_bytes: z.number().int().min(0),
                content_types: z.array(z.string()),
                upstream_auth: z
                  .object({
                    type: z.enum(['none', 'aws_sigv4']),
                    region: z.string().optional()
                  })
                  .optional()
              })
              .strict()
          )
          .min(1)
      })
      .strict()
  })
  .strict();

export type TemplateDraftRouteState = z.infer<typeof templateDraftRouteSchema>;
export type TemplateDraft = TemplateDraftRouteState['templateDraft'];

export const parseTemplateDraftRouteState = (value: unknown): TemplateDraft | undefined => {
  const parsed = templateDraftRouteSchema.safeParse(value);
  if (!parsed.success) {
    return undefined;
  }

  return parsed.data.templateDraft;
};

export const readTemplateDraftFromStorage = (
  storage: Pick<Storage, 'getItem'>,
  storageKey = TEMPLATE_DRAFT_STORAGE_KEY
): TemplateDraft | undefined => {
  const rawValue = storage.getItem(storageKey);
  if (!rawValue) {
    return undefined;
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(rawValue);
  } catch {
    return undefined;
  }

  return parseTemplateDraftRouteState(parsedJson);
};
