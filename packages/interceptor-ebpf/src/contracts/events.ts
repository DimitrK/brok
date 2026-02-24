import {z} from 'zod';

import {ControlPlaneAuthzErrorCodeSchema} from './control-authz-codes.js';
import {DataplaneVerdictReasonCodeSchema} from './reason-codes.js';

const observeIntentCodes = new Set([
  'OBSERVE_WOULD_ALLOW',
  'OBSERVE_WOULD_DENY_EXPLICIT',
  'OBSERVE_WOULD_DENY_DEFAULT'
]);

export const DataplaneVerdictSchema = z.enum(['allow', 'deny']);

export const DataplaneHookSchema = z.enum(['connect4', 'connect6', 'sendmsg4', 'sendmsg6']);

export const DataplanePacketEventSchema = z
  .object({
    code_namespace: z.literal('dataplane_verdict'),
    reason_code: DataplaneVerdictReasonCodeSchema,
    verdict: DataplaneVerdictSchema,
    would_block: z.boolean().optional(),
    hook: DataplaneHookSchema.optional(),
    cgroup_id: z.string().optional(),
    message: z.string().optional()
  })
  .strict()
  .superRefine((value, ctx) => {
    const usesObserveIntent = observeIntentCodes.has(value.reason_code);

    if (usesObserveIntent && value.verdict !== 'allow') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'observe reason codes must serialize verdict=allow'
      });
    }

    if (usesObserveIntent && value.would_block === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'observe reason codes require would_block'
      });
    }

    if (!usesObserveIntent && value.would_block !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'would_block is only valid for observe reason codes'
      });
    }
  });

export type DataplanePacketEvent = z.infer<typeof DataplanePacketEventSchema>;

export const ControlPlaneAuthzEventSchema = z
  .object({
    code_namespace: z.literal('control_authz'),
    reason_code: ControlPlaneAuthzErrorCodeSchema,
    message: z.string().min(1),
    command: z.string().min(1).optional()
  })
  .strict();

export type ControlPlaneAuthzEvent = z.infer<typeof ControlPlaneAuthzEventSchema>;

export function parseDataplanePacketEvent(input: unknown): DataplanePacketEvent {
  return DataplanePacketEventSchema.parse(input);
}

export function parseControlPlaneAuthzEvent(input: unknown): ControlPlaneAuthzEvent {
  return ControlPlaneAuthzEventSchema.parse(input);
}
