import {z} from 'zod';

import {ControlPlaneAuthzEventSchema} from '../contracts/events.js';

export const ControlProtocolCommandSchema = z.enum([
  'GetHealth',
  'GetStatus',
  'GetPolicySummary',
  'ReplacePolicySnapshot',
  'UpsertManagedCgroup',
  'DeleteManagedCgroup',
  'SetGlobalMode',
  'SetCgroupMode',
  'Shutdown'
]);

export type ControlProtocolCommand = z.infer<typeof ControlProtocolCommandSchema>;

export const ControlProtocolRequestSchema = z
  .object({
    command: ControlProtocolCommandSchema,
    payload: z.unknown().optional()
  })
  .strict();

export type ControlProtocolRequest = z.infer<typeof ControlProtocolRequestSchema>;

export const ControlProtocolErrorSchema = ControlPlaneAuthzEventSchema.extend({
  command: ControlProtocolCommandSchema.optional()
}).strict();

export type ControlProtocolError = z.infer<typeof ControlProtocolErrorSchema>;

export const ControlProtocolSuccessResponseSchema = z
  .object({
    ok: z.literal(true),
    command: ControlProtocolCommandSchema,
    data: z.unknown().optional()
  })
  .strict();

export const ControlProtocolFailureResponseSchema = z
  .object({
    ok: z.literal(false),
    error: ControlProtocolErrorSchema
  })
  .strict();

export const ControlProtocolResponseSchema = z.union([
  ControlProtocolSuccessResponseSchema,
  ControlProtocolFailureResponseSchema
]);

export type ControlProtocolResponse = z.infer<typeof ControlProtocolResponseSchema>;

export function parseControlProtocolResponse(input: unknown): ControlProtocolResponse {
  return ControlProtocolResponseSchema.parse(input);
}
