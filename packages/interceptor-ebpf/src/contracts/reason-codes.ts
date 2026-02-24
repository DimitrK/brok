import {z} from 'zod';

export const dataplaneVerdictReasonCodes = [
  'UNMANAGED_ALLOW',
  'OBSERVE_WOULD_ALLOW',
  'OBSERVE_WOULD_DENY_EXPLICIT',
  'OBSERVE_WOULD_DENY_DEFAULT',
  'ALLOW_EXPLICIT',
  'ALLOW_BROKER',
  'ALLOW_DNS',
  'DENY_EXPLICIT',
  'DENY_DEFAULT',
  'DENY_DEGRADED_FAIL_CLOSED',
  'ALLOW_DEGRADED_FAIL_OPEN'
] as const;

export const DataplaneVerdictReasonCodeSchema = z.enum(dataplaneVerdictReasonCodes);

export type DataplaneVerdictReasonCode = z.infer<typeof DataplaneVerdictReasonCodeSchema>;
