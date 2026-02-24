import {z} from 'zod';

export const controlPlaneAuthzErrorCodes = [
  'CTRL_AUTH_PEERCRED_UNAVAILABLE',
  'CTRL_AUTH_PEERCRED_REJECTED_UID',
  'CTRL_AUTH_PEERCRED_REJECTED_GID',
  'CTRL_AUTH_SOCKET_MODE_INVALID',
  'CTRL_AUTH_SOCKET_OWNER_INVALID'
] as const;

export const ControlPlaneAuthzErrorCodeSchema = z.enum(controlPlaneAuthzErrorCodes);

export type ControlPlaneAuthzErrorCode = z.infer<typeof ControlPlaneAuthzErrorCodeSchema>;
