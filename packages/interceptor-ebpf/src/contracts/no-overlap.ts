import {controlPlaneAuthzErrorCodes, type ControlPlaneAuthzErrorCode} from './control-authz-codes.js';
import {dataplaneVerdictReasonCodes, type DataplaneVerdictReasonCode} from './reason-codes.js';

type AssertNever<T extends never> = T;
type DataplaneAndControlPlaneOverlap = Extract<DataplaneVerdictReasonCode, ControlPlaneAuthzErrorCode>;

// Compile-time guard: any overlap makes TypeScript fail this package build.
export type DataplaneAndControlPlaneCodesMustNotOverlap = AssertNever<DataplaneAndControlPlaneOverlap>;

export function assertNoReasonCodeOverlap(): void {
  const overlaps = dataplaneVerdictReasonCodes.filter(reasonCode =>
    (controlPlaneAuthzErrorCodes as readonly string[]).includes(reasonCode)
  );

  if (overlaps.length > 0) {
    throw new Error(`Dataplane/control-plane reason code overlap detected: ${overlaps.join(', ')}`);
  }
}
