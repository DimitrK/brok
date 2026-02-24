import type {ControlPlaneAuthzErrorCode} from '../contracts/control-authz-codes.js';

export interface ControllerPeer {
  hasPeerCred: boolean;
  uid: number;
  gid: number;
}

export interface ControllerAuthorizationPolicy {
  allowedUids: readonly number[];
  allowedGids: readonly number[];
}

export interface SocketSecurityMetadata {
  mode: number;
  ownerUid: number;
  ownerGid: number;
}

export interface SocketSecurityExpectations {
  expectedMode: number;
  expectedOwnerUid: number;
  expectedOwnerGid: number;
}

export type ControlAuthzFailure = {
  ok: false;
  code_namespace: 'control_authz';
  reason_code: ControlPlaneAuthzErrorCode;
  message: string;
};

export type ControlAuthzResult = {ok: true} | ControlAuthzFailure;

function fail(reasonCode: ControlPlaneAuthzErrorCode, message: string): ControlAuthzFailure {
  return {
    ok: false,
    code_namespace: 'control_authz',
    reason_code: reasonCode,
    message
  };
}

export function authorizeControllerPeer(
  peer: ControllerPeer,
  policy: ControllerAuthorizationPolicy
): ControlAuthzResult {
  if (!peer.hasPeerCred) {
    return fail('CTRL_AUTH_PEERCRED_UNAVAILABLE', 'SO_PEERCRED metadata is required');
  }

  const uidRestricted = policy.allowedUids.length > 0;
  const gidRestricted = policy.allowedGids.length > 0;
  const uidAuthorized = uidRestricted && policy.allowedUids.includes(peer.uid);
  const gidAuthorized = gidRestricted && policy.allowedGids.includes(peer.gid);

  // If both allow-lists are empty we operate in permissive mode for local setups.
  if (!uidRestricted && !gidRestricted) {
    return {ok: true};
  }

  // Planned policy semantics are OR-based: peer is authorized when either UID or GID matches.
  if (uidAuthorized || gidAuthorized) {
    return {ok: true};
  }

  if (uidRestricted) {
    return fail('CTRL_AUTH_PEERCRED_REJECTED_UID', `peer uid ${peer.uid} is not authorized`);
  }

  return fail('CTRL_AUTH_PEERCRED_REJECTED_GID', `peer gid ${peer.gid} is not authorized`);
}

export function validateSocketSecurityMetadata(
  metadata: SocketSecurityMetadata,
  expectations: SocketSecurityExpectations
): ControlAuthzResult {
  const effectiveMode = metadata.mode & 0o777;
  if (effectiveMode !== expectations.expectedMode) {
    return fail(
      'CTRL_AUTH_SOCKET_MODE_INVALID',
      `socket mode ${effectiveMode.toString(8)} != expected ${expectations.expectedMode.toString(8)}`
    );
  }

  if (metadata.ownerUid !== expectations.expectedOwnerUid || metadata.ownerGid !== expectations.expectedOwnerGid) {
    return fail(
      'CTRL_AUTH_SOCKET_OWNER_INVALID',
      `socket owner ${metadata.ownerUid}:${metadata.ownerGid} != expected ${expectations.expectedOwnerUid}:${expectations.expectedOwnerGid}`
    );
  }

  return {ok: true};
}
