import {describe, expect, it} from 'vitest';

import {authorizeControllerPeer, validateSocketSecurityMetadata} from '../control/authz.js';

describe('control-plane socket authz', () => {
  it('returns PEERCRED_UNAVAILABLE when peer credentials are missing', () => {
    const result = authorizeControllerPeer(
      {hasPeerCred: false, uid: 123, gid: 456},
      {allowedUids: [123], allowedGids: [456]}
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe('CTRL_AUTH_PEERCRED_UNAVAILABLE');
      expect(result.reason_code.startsWith('CTRL_AUTH_')).toBe(true);
    }
  });

  it('returns REJECTED_UID for unauthorized uid', () => {
    const result = authorizeControllerPeer(
      {hasPeerCred: true, uid: 2000, gid: 1000},
      {allowedUids: [1000], allowedGids: []}
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe('CTRL_AUTH_PEERCRED_REJECTED_UID');
      expect(result.reason_code.startsWith('CTRL_AUTH_')).toBe(true);
    }
  });

  it('returns REJECTED_GID for unauthorized gid', () => {
    const result = authorizeControllerPeer(
      {hasPeerCred: true, uid: 1000, gid: 2000},
      {allowedUids: [], allowedGids: [1000]}
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe('CTRL_AUTH_PEERCRED_REJECTED_GID');
      expect(result.reason_code.startsWith('CTRL_AUTH_')).toBe(true);
    }
  });

  it('returns SOCKET_MODE_INVALID for unexpected socket mode', () => {
    const result = validateSocketSecurityMetadata(
      {mode: 0o666, ownerUid: 0, ownerGid: 0},
      {expectedMode: 0o660, expectedOwnerUid: 0, expectedOwnerGid: 0}
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe('CTRL_AUTH_SOCKET_MODE_INVALID');
    }
  });

  it('returns SOCKET_OWNER_INVALID for unexpected socket owner', () => {
    const result = validateSocketSecurityMetadata(
      {mode: 0o660, ownerUid: 1000, ownerGid: 1000},
      {expectedMode: 0o660, expectedOwnerUid: 0, expectedOwnerGid: 0}
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe('CTRL_AUTH_SOCKET_OWNER_INVALID');
    }
  });

  it('authorizes valid peer and socket metadata', () => {
    const authzResult = authorizeControllerPeer(
      {hasPeerCred: true, uid: 1000, gid: 1000},
      {allowedUids: [1000], allowedGids: [1000]}
    );

    expect(authzResult).toEqual({ok: true});

    const socketResult = validateSocketSecurityMetadata(
      {mode: 0o660, ownerUid: 0, ownerGid: 0},
      {expectedMode: 0o660, expectedOwnerUid: 0, expectedOwnerGid: 0}
    );

    expect(socketResult).toEqual({ok: true});
  });

  it('authorizes peer when UID matches even if GID does not (OR semantics)', () => {
    const result = authorizeControllerPeer(
      {hasPeerCred: true, uid: 1000, gid: 9999},
      {allowedUids: [1000], allowedGids: [2000]}
    );

    expect(result).toEqual({ok: true});
  });

  it('authorizes peer when GID matches even if UID does not (OR semantics)', () => {
    const result = authorizeControllerPeer(
      {hasPeerCred: true, uid: 9999, gid: 2000},
      {allowedUids: [1000], allowedGids: [2000]}
    );

    expect(result).toEqual({ok: true});
  });

  it('allows peer when both allow-lists are empty', () => {
    const result = authorizeControllerPeer(
      {hasPeerCred: true, uid: 5000, gid: 5000},
      {allowedUids: [], allowedGids: []}
    );

    expect(result).toEqual({ok: true});
  });
});
