import {describe, expect, it} from 'vitest';

import {shouldRestoreOverlayHistoryEntry} from './useOverlayDismiss';

describe('shouldRestoreOverlayHistoryEntry', () => {
  it('restores the pushed history entry when closing on the same route', () => {
    expect(
      shouldRestoreOverlayHistoryEntry({
        enableHistoryBack: true,
        pushedState: true,
        closeRequestedByHistory: false,
        openedLocationKey: '/audit',
        currentLocationKey: '/audit'
      })
    ).toBe(true);
  });

  it('does not rewind browser history after navigating to a different route', () => {
    expect(
      shouldRestoreOverlayHistoryEntry({
        enableHistoryBack: true,
        pushedState: true,
        closeRequestedByHistory: false,
        openedLocationKey: '/audit',
        currentLocationKey: '/templates?draft=audit'
      })
    ).toBe(false);
  });

  it('does not restore history when dismissal already came from browser back', () => {
    expect(
      shouldRestoreOverlayHistoryEntry({
        enableHistoryBack: true,
        pushedState: true,
        closeRequestedByHistory: true,
        openedLocationKey: '/audit',
        currentLocationKey: '/audit'
      })
    ).toBe(false);
  });
});
