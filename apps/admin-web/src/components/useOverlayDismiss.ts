import {useCallback, useEffect, useRef} from 'react';

type UseOverlayDismissInput = {
  isOpen: boolean;
  onClose: () => void;
  scope: string;
  enableEscape?: boolean;
  enableHistoryBack?: boolean;
};

const OVERLAY_STATE_KEY = '__admin_overlay_scope__';

const readCurrentLocationKey = () => `${window.location.pathname}${window.location.search}${window.location.hash}`;

export const shouldRestoreOverlayHistoryEntry = (input: {
  enableHistoryBack: boolean;
  pushedState: boolean;
  closeRequestedByHistory: boolean;
  openedLocationKey?: string;
  currentLocationKey?: string;
}) =>
  input.enableHistoryBack &&
  input.pushedState &&
  !input.closeRequestedByHistory &&
  input.openedLocationKey === input.currentLocationKey;

export const useOverlayDismiss = ({
  isOpen,
  onClose,
  scope,
  enableEscape = true,
  enableHistoryBack = true
}: UseOverlayDismissInput) => {
  const onCloseRef = useRef(onClose);
  const isOpenRef = useRef(isOpen);
  const pushedStateRef = useRef(false);
  const closeRequestedByHistoryRef = useRef(false);
  const openedLocationKeyRef = useRef<string>();

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    isOpenRef.current = isOpen;
  }, [isOpen]);

  const requestClose = useCallback(() => {
    if (!isOpenRef.current) {
      onCloseRef.current();
      return;
    }

    if (enableHistoryBack && typeof window !== 'undefined' && pushedStateRef.current) {
      closeRequestedByHistoryRef.current = true;
      window.history.back();
      return;
    }

    onCloseRef.current();
  }, [enableHistoryBack]);

  useEffect(() => {
    if (!isOpen || typeof window === 'undefined') {
      return;
    }

    if (enableHistoryBack) {
      const historyState = window.history.state as unknown;
      const currentState =
        historyState && typeof historyState === 'object' ? (historyState as Record<string, unknown>) : {};
      window.history.pushState({...currentState, [OVERLAY_STATE_KEY]: scope}, '');
      pushedStateRef.current = true;
      openedLocationKeyRef.current = readCurrentLocationKey();
    }

    const handlePopState = () => {
      pushedStateRef.current = false;
      onCloseRef.current();
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (enableEscape && event.key === 'Escape') {
        event.preventDefault();
        requestClose();
      }
    };

    if (enableHistoryBack) {
      window.addEventListener('popstate', handlePopState);
    }
    if (enableEscape) {
      window.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      if (enableHistoryBack) {
        window.removeEventListener('popstate', handlePopState);
      }
      if (enableEscape) {
        window.removeEventListener('keydown', handleKeyDown);
      }

      if (
        shouldRestoreOverlayHistoryEntry({
          enableHistoryBack,
          pushedState: pushedStateRef.current,
          closeRequestedByHistory: closeRequestedByHistoryRef.current,
          openedLocationKey: openedLocationKeyRef.current,
          currentLocationKey: readCurrentLocationKey()
        })
      ) {
        pushedStateRef.current = false;
        window.history.back();
      }
      closeRequestedByHistoryRef.current = false;
      openedLocationKeyRef.current = undefined;
    };
  }, [enableEscape, enableHistoryBack, isOpen, requestClose, scope]);

  return {
    requestClose
  };
};
