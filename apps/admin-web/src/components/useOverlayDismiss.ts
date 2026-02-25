import {useCallback, useEffect, useRef} from 'react';

type UseOverlayDismissInput = {
  isOpen: boolean;
  onClose: () => void;
  scope: string;
  enableEscape?: boolean;
  enableHistoryBack?: boolean;
};

const OVERLAY_STATE_KEY = '__admin_overlay_scope__';

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

      if (enableHistoryBack && pushedStateRef.current && !closeRequestedByHistoryRef.current) {
        pushedStateRef.current = false;
        window.history.back();
      }
      closeRequestedByHistoryRef.current = false;
    };
  }, [enableEscape, enableHistoryBack, isOpen, requestClose, scope]);

  return {
    requestClose
  };
};
