import {create} from 'zustand';
import {createJSONStorage, persist, type StateStorage} from 'zustand/middleware';
import type {OpenApiAdminSessionPrincipal} from '@broker-interceptor/schemas';

type PersistedAdminSession = {
  apiBaseUrl: string;
  authToken: string;
  selectedTenantId?: string;
  sessionId?: string;
  sessionExpiresAt?: string;
  adminPrincipal?: OpenApiAdminSessionPrincipal;
};

type AdminStore = PersistedAdminSession & {
  setApiBaseUrl: (value: string) => void;
  setAuthToken: (value: string) => void;
  setSelectedTenantId: (value: string | undefined) => void;
  applySession: (value: {
    apiBaseUrl: string;
    authToken: string;
    sessionId?: string;
    sessionExpiresAt?: string;
    adminPrincipal?: OpenApiAdminSessionPrincipal;
  }) => void;
  setAdminSessionMetadata: (value: {
    sessionId?: string;
    sessionExpiresAt?: string;
    adminPrincipal?: OpenApiAdminSessionPrincipal;
  }) => void;
  clearSession: () => void;
};

const noopStorage: StateStorage = {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined
};

const sessionStorageProvider = () => (typeof window === 'undefined' ? noopStorage : window.sessionStorage);

const initialState: PersistedAdminSession = {
  apiBaseUrl: '',
  authToken: '',
  selectedTenantId: undefined,
  sessionId: undefined,
  sessionExpiresAt: undefined,
  adminPrincipal: undefined
};

export const useAdminStore = create<AdminStore>()(
  persist(
    set => ({
      ...initialState,
      setApiBaseUrl: value => set({apiBaseUrl: value}),
      setAuthToken: value => set({authToken: value}),
      setSelectedTenantId: value => set({selectedTenantId: value}),
      applySession: value =>
        set({
          apiBaseUrl: value.apiBaseUrl,
          authToken: value.authToken,
          selectedTenantId: undefined,
          sessionId: value.sessionId,
          sessionExpiresAt: value.sessionExpiresAt,
          adminPrincipal: value.adminPrincipal
        }),
      setAdminSessionMetadata: value =>
        set({
          sessionId: value.sessionId,
          sessionExpiresAt: value.sessionExpiresAt,
          adminPrincipal: value.adminPrincipal
        }),
      clearSession: () => set({...initialState})
    }),
    {
      name: 'broker-admin-web-session',
      storage: createJSONStorage(sessionStorageProvider),
      partialize: state => ({
        apiBaseUrl: state.apiBaseUrl,
        authToken: state.authToken,
        selectedTenantId: state.selectedTenantId,
        sessionId: state.sessionId,
        sessionExpiresAt: state.sessionExpiresAt,
        adminPrincipal: state.adminPrincipal
      })
    }
  )
);
