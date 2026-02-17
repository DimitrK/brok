import type {OpenApiAdminAuthProvider} from '@broker-interceptor/schemas';

const OAUTH_STATE_KEY_PREFIX = 'broker-admin-web:oauth-state:';
const OAUTH_STATE_MAX_AGE_MS = 15 * 60 * 1000;

export type PendingAdminOAuthState = {
  provider: OpenApiAdminAuthProvider;
  codeVerifier: string;
  redirectUri: string;
  nextPath: string;
  apiBaseUrl: string;
  createdAt: string;
};

const getStorage = () => {
  if (typeof window === 'undefined') {
    return undefined;
  }

  return window.sessionStorage;
};

const toStateKey = (state: string) => `${OAUTH_STATE_KEY_PREFIX}${state}`;

export const prunePendingAdminOAuthStates = (now = Date.now()) => {
  const storage = getStorage();
  if (!storage) {
    return;
  }

  for (let index = storage.length - 1; index >= 0; index -= 1) {
    const key = storage.key(index);
    if (!key || !key.startsWith(OAUTH_STATE_KEY_PREFIX)) {
      continue;
    }

    const rawValue = storage.getItem(key);
    if (!rawValue) {
      storage.removeItem(key);
      continue;
    }

    try {
      const parsed = JSON.parse(rawValue) as PendingAdminOAuthState;
      const createdAt = new Date(parsed.createdAt).getTime();
      if (!Number.isFinite(createdAt) || now - createdAt > OAUTH_STATE_MAX_AGE_MS) {
        storage.removeItem(key);
      }
    } catch {
      storage.removeItem(key);
    }
  }
};

export const storePendingAdminOAuthState = (state: string, value: PendingAdminOAuthState) => {
  const storage = getStorage();
  if (!storage) {
    return;
  }

  prunePendingAdminOAuthStates();
  storage.setItem(toStateKey(state), JSON.stringify(value));
};

export const readPendingAdminOAuthState = (state: string): PendingAdminOAuthState | undefined => {
  const storage = getStorage();
  if (!storage) {
    return undefined;
  }

  const rawValue = storage.getItem(toStateKey(state));
  if (!rawValue) {
    return undefined;
  }

  try {
    return JSON.parse(rawValue) as PendingAdminOAuthState;
  } catch {
    storage.removeItem(toStateKey(state));
    return undefined;
  }
};

export const clearPendingAdminOAuthState = (state: string) => {
  const storage = getStorage();
  if (!storage) {
    return;
  }

  storage.removeItem(toStateKey(state));
};
