import React, {useMemo, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {useLocation, useNavigate} from 'react-router-dom';
import type {OpenApiAdminAuthProvider} from '@broker-interceptor/schemas';

import {BrokerAdminApiClient} from '../../api/client';
import {ApiClientError} from '../../api/errors';
import {ErrorNotice} from '../../components/ErrorNotice';
import {appConfig} from '../../config';
import {useAdminStore} from '../../store/adminStore';
import {createPkcePair} from './oauthPkce';
import {storePendingAdminOAuthState} from './oauthState';

const resolveNextPath = (rawSearch: string) => {
  const params = new URLSearchParams(rawSearch);
  const nextPath = params.get('next');

  if (!nextPath || !nextPath.startsWith('/') || nextPath.startsWith('//')) {
    return '/tenants';
  }

  return nextPath;
};

const isMissingSessionRoute = (error: unknown) =>
  error instanceof ApiClientError && error.status === 404 && error.reason === 'route_not_found';

const isAuthNotAvailableForPublicProviderDiscovery = (error: unknown) =>
  error instanceof ApiClientError &&
  (error.status === 401 || (error.status === 404 && error.reason === 'route_not_found'));

export const AdminLoginPage = () => {
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();

  const storedApiBaseUrl = useAdminStore(state => state.apiBaseUrl);
  const applySession = useAdminStore(state => state.applySession);

  const [apiBaseUrl, setApiBaseUrl] = useState(storedApiBaseUrl || appConfig.apiBaseUrl);
  const [authToken, setAuthToken] = useState('');

  const nextPath = useMemo(() => resolveNextPath(location.search), [location.search]);
  const normalizedBaseUrl = apiBaseUrl.trim() || appConfig.apiBaseUrl;
  const oauthApi = useMemo(
    () =>
      new BrokerAdminApiClient({
        baseUrl: normalizedBaseUrl,
        getToken: () => ''
      }),
    [normalizedBaseUrl]
  );

  const providersQuery = useQuery({
    queryKey: ['admin-auth-providers', normalizedBaseUrl],
    queryFn: async ({signal}) => {
      try {
        return (
          (await oauthApi.listAdminAuthProviders(signal)) ?? {
            providers: []
          }
        );
      } catch (error) {
        if (isAuthNotAvailableForPublicProviderDiscovery(error)) {
          return {
            providers: []
          };
        }

        throw error;
      }
    }
  });

  const oauthStartMutation = useMutation({
    mutationFn: async (provider: OpenApiAdminAuthProvider) => {
      const {codeVerifier, codeChallenge} = await createPkcePair();
      const redirectUri = `${window.location.origin}/login/callback`;
      const response = await oauthApi.startAdminLogin({
        provider,
        redirectUri,
        codeChallenge
      });

      if (!response) {
        throw new Error('OAuth login start did not return redirect data.');
      }

      storePendingAdminOAuthState(response.state, {
        provider,
        codeVerifier,
        redirectUri,
        nextPath,
        apiBaseUrl: normalizedBaseUrl,
        createdAt: new Date().toISOString()
      });

      return response;
    },
    onSuccess: response => {
      window.location.assign(response.authorization_url);
    }
  });

  const loginMutation = useMutation({
    mutationFn: async () => {
      const normalizedToken = authToken.trim();

      if (!normalizedToken) {
        throw new Error('Admin bearer token is required.');
      }

      const api = new BrokerAdminApiClient({
        baseUrl: normalizedBaseUrl,
        getToken: () => normalizedToken
      });

      try {
        const session = await api.fetchCurrentAdminPrincipal();
        if (!session?.authenticated || !session.principal) {
          throw new Error('Authenticated admin principal is required.');
        }

        return {
          apiBaseUrl: normalizedBaseUrl,
          authToken: normalizedToken,
          sessionId: session.session_id,
          sessionExpiresAt: session.expires_at,
          adminPrincipal: session.principal
        };
      } catch (error) {
        if (!isMissingSessionRoute(error)) {
          throw error;
        }

        try {
          await api.listTenants();
        } catch (tenantError) {
          // Legacy servers can return 403 for valid but limited-scope tokens.
          if (!(tenantError instanceof ApiClientError) || tenantError.status !== 403) {
            throw tenantError;
          }
        }
      }

      return {
        apiBaseUrl: normalizedBaseUrl,
        authToken: normalizedToken
      };
    },
    onSuccess: async session => {
      applySession(session);
      await queryClient.invalidateQueries();
      navigate(nextPath, {replace: true});
    }
  });

  return (
    <main className="login-shell">
      <section className="auth-card">
        <div className="auth-hero">
          <p className="eyebrow">Broker Control Plane</p>
          <h1>Admin Sign In</h1>
          <p>
            Sign in with your organization identity provider. Direct token sign-in is kept only as an advanced fallback.
          </p>
        </div>

        <form
          className="stack-form"
          onSubmit={event => {
            event.preventDefault();
          }}
        >
          <label className="field">
            <span>Broker Admin API Base URL</span>
            <input
              value={apiBaseUrl}
              onChange={event => setApiBaseUrl(event.currentTarget.value)}
              placeholder="http://localhost:8080"
              autoComplete="url"
            />
          </label>

          <div className="oauth-provider-grid">
            {(providersQuery.data?.providers ?? []).map(provider => (
              <button
                key={provider.provider}
                className="oauth-provider-button"
                type="button"
                onClick={() => oauthStartMutation.mutate(provider.provider)}
                disabled={!provider.enabled || oauthStartMutation.isPending}
              >
                <strong>{provider.provider === 'google' ? 'Continue with Google' : 'Continue with GitHub'}</strong>
                <span>{provider.enabled ? 'OIDC provider enabled' : 'Provider unavailable'}</span>
              </button>
            ))}
          </div>
          {(providersQuery.data?.providers?.length ?? 0) === 0 ? (
            <p className="helper-text">No OAuth providers are currently exposed by the API.</p>
          ) : null}

          <p className="helper-text">
            OAuth uses Authorization Code + PKCE and returns to `/login/callback` on this origin.
          </p>
        </form>

        <ErrorNotice error={providersQuery.error ?? oauthStartMutation.error} />

        <details className="advanced-auth">
          <summary>Advanced: direct bearer token sign-in</summary>

          <form
            className="stack-form"
            onSubmit={event => {
              event.preventDefault();
              loginMutation.mutate();
            }}
          >
            <label className="field">
              <span>Admin bearer token</span>
              <input
                value={authToken}
                onChange={event => setAuthToken(event.currentTarget.value)}
                placeholder="Paste token from secure source"
                type="password"
                autoComplete="current-password"
              />
            </label>

            <p className="helper-text">
              Session remains active on refresh in this browser context. Use Sign out when done.
            </p>

            <button type="submit" disabled={loginMutation.isPending}>
              Sign in to console
            </button>
          </form>
        </details>

        <ErrorNotice error={loginMutation.error} />
      </section>
    </main>
  );
};
