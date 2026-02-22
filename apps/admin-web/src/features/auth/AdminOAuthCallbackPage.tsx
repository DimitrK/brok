import React, {useEffect, useRef} from 'react';
import {useMutation, useQueryClient} from '@tanstack/react-query';
import {useLocation, useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from '../../api/client';
import {ApiClientError} from '../../api/errors';
import {ErrorNotice} from '../../components/ErrorNotice';
import {useAdminStore} from '../../store/adminStore';
import {clearPendingAdminOAuthState, readPendingAdminOAuthState} from './oauthState';

const getCallbackQuery = (search: string) => {
  const params = new URLSearchParams(search);
  return {
    state: params.get('state') ?? '',
    code: params.get('code') ?? '',
    providerError: params.get('error') ?? '',
    providerErrorDescription: params.get('error_description') ?? ''
  };
};

const isSignupBlockedError = (error: unknown) =>
  error instanceof ApiClientError &&
  (error.reason === 'signup_closed' ||
    error.reason === 'admin_signup_closed' ||
    error.reason === 'admin_access_request_pending');

const getSignupBlockedMessage = (error: unknown) => {
  if (!(error instanceof ApiClientError)) {
    return undefined;
  }

  if (error.reason === 'admin_access_request_pending') {
    return 'Your access request is already pending owner approval. You will be able to sign in once it is approved.';
  }

  if (error.reason === 'signup_closed' || error.reason === 'admin_signup_closed') {
    return 'New admin sign-ins are currently blocked. Ask an owner to approve access from the User Management page.';
  }

  return undefined;
};

export const AdminOAuthCallbackPage = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const startedRef = useRef(false);

  const applySession = useAdminStore(state => state.applySession);

  const callbackMutation = useMutation({
    mutationFn: async () => {
      const query = getCallbackQuery(location.search);
      if (query.providerError) {
        throw new Error(
          query.providerErrorDescription
            ? `OAuth provider error: ${query.providerErrorDescription}`
            : `OAuth provider error: ${query.providerError}`
        );
      }

      if (!query.code || !query.state) {
        throw new Error('Missing required OAuth callback parameters.');
      }

      const pendingState = readPendingAdminOAuthState(query.state);
      if (!pendingState) {
        throw new Error('OAuth callback state is missing or expired. Start sign-in again.');
      }

      const api = new BrokerAdminApiClient({
        baseUrl: pendingState.apiBaseUrl,
        getToken: () => ''
      });

      const callbackResponse = await api.handleAdminLoginCallback({
        provider: pendingState.provider,
        code: query.code,
        state: query.state,
        codeVerifier: pendingState.codeVerifier,
        redirectUri: pendingState.redirectUri
      });
      if (!callbackResponse) {
        throw new Error('OAuth callback did not return a valid session payload.');
      }

      return {
        callbackResponse,
        queryState: query.state,
        pendingState
      };
    },
    onSuccess: async ({callbackResponse, queryState, pendingState}) => {
      clearPendingAdminOAuthState(queryState);
      applySession({
        apiBaseUrl: pendingState.apiBaseUrl,
        authToken: callbackResponse.session_id,
        sessionId: callbackResponse.session_id,
        sessionExpiresAt: callbackResponse.expires_at,
        adminPrincipal: callbackResponse.principal
      });
      await queryClient.invalidateQueries();
      navigate(pendingState.nextPath || '/tenants', {replace: true});
    },
    onError: () => {
      const query = getCallbackQuery(location.search);
      if (query.state) {
        clearPendingAdminOAuthState(query.state);
      }
    }
  });

  useEffect(() => {
    if (startedRef.current) {
      return;
    }

    startedRef.current = true;
    callbackMutation.mutate();
  }, [callbackMutation]);

  return (
    <main className="login-shell">
      <section className="auth-card">
        <div className="auth-hero">
          <p className="eyebrow">Broker Control Plane</p>
          <h1>Completing Sign In</h1>
          <p>Finalizing your OAuth session and verifying admin access policy.</p>
        </div>

        {callbackMutation.isPending ? <p className="helper-text">Processing callback response...</p> : null}

        <ErrorNotice error={callbackMutation.error} />

        {isSignupBlockedError(callbackMutation.error) ? (
          <div className="auth-actions">
            <p className="helper-text">{getSignupBlockedMessage(callbackMutation.error)}</p>
          </div>
        ) : null}

        <div className="auth-actions">
          <button
            type="button"
            className="btn-secondary"
            onClick={() => navigate('/login', {replace: true})}
          >
            Back to sign in
          </button>
        </div>
      </section>
    </main>
  );
};
