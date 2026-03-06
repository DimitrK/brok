import React, {useEffect, useMemo, useRef, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {useLocation, useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from '../../api/client';
import {ApiClientError} from '../../api/errors';
import {ErrorNotice} from '../../components/ErrorNotice';
import {useAdminStore} from '../../store/adminStore';
import {clearPendingAdminOAuthState, readPendingAdminOAuthState, type PendingAdminOAuthState} from './oauthState';

const getCallbackQuery = (search: string) => {
  const params = new URLSearchParams(search);
  return {
    state: params.get('state') ?? '',
    code: params.get('code') ?? '',
    providerError: params.get('error') ?? '',
    providerErrorDescription: params.get('error_description') ?? ''
  };
};

const isAccessRequestRequiredError = (error: unknown) =>
  error instanceof ApiClientError &&
  (error.reason === 'signup_closed' ||
    error.reason === 'admin_signup_closed' ||
    error.reason === 'admin_access_request_pending');

const getAccessRequestRequiredMessage = (error: unknown) => {
  if (!(error instanceof ApiClientError)) {
    return undefined;
  }

  if (error.reason === 'admin_access_request_pending') {
    return 'Your access request is already pending owner approval. You will be able to sign in once it is approved.';
  }

  if (error.reason === 'signup_closed' || error.reason === 'admin_signup_closed') {
    return 'This identity requires owner approval before sign-in can complete. Submit an access request for review.';
  }

  return undefined;
};

const getAccessRequestSessionToken = (error: unknown) =>
  error instanceof ApiClientError && isAccessRequestRequiredError(error) ? error.sessionToken : undefined;

const canSubmitAccessRequest = (error: unknown) =>
  error instanceof ApiClientError &&
  (error.reason === 'signup_closed' || error.reason === 'admin_signup_closed');

const getCallbackTroubleshootingHint = (error: unknown) => {
  if (!(error instanceof ApiClientError)) {
    return undefined;
  }

  if (error.reason === 'admin_auth_invalid') {
    return 'OIDC verification failed on broker-admin-api. Verify issuer, audience, JWKS URI, client credentials, and provider callback configuration.';
  }

  return undefined;
};

export const AdminOAuthCallbackPage = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const startedRef = useRef(false);

  const applySession = useAdminStore(state => state.applySession);
  const [pendingState, setPendingState] = useState<PendingAdminOAuthState | undefined>();
  const [accessRequestReason, setAccessRequestReason] = useState('');
  const [submittedAccessRequestId, setSubmittedAccessRequestId] = useState<string | undefined>();
  const [submittedAccessRequestToken, setSubmittedAccessRequestToken] = useState<string | undefined>();

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
      setPendingState(pendingState);

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
      setPendingState(undefined);
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
    onError: error => {
      const query = getCallbackQuery(location.search);
      if (query.state && !isAccessRequestRequiredError(error)) {
        clearPendingAdminOAuthState(query.state);
      }
      if (!isAccessRequestRequiredError(error)) {
        setPendingState(undefined);
      }
    }
  });
  const accessRequestSessionToken = useMemo(
    () => getAccessRequestSessionToken(callbackMutation.error),
    [callbackMutation.error]
  );
  const submitAccessRequestMutation = useMutation({
    mutationFn: async () => {
      if (!pendingState?.apiBaseUrl) {
        throw new Error('Missing OAuth callback context for access request submission.');
      }

      if (!accessRequestSessionToken) {
        throw new Error('OAuth session token is unavailable; cannot submit access request.');
      }

      const api = new BrokerAdminApiClient({
        baseUrl: pendingState.apiBaseUrl,
        getToken: () => accessRequestSessionToken
      });
      const payload = accessRequestReason.trim() ? {reason: accessRequestReason.trim()} : undefined;
      const created = await api.submitAdminAccessRequest(payload ? {payload} : {});
      if (!created) {
        throw new Error('Access request submission did not return a valid response.');
      }

      return {
        requestId: created.request_id,
        sessionToken: accessRequestSessionToken
      };
    },
    onSuccess: ({requestId, sessionToken}) => {
      setSubmittedAccessRequestId(requestId);
      setSubmittedAccessRequestToken(sessionToken);
    }
  });
  const submittedAccessRequestQuery = useQuery({
    queryKey: ['oauth-access-request', pendingState?.apiBaseUrl, submittedAccessRequestId],
    enabled: Boolean(pendingState?.apiBaseUrl && submittedAccessRequestId && submittedAccessRequestToken),
    queryFn: async ({signal}) => {
      const api = new BrokerAdminApiClient({
        baseUrl: pendingState?.apiBaseUrl ?? '',
        getToken: () => submittedAccessRequestToken ?? ''
      });

      return api.getAdminAccessRequestById({
        requestId: submittedAccessRequestId ?? '',
        signal
      });
    },
    refetchInterval: query => (query.state.data?.status === 'pending' ? 5000 : false)
  });
  const callbackTroubleshootingHint = getCallbackTroubleshootingHint(callbackMutation.error);

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
        {callbackTroubleshootingHint ? <p className="helper-text">{callbackTroubleshootingHint}</p> : null}

        {isAccessRequestRequiredError(callbackMutation.error) ? (
          <div className="auth-actions">
            <p className="helper-text">{getAccessRequestRequiredMessage(callbackMutation.error)}</p>
            {canSubmitAccessRequest(callbackMutation.error) ? (
              accessRequestSessionToken ? (
                <>
                  <label className="field">
                    <span>Request reason (optional)</span>
                    <textarea
                      value={accessRequestReason}
                      onChange={event => setAccessRequestReason(event.currentTarget.value)}
                      rows={3}
                      placeholder="Need access to manage tenant integrations."
                    />
                  </label>
                  <button
                    type="button"
                    disabled={submitAccessRequestMutation.isPending}
                    onClick={() => submitAccessRequestMutation.mutate()}
                  >
                    Submit access request
                  </button>
                  <ErrorNotice error={submitAccessRequestMutation.error} />
                  {submittedAccessRequestId ? (
                    <>
                      <p className="helper-text">
                        Access request `{submittedAccessRequestId}` submitted. Current status:{' '}
                        {submittedAccessRequestQuery.data?.status ?? 'pending'}.
                      </p>
                      <ErrorNotice error={submittedAccessRequestQuery.error} />
                    </>
                  ) : null}
                </>
              ) : (
                <p className="helper-text">
                  Unable to submit automatically because callback did not include an OAuth session token.
                </p>
              )
            ) : null}
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
