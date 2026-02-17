import React, {useEffect, useMemo, useState} from 'react';
import {useQuery, useQueryClient} from '@tanstack/react-query';
import {Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from './api/client';
import {ApiClientError} from './api/errors';
import {ErrorNotice} from './components/ErrorNotice';
import {appConfig} from './config';
import {AdminLoginPage} from './features/auth/AdminLoginPage';
import {AdminOAuthCallbackPage} from './features/auth/AdminOAuthCallbackPage';
import {ApprovalsPanel} from './features/approvals/ApprovalsPanel';
import {AuditPanel} from './features/audit/AuditPanel';
import {IntegrationsPanel} from './features/integrations/IntegrationsPanel';
import {ManifestKeysPanel} from './features/manifest/ManifestKeysPanel';
import {PoliciesPanel} from './features/policies/PoliciesPanel';
import {TemplatesPanel} from './features/templates/TemplatesPanel';
import {TenantsPanel} from './features/tenants/TenantsPanel';
import {UserManagementPanel} from './features/users/UserManagementPanel';
import {WorkloadsPanel} from './features/workloads/WorkloadsPanel';
import {useAdminStore} from './store/adminStore';

type SectionRoute = {
  path: string;
  label: string;
  description: string;
};

const sectionRoutes: SectionRoute[] = [
  {
    path: 'tenants',
    label: 'Tenants',
    description: 'Create tenants and control active admin scope.'
  },
  {
    path: 'users',
    label: 'User Management',
    description: 'Manage admin users, roles, and access requests.'
  },
  {
    path: 'workloads',
    label: 'Workloads',
    description: 'Provision workloads and complete certificate enrollment.'
  },
  {
    path: 'integrations',
    label: 'Integrations',
    description: 'Store provider secrets and bind templates safely.'
  },
  {
    path: 'templates',
    label: 'Templates',
    description: 'Publish canonical outbound access contracts.'
  },
  {
    path: 'policies',
    label: 'Policies',
    description: 'Define enforceable allow, deny, approval, and rate rules.'
  },
  {
    path: 'approvals',
    label: 'Approvals',
    description: 'Review pending high-risk execution requests.'
  },
  {
    path: 'audit',
    label: 'Audit',
    description: 'Query immutable decision and execution events.'
  },
  {
    path: 'manifest',
    label: 'Manifest Keys',
    description: 'Inspect signing material used for broker manifests.'
  }
];

const findActiveSection = (pathname: string) =>
  sectionRoutes.find(section => pathname === `/${section.path}` || pathname.startsWith(`/${section.path}/`)) ??
  sectionRoutes[0];

const RequireAuth = ({children}: {children: React.ReactNode}) => {
  const authToken = useAdminStore(state => state.authToken);
  const location = useLocation();

  if (!authToken) {
    const nextPath = `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to={`/login?next=${encodeURIComponent(nextPath)}`} replace />;
  }

  return <>{children}</>;
};

type AdminConsoleLayoutProps = {
  draftApiBaseUrl: string;
  draftAuthToken: string;
  connectionDirty: boolean;
  onDraftApiBaseUrlChange: (value: string) => void;
  onDraftAuthTokenChange: (value: string) => void;
  onApplyConnection: () => void;
  onSignOut: () => void;
  selectedTenantId?: string;
  healthStatus?: string;
  healthError: unknown;
  adminIdentityLabel: string;
  adminIdentityRoles: string;
  pendingAccessRequestsCount: number;
};

const AdminConsoleLayout = ({
  draftApiBaseUrl,
  draftAuthToken,
  connectionDirty,
  onDraftApiBaseUrlChange,
  onDraftAuthTokenChange,
  onApplyConnection,
  onSignOut,
  selectedTenantId,
  healthStatus,
  healthError,
  adminIdentityLabel,
  adminIdentityRoles,
  pendingAccessRequestsCount
}: AdminConsoleLayoutProps) => {
  const location = useLocation();
  const activeSection = findActiveSection(location.pathname);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div className="console-layout">
      {mobileNavOpen ? (
        <button
          type="button"
          className="sidebar-scrim"
          aria-label="Close navigation menu"
          onClick={() => setMobileNavOpen(false)}
        />
      ) : null}

      <aside className={`console-sidebar${mobileNavOpen ? ' open' : ''}`}>
        <div className="sidebar-mobile-header">
          <p className="eyebrow">Navigation</p>
          <button type="button" className="btn-secondary sidebar-close" onClick={() => setMobileNavOpen(false)}>
            Close
          </button>
        </div>

        <div className="brand-block">
          <p className="eyebrow">Broker</p>
          <h1>Admin Console</h1>
          <p>Operate tenant boundaries, secret material, policy controls, and approvals from one place.</p>
        </div>

        <div className="identity-card">
          <p className="eyebrow">Signed in as</p>
          <strong>{adminIdentityLabel}</strong>
          <p>{adminIdentityRoles}</p>
        </div>

        <nav className="side-nav" aria-label="Admin sections">
          {sectionRoutes.map(section => (
            <NavLink
              key={section.path}
              to={`/${section.path}`}
              className={({isActive}) => `side-nav-link${isActive ? ' active' : ''}`}
              onClick={() => setMobileNavOpen(false)}
            >
              <div className="side-nav-title">
                <strong>{section.label}</strong>
                {section.path === 'users' && pendingAccessRequestsCount > 0 ? (
                  <span className="side-nav-badge" aria-label={`${pendingAccessRequestsCount} pending access requests`}>
                    {pendingAccessRequestsCount}
                  </span>
                ) : null}
              </div>
              <span>{section.description}</span>
            </NavLink>
          ))}
        </nav>

        <details className="sidebar-server-settings">
          <summary>Server settings</summary>
          <form
            className="stack-form sidebar-server-settings-form"
            onSubmit={event => {
              event.preventDefault();
              onApplyConnection();
            }}
          >
            <label className="field">
              <span>Broker Admin API Base URL</span>
              <input
                value={draftApiBaseUrl}
                onChange={event => onDraftApiBaseUrlChange(event.currentTarget.value)}
                placeholder="http://localhost:8080"
              />
            </label>

            <label className="field">
              <span>Admin session token</span>
              <input
                value={draftAuthToken}
                onChange={event => onDraftAuthTokenChange(event.currentTarget.value)}
                placeholder="Update token from secure source"
                type="password"
                autoComplete="current-password"
              />
            </label>

            <button type="submit" disabled={!connectionDirty}>
              Apply connection
            </button>
          </form>
        </details>

        <button
          className="btn-secondary"
          type="button"
          onClick={() => {
            setMobileNavOpen(false);
            onSignOut();
          }}
        >
          Sign out
        </button>
      </aside>

      <div className="console-main">
        <button
          type="button"
          className="btn-secondary mobile-menu-toggle"
          aria-label="Open navigation menu"
          onClick={() => setMobileNavOpen(true)}
        >
          Menu
        </button>

        <header className="workspace-header">
          <div>
            <p className="eyebrow">Control Plane</p>
            <h2>{activeSection.label}</h2>
            <p>{activeSection.description}</p>
          </div>
          <div className="workspace-meta">
            <div className={`tenant-chip${selectedTenantId ? '' : ' muted'}`}>
              {selectedTenantId ? `Active tenant: ${selectedTenantId}` : 'No tenant selected'}
            </div>
            <p className={`status-pill compact${healthError ? ' danger' : ''}`}>
              Health status: {healthStatus ?? 'unknown'}
            </p>
          </div>
        </header>

        <ErrorNotice error={healthError} />

        <main className="main-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export const App = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const apiBaseUrl = useAdminStore(state => state.apiBaseUrl);
  const authToken = useAdminStore(state => state.authToken);
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);
  const adminPrincipal = useAdminStore(state => state.adminPrincipal);

  const setApiBaseUrl = useAdminStore(state => state.setApiBaseUrl);
  const setAuthToken = useAdminStore(state => state.setAuthToken);
  const setSelectedTenantId = useAdminStore(state => state.setSelectedTenantId);
  const setAdminSessionMetadata = useAdminStore(state => state.setAdminSessionMetadata);
  const clearSession = useAdminStore(state => state.clearSession);

  const [draftApiBaseUrl, setDraftApiBaseUrl] = useState(appConfig.apiBaseUrl);
  const [draftAuthToken, setDraftAuthToken] = useState('');

  useEffect(() => {
    if (!apiBaseUrl) {
      setApiBaseUrl(appConfig.apiBaseUrl);
    }
  }, [apiBaseUrl, setApiBaseUrl]);

  useEffect(() => {
    setDraftApiBaseUrl(apiBaseUrl || appConfig.apiBaseUrl);
  }, [apiBaseUrl]);

  useEffect(() => {
    setDraftAuthToken(authToken);
  }, [authToken]);

  const normalizedDraftBaseUrl = draftApiBaseUrl.trim() || appConfig.apiBaseUrl;
  const normalizedStoredBaseUrl = apiBaseUrl || appConfig.apiBaseUrl;
  const normalizedDraftAuthToken = draftAuthToken.trim();

  const connectionDirty =
    normalizedDraftBaseUrl !== normalizedStoredBaseUrl || normalizedDraftAuthToken !== authToken;

  const api = useMemo(
    () =>
      new BrokerAdminApiClient({
        baseUrl: apiBaseUrl || appConfig.apiBaseUrl,
        getToken: () => useAdminStore.getState().authToken
      }),
    [apiBaseUrl]
  );

  const healthQuery = useQuery({
    queryKey: ['health', apiBaseUrl || appConfig.apiBaseUrl],
    queryFn: ({signal}) => api.getHealth(signal),
    enabled: Boolean(apiBaseUrl || appConfig.apiBaseUrl)
  });

  const adminSessionQuery = useQuery({
    queryKey: ['admin-session', apiBaseUrl || appConfig.apiBaseUrl, authToken],
    enabled: Boolean(authToken),
    queryFn: async ({signal}) => {
      try {
        return await api.fetchCurrentAdminPrincipal(signal);
      } catch (error) {
        if (error instanceof ApiClientError && error.status === 404 && error.reason === 'route_not_found') {
          return undefined;
        }

        throw error;
      }
    }
  });

  const pendingAccessRequestsCountQuery = useQuery({
    queryKey: ['admin-access-requests-pending-count', apiBaseUrl || appConfig.apiBaseUrl, authToken],
    enabled: Boolean(authToken),
    queryFn: async ({signal}) => {
      try {
        const response = await api.listAdminAccessRequests({
          filter: {
            status: 'pending',
            limit: 100
          },
          signal
        });
        return response?.requests.length ?? 0;
      } catch (error) {
        if (error instanceof ApiClientError && [401, 403, 404].includes(error.status)) {
          return 0;
        }

        throw error;
      }
    }
  });

  useEffect(() => {
    if (!adminSessionQuery.data) {
      return;
    }

    setAdminSessionMetadata({
      sessionId: adminSessionQuery.data.session_id,
      sessionExpiresAt: adminSessionQuery.data.expires_at,
      adminPrincipal: adminSessionQuery.data.principal
    });
  }, [adminSessionQuery.data, setAdminSessionMetadata]);

  useEffect(() => {
    if (!(adminSessionQuery.error instanceof ApiClientError) || adminSessionQuery.error.status !== 401) {
      return;
    }

    clearSession();
    queryClient.clear();
    navigate('/login', {replace: true});
  }, [adminSessionQuery.error, clearSession, queryClient, navigate]);

  const applyConnection = () => {
    if (!normalizedDraftAuthToken) {
      clearSession();
      queryClient.clear();
      navigate('/login', {replace: true});
      return;
    }

    setApiBaseUrl(normalizedDraftBaseUrl);
    setAuthToken(normalizedDraftAuthToken);
    setSelectedTenantId(undefined);
    setAdminSessionMetadata({
      sessionId: undefined,
      sessionExpiresAt: undefined,
      adminPrincipal: undefined
    });
    void queryClient.invalidateQueries();
  };

  const signOut = () => {
    clearSession();
    queryClient.clear();
    navigate('/login', {replace: true});
  };

  const adminIdentityLabel =
    adminPrincipal?.name?.trim() || adminPrincipal?.email || adminPrincipal?.subject || 'Unknown admin';
  const adminIdentityRoles = adminPrincipal?.roles?.join(', ') || 'roles unavailable';

  return (
    <Routes>
      <Route path="/login" element={authToken ? <Navigate to="/tenants" replace /> : <AdminLoginPage />} />
      <Route path="/login/callback" element={<AdminOAuthCallbackPage />} />

      <Route
        path="/"
        element={
          <RequireAuth>
            <AdminConsoleLayout
              draftApiBaseUrl={draftApiBaseUrl}
              draftAuthToken={draftAuthToken}
              connectionDirty={connectionDirty}
              onDraftApiBaseUrlChange={setDraftApiBaseUrl}
              onDraftAuthTokenChange={setDraftAuthToken}
              onApplyConnection={applyConnection}
              onSignOut={signOut}
              selectedTenantId={selectedTenantId}
              healthStatus={healthQuery.data?.status}
              healthError={healthQuery.error}
              adminIdentityLabel={adminIdentityLabel}
              adminIdentityRoles={adminIdentityRoles}
              pendingAccessRequestsCount={pendingAccessRequestsCountQuery.data ?? 0}
            />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/tenants" replace />} />
        <Route path="tenants" element={<TenantsPanel api={api} />} />
        <Route path="users" element={<UserManagementPanel api={api} />} />
        <Route path="workloads" element={<WorkloadsPanel api={api} />} />
        <Route path="integrations" element={<IntegrationsPanel api={api} />} />
        <Route path="templates" element={<TemplatesPanel api={api} />} />
        <Route path="policies" element={<PoliciesPanel api={api} />} />
        <Route path="approvals" element={<ApprovalsPanel api={api} />} />
        <Route path="audit" element={<AuditPanel api={api} />} />
        <Route path="manifest" element={<ManifestKeysPanel api={api} />} />
      </Route>

      <Route path="*" element={<Navigate to={authToken ? '/tenants' : '/login'} replace />} />
    </Routes>
  );
};
