import React, {useEffect, useMemo, useState} from 'react';
import {useQuery, useQueryClient} from '@tanstack/react-query';
import {Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate} from 'react-router-dom';

import {BrokerAdminApiClient} from './api/client';
import {ApiClientError} from './api/errors';
import {AppIcon, type AppIconName} from './components/AppIcon';
import {ErrorNotice} from './components/ErrorNotice';
import {appConfig} from './config';
import {AdminLoginPage} from './features/auth/AdminLoginPage';
import {AdminOAuthCallbackPage} from './features/auth/AdminOAuthCallbackPage';
import {ApprovalsPanel} from './features/approvals/ApprovalsPanel';
import {AuditPanel} from './features/audit/AuditPanel';
import {IntegrationsPanel} from './features/integrations/IntegrationsPanel';
import {ManifestPanel} from './features/manifest/ManifestKeysPanel';
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
  icon: AppIconName;
};

type TenantOption = {
  tenantId: string;
  name: string;
};

const sectionRoutes: SectionRoute[] = [
  {
    path: 'tenants',
    label: 'Tenants',
    description: 'Create tenants and control active admin scope.',
    icon: 'tenants'
  },
  {
    path: 'users',
    label: 'User Management',
    description: 'Manage admin users, roles, and access requests.',
    icon: 'users'
  },
  {
    path: 'workloads',
    label: 'Workloads',
    description: 'Provision workloads and complete certificate enrollment.',
    icon: 'workloads'
  },
  {
    path: 'templates',
    label: 'Templates',
    description: 'Publish canonical outbound access contracts.',
    icon: 'templates'
  },
  {
    path: 'integrations',
    label: 'Integrations',
    description: 'Store provider secrets and bind templates safely.',
    icon: 'integrations'
  },
  {
    path: 'policies',
    label: 'Policies',
    description: 'Define enforceable allow, deny, approval, and rate rules.',
    icon: 'policies'
  },
  {
    path: 'approvals',
    label: 'Approvals',
    description: 'Review pending high-risk execution requests.',
    icon: 'approvals'
  },
  {
    path: 'audit',
    label: 'Audit',
    description: 'Query immutable decision and execution events.',
    icon: 'audit'
  },
  {
    path: 'manifest',
    label: 'Manifest',
    description: 'Inspect signing material used for broker manifests.',
    icon: 'manifest'
  }
];

const findActiveSection = (pathname: string) =>
  sectionRoutes.find(section => pathname === `/${section.path}` || pathname.startsWith(`/${section.path}/`)) ??
  sectionRoutes[0];

const isIgnorableLogoutError = (error: unknown) =>
  error instanceof ApiClientError && error.status === 401;

const reportNonBlockingError = (error: unknown) => {
  const globalReportError = (globalThis as {reportError?: (input: unknown) => void}).reportError;
  if (typeof globalReportError === 'function') {
    globalReportError(error);
    return;
  }

  console.error(error);
};

const RequireAuth = ({children}: {children: React.ReactNode}) => {
  const authToken = useAdminStore(state => state.authToken);
  const location = useLocation();

  if (!authToken) {
    const nextPath = `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to={`/login?next=${encodeURIComponent(nextPath)}`} replace />;
  }

  return <>{children}</>;
};

const RequireTenantSelection = ({children}: {children: React.ReactNode}) => {
  const selectedTenantId = useAdminStore(state => state.selectedTenantId);
  const location = useLocation();

  if (!selectedTenantId) {
    const nextPath = `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to={`/tenants?next=${encodeURIComponent(nextPath)}`} replace />;
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
  onSignOut: () => Promise<void>;
  tenantOptions: TenantOption[];
  onTenantChange: (tenantId: string | undefined) => void;
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
  tenantOptions,
  onTenantChange,
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
  const renderTenantSelector = (className?: string) => (
    <label className={className ? `tenant-selector ${className}` : 'tenant-selector'}>
      <span>Active tenant</span>
      <div className="tenant-selector-control">
        <select
          value={selectedTenantId ?? ''}
          title={selectedTenantId ? `Tenant ID: ${selectedTenantId}` : undefined}
          onChange={event => onTenantChange(event.currentTarget.value || undefined)}
        >
          <option value="">{selectedTenantId ? 'No tenant selected' : 'Select tenant'}</option>
          {tenantOptions.map(tenant => (
            <option key={tenant.tenantId} value={tenant.tenantId}>
              {tenant.name}
            </option>
          ))}
        </select>
        <span className="tenant-selector-caret" aria-hidden>
          ▾
        </span>
      </div>
    </label>
  );

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
            <AppIcon name="close" />
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
                <strong>
                  <AppIcon name={section.icon} className="side-nav-icon" />
                  {section.label}
                </strong>
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
            void onSignOut();
          }}
        >
          Sign out
        </button>
      </aside>

      <div className="console-main">
        <div className="workspace-toprow">
          <button
            type="button"
            className="btn-secondary mobile-menu-toggle"
            aria-label="Open navigation menu"
            onClick={() => setMobileNavOpen(true)}
          >
            <AppIcon name="menu" />
            Menu
          </button>
          {renderTenantSelector('tenant-selector-topbar')}
        </div>

        <header className="workspace-header">
          <div>
            <p className="eyebrow">Control Plane</p>
            <h2>{activeSection.label}</h2>
            <p>{activeSection.description}</p>
          </div>
          <div className="workspace-meta">
            <p className={`status-pill compact${healthError ? ' danger' : ''}`}>
              Health status: {healthStatus ?? 'unknown'}
            </p>
            {renderTenantSelector('tenant-selector-desktop')}
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

  const tenantsQuery = useQuery({
    queryKey: ['tenants'],
    enabled: Boolean(authToken),
    queryFn: async ({signal}) => {
      try {
        return await api.listTenants(signal);
      } catch (error) {
        if (error instanceof ApiClientError && [401, 403, 404].includes(error.status)) {
          return {
            tenants: []
          };
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

  const signOut = async () => {
    if (authToken) {
      try {
        await api.logoutAdminSession();
      } catch (error) {
        if (!isIgnorableLogoutError(error)) {
          reportNonBlockingError(error);
        }
      }
    }

    clearSession();
    queryClient.clear();
    navigate('/login', {replace: true});
  };

  const adminIdentityLabel =
    adminPrincipal?.name?.trim() || adminPrincipal?.email || adminPrincipal?.subject || 'Unknown admin';
  const adminIdentityRoles = adminPrincipal?.roles?.join(', ') || 'roles unavailable';
  const tenantOptions: TenantOption[] = (tenantsQuery.data?.tenants ?? []).map(tenant => ({
    tenantId: tenant.tenant_id,
    name: tenant.name
  }));

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
              tenantOptions={tenantOptions}
              onTenantChange={tenantId => setSelectedTenantId(tenantId)}
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
        <Route
          path="workloads"
          element={
            <RequireTenantSelection>
              <WorkloadsPanel api={api} />
            </RequireTenantSelection>
          }
        />
        <Route
          path="integrations"
          element={
            <RequireTenantSelection>
              <IntegrationsPanel api={api} />
            </RequireTenantSelection>
          }
        />
        <Route path="templates" element={<TemplatesPanel api={api} />} />
        <Route path="policies" element={<PoliciesPanel api={api} />} />
        <Route path="approvals" element={<ApprovalsPanel api={api} />} />
        <Route path="audit" element={<AuditPanel api={api} />} />
        <Route path="manifest" element={<ManifestPanel api={api} />} />
      </Route>

      <Route path="*" element={<Navigate to={authToken ? '/tenants' : '/login'} replace />} />
    </Routes>
  );
};
