import React, {useMemo, useState} from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {
  type OpenApiAdminAccessRequest,
  type OpenApiAdminAccessRequestStatus,
  type OpenApiAdminRole,
  type OpenApiAdminUser,
  type OpenApiAdminUserStatus
} from '@broker-interceptor/schemas';

import type {AdminAccessRequestFilter, AdminUserFilter} from '../../api/querySchemas';
import {BrokerAdminApiClient} from '../../api/client';
import {AppIcon} from '../../components/AppIcon';
import {ErrorNotice} from '../../components/ErrorNotice';
import {MobileEntityList} from '../../components/MobileEntityList';
import {Panel} from '../../components/Panel';
import {useOverlayDismiss} from '../../components/useOverlayDismiss';
import {AdminSignupPolicyControls} from '../auth/AdminSignupPolicyControls';
import {useAdminStore} from '../../store/adminStore';

const adminRoleOrder: OpenApiAdminRole[] = ['owner', 'admin', 'auditor', 'operator'];
const adminUserStatuses: OpenApiAdminUserStatus[] = ['active', 'pending', 'disabled'];
const adminAccessRequestStatuses: OpenApiAdminAccessRequestStatus[] = ['pending', 'approved', 'denied', 'canceled'];

type UserEditDraft = {
  identityId: string;
  status: OpenApiAdminUserStatus;
  roles: OpenApiAdminRole[];
  tenantIds: string[];
};

type AccessRequestDraft = {
  requestId: string;
  roles: OpenApiAdminRole[];
  tenantIds: string[];
  approveReason: string;
  denyReason: string;
};

type UserManagementPanelProps = {
  api: BrokerAdminApiClient;
};

const normalizeSearch = (value: string) => {
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : undefined;
};

const sortRoles = (roles: OpenApiAdminRole[]) =>
  [...roles].sort((left, right) => adminRoleOrder.indexOf(left) - adminRoleOrder.indexOf(right));

const sortTenantIds = (tenantIds: string[]) => [...tenantIds].sort((left, right) => left.localeCompare(right));

const summarizeRoles = (roles: OpenApiAdminRole[]) => sortRoles(roles).join(', ');

const summarizeTenantIds = (tenantIds: string[]) => {
  if (tenantIds.length === 0) {
    return 'all tenants';
  }

  return sortTenantIds(tenantIds).join(', ');
};

const summarizeTenantNames = (tenantIds: string[], tenantNameById: Map<string, string>) => {
  if (tenantIds.length === 0) {
    return 'all tenants';
  }

  return sortTenantIds(tenantIds)
    .map(tenantId => tenantNameById.get(tenantId) ?? tenantId)
    .join(', ');
};

const resolveSignInMethod = (issuer: string) => {
  try {
    const host = new URL(issuer).host.toLowerCase();
    const value = `${host} ${issuer}`.toLowerCase();

    if (value.includes('github')) {
      return 'github';
    }

    if (value.includes('google')) {
      return 'google';
    }

    if (value.includes('local') || value.includes('invalid')) {
      return 'local';
    }
  } catch {
    // Fall through to unknown label.
  }

  return 'oidc';
};

const intersectsTenantScope = (left: string[], right: Set<string>) => {
  if (right.size === 0) {
    return false;
  }

  if (left.length === 0) {
    return false;
  }

  return left.some(tenantId => right.has(tenantId));
};

const buildUserFilter = (input: {
  status: OpenApiAdminUserStatus | '';
  role: OpenApiAdminRole | '';
  tenantId: string;
  search: string;
}): AdminUserFilter => {
  const filter: AdminUserFilter = {
    limit: 50
  };

  const search = normalizeSearch(input.search);
  const tenantId = normalizeSearch(input.tenantId);

  if (input.status) {
    filter.status = input.status;
  }
  if (input.role) {
    filter.role = input.role;
  }
  if (tenantId) {
    filter.tenant_id = tenantId;
  }
  if (search) {
    filter.search = search;
  }

  return filter;
};

const buildAccessRequestFilter = (input: {
  status: OpenApiAdminAccessRequestStatus | '';
  role: OpenApiAdminRole | '';
  tenantId: string;
  search: string;
}): AdminAccessRequestFilter => {
  const filter: AdminAccessRequestFilter = {
    limit: 50
  };

  const search = normalizeSearch(input.search);
  const tenantId = normalizeSearch(input.tenantId);

  if (input.status) {
    filter.status = input.status;
  }
  if (input.role) {
    filter.role = input.role;
  }
  if (tenantId) {
    filter.tenant_id = tenantId;
  }
  if (search) {
    filter.search = search;
  }

  return filter;
};

export const UserManagementPanel = ({api}: UserManagementPanelProps) => {
  const queryClient = useQueryClient();
  const adminPrincipal = useAdminStore(state => state.adminPrincipal);

  const actorRoles = adminPrincipal?.roles ?? [];
  const actorTenantIds = adminPrincipal?.tenant_ids;
  const actorIdentity = adminPrincipal?.subject ?? '';

  const isOwner = actorRoles.includes('owner');
  const isAdmin = actorRoles.includes('admin');
  const canViewPanel = isOwner || isAdmin;

  const actorTenantIdSet = useMemo(() => new Set(actorTenantIds ?? []), [actorTenantIds]);
  const allowedAssignableRoles = useMemo(
    () => (isOwner ? adminRoleOrder : adminRoleOrder.filter(role => role !== 'owner')),
    [isOwner]
  );

  const [userFilterStatus, setUserFilterStatus] = useState<OpenApiAdminUserStatus | ''>('');
  const [userFilterRole, setUserFilterRole] = useState<OpenApiAdminRole | ''>('');
  const [userFilterTenantId, setUserFilterTenantId] = useState('');
  const [userFilterSearch, setUserFilterSearch] = useState('');

  const [requestFilterStatus, setRequestFilterStatus] = useState<OpenApiAdminAccessRequestStatus | ''>('pending');
  const [requestFilterRole, setRequestFilterRole] = useState<OpenApiAdminRole | ''>('');
  const [requestFilterTenantId, setRequestFilterTenantId] = useState('');
  const [requestFilterSearch, setRequestFilterSearch] = useState('');

  const [userDraft, setUserDraft] = useState<UserEditDraft | undefined>();
  const [requestDraft, setRequestDraft] = useState<AccessRequestDraft | undefined>();
  const [userDraftError, setUserDraftError] = useState<string | undefined>();
  const [requestDraftError, setRequestDraftError] = useState<string | undefined>();

  const userFilter = useMemo(
    () =>
      buildUserFilter({
        status: userFilterStatus,
        role: userFilterRole,
        tenantId: userFilterTenantId,
        search: userFilterSearch
      }),
    [userFilterRole, userFilterSearch, userFilterStatus, userFilterTenantId]
  );

  const requestFilter = useMemo(
    () =>
      buildAccessRequestFilter({
        status: requestFilterStatus,
        role: requestFilterRole,
        tenantId: requestFilterTenantId,
        search: requestFilterSearch
      }),
    [requestFilterRole, requestFilterSearch, requestFilterStatus, requestFilterTenantId]
  );

  const tenantsQuery = useQuery({
    queryKey: ['tenants'],
    enabled: canViewPanel,
    queryFn: ({signal}) => api.listTenants(signal)
  });

  const usersQuery = useQuery({
    queryKey: ['admin-users', userFilter],
    enabled: canViewPanel,
    queryFn: ({signal}) => api.listAdminUsers({filter: userFilter, signal})
  });

  const accessRequestsQuery = useQuery({
    queryKey: ['admin-access-requests', requestFilter],
    enabled: canViewPanel,
    queryFn: ({signal}) => api.listAdminAccessRequests({filter: requestFilter, signal})
  });

  const ownerCount = useMemo(
    () => (usersQuery.data?.users ?? []).filter(user => user.roles.includes('owner') && user.status !== 'disabled').length,
    [usersQuery.data]
  );

  const canManageUser = (user: OpenApiAdminUser) => {
    if (isOwner) {
      return true;
    }

    if (!isAdmin) {
      return false;
    }

    if (user.roles.includes('owner')) {
      return false;
    }

    return intersectsTenantScope(user.tenant_ids, actorTenantIdSet);
  };

  const canManageAccessRequest = (request: OpenApiAdminAccessRequest) => {
    if (isOwner) {
      return true;
    }

    if (!isAdmin) {
      return false;
    }

    if (request.requested_roles.includes('owner')) {
      return false;
    }

    return intersectsTenantScope(request.requested_tenant_ids, actorTenantIdSet);
  };

  const startEditUser = (user: OpenApiAdminUser) => {
    setUserDraftError(undefined);
    setUserDraft({
      identityId: user.identity_id,
      status: user.status,
      roles: sortRoles(user.roles),
      tenantIds: sortTenantIds(user.tenant_ids)
    });
  };

  const closeUserEditor = () => {
    setUserDraft(undefined);
    setUserDraftError(undefined);
  };

  const startAccessRequestReview = (request: OpenApiAdminAccessRequest) => {
    setRequestDraftError(undefined);
    setRequestDraft({
      requestId: request.request_id,
      roles: sortRoles(request.requested_roles),
      tenantIds: sortTenantIds(request.requested_tenant_ids),
      approveReason: '',
      denyReason: ''
    });
  };

  const closeAccessRequestReview = () => {
    setRequestDraft(undefined);
    setRequestDraftError(undefined);
  };

  const updateUserMutation = useMutation({
    mutationFn: async (draft: UserEditDraft) =>
      api.updateAdminUser({
        identityId: draft.identityId,
        payload: {
          status: draft.status,
          roles: draft.roles,
          tenant_ids: draft.tenantIds
        }
      }),
    onSuccess: async () => {
      closeUserEditor();
      await queryClient.invalidateQueries({queryKey: ['admin-users']});
      await queryClient.invalidateQueries({queryKey: ['admin-access-requests']});
      await queryClient.invalidateQueries({queryKey: ['admin-session']});
    }
  });

  const approveRequestMutation = useMutation({
    mutationFn: async (draft: AccessRequestDraft) =>
      api.approveAdminAccessRequest({
        requestId: draft.requestId,
        payload: {
          roles: draft.roles,
          tenant_ids: draft.tenantIds,
          ...(normalizeSearch(draft.approveReason) ? {reason: normalizeSearch(draft.approveReason)} : {})
        }
      }),
    onSuccess: async () => {
      closeAccessRequestReview();
      await queryClient.invalidateQueries({queryKey: ['admin-users']});
      await queryClient.invalidateQueries({queryKey: ['admin-access-requests']});
    }
  });

  const denyRequestMutation = useMutation({
    mutationFn: async (draft: AccessRequestDraft) =>
      api.denyAdminAccessRequest({
        requestId: draft.requestId,
        payload: {
          reason: draft.denyReason.trim()
        }
      }),
    onSuccess: async () => {
      closeAccessRequestReview();
      await queryClient.invalidateQueries({queryKey: ['admin-access-requests']});
    }
  });

  const activeUser = useMemo(
    () => (userDraft ? (usersQuery.data?.users ?? []).find(user => user.identity_id === userDraft.identityId) : undefined),
    [userDraft, usersQuery.data]
  );

  const activeAccessRequest = useMemo(
    () =>
      requestDraft
        ? (accessRequestsQuery.data?.requests ?? []).find(request => request.request_id === requestDraft.requestId)
        : undefined,
    [accessRequestsQuery.data, requestDraft]
  );

  const canSaveUserDraft = Boolean(userDraft && userDraft.roles.length > 0);
  const users = usersQuery.data?.users ?? [];
  const accessRequests = accessRequestsQuery.data?.requests ?? [];
  const tenantNameById = useMemo(
    () => new Map((tenantsQuery.data?.tenants ?? []).map(tenant => [tenant.tenant_id, tenant.name])),
    [tenantsQuery.data?.tenants]
  );
  const userEditorOverlay = useOverlayDismiss({
    isOpen: Boolean(userDraft && activeUser),
    onClose: closeUserEditor,
    scope: 'users-editor'
  });
  const requestReviewOverlay = useOverlayDismiss({
    isOpen: Boolean(requestDraft && activeAccessRequest),
    onClose: closeAccessRequestReview,
    scope: 'users-access-request-review'
  });

  if (!canViewPanel) {
    return (
      <Panel
        title="User Management"
        subtitle="Owner and admin roles can manage signup policy, identities, and access requests."
      >
        <p className="helper-text">This account does not have permission to view user management.</p>
      </Panel>
    );
  }

  return (
    <Panel
      title="User Management"
      subtitle="Manage signup mode, admin identities, tenant scopes, and pending access approvals."
    >
      <AdminSignupPolicyControls api={api} roles={actorRoles} />

      <section className="management-surface">
        <header className="management-surface-header">
          <h3>Admin users</h3>
          <p>Review existing admins and update status, roles, and tenant assignments.</p>
        </header>

        <form className="inline-form mobile-filter-form" onSubmit={event => event.preventDefault()}>
          <label className="field">
            <span>Status</span>
            <select
              value={userFilterStatus}
              onChange={event => setUserFilterStatus((event.currentTarget.value as OpenApiAdminUserStatus | '') || '')}
            >
              <option value="">all</option>
              {adminUserStatuses.map(status => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Role</span>
            <select value={userFilterRole} onChange={event => setUserFilterRole((event.currentTarget.value as OpenApiAdminRole | '') || '')}>
              <option value="">all</option>
              {adminRoleOrder.map(role => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Tenant ID</span>
            <input
              value={userFilterTenantId}
              onChange={event => setUserFilterTenantId(event.currentTarget.value)}
              placeholder="t_acme"
            />
          </label>

          <label className="field">
            <span>Search</span>
            <input
              value={userFilterSearch}
              onChange={event => setUserFilterSearch(event.currentTarget.value)}
              placeholder="email or subject"
            />
          </label>
        </form>

        <ErrorNotice error={usersQuery.error} />

        <MobileEntityList
          ariaLabel="Admin users list"
          items={users}
          emptyState="No admin users found."
          getItemKey={user => user.identity_id}
          getSummary={user => ({
            title: user.email,
            subtitle: user.identity_id,
            statusTone: user.status === 'active' ? 'positive' : 'neutral',
            meta: [{label: 'Sign-in', value: resolveSignInMethod(user.issuer)}]
          })}
          renderDetail={(user, controls) => {
            const canManage = canManageUser(user);
            const isSelf = user.subject === actorIdentity;
            return (
              <div className="stack-form">
                <label className="field">
                  <span>Email</span>
                  <input value={user.email} readOnly />
                </label>
                <label className="field">
                  <span>Identity ID</span>
                  <input value={user.identity_id} readOnly />
                </label>
                <label className="field">
                  <span>Status</span>
                  <input value={user.status} readOnly />
                </label>
                <label className="field">
                  <span>Sign-in</span>
                  <input value={resolveSignInMethod(user.issuer)} readOnly />
                </label>
                <label className="field wide">
                  <span>Roles</span>
                  <input value={summarizeRoles(user.roles)} readOnly />
                </label>
                <label className="field wide">
                  <span>Tenant scope</span>
                  <input
                    value={summarizeTenantNames(user.tenant_ids, tenantNameById)}
                    title={user.tenant_ids.length > 0 ? summarizeTenantIds(user.tenant_ids) : undefined}
                    readOnly
                  />
                </label>
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={!canManage}
                  onClick={() => {
                    startEditUser(user);
                    controls.close();
                  }}
                >
                  {isSelf ? 'Edit self' : 'Edit user'}
                </button>
              </div>
            );
          }}
        />

        <div className="table-shell desktop-table-shell">
          <table className="data-table">
            <thead>
              <tr>
                <th>Email</th>
                <th>Sign-in</th>
                <th>Status</th>
                <th>Roles</th>
                <th>Tenant scope</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(user => {
                const canManage = canManageUser(user);
                const isSelf = user.subject === actorIdentity;
                return (
                  <tr key={user.identity_id}>
                    <td>
                      <strong>{user.email}</strong>
                      <div className="muted small-text">{user.identity_id}</div>
                    </td>
                    <td>{resolveSignInMethod(user.issuer)}</td>
                    <td>{user.status}</td>
                    <td>{summarizeRoles(user.roles)}</td>
                    <td title={user.tenant_ids.length > 0 ? summarizeTenantIds(user.tenant_ids) : undefined}>
                      {summarizeTenantNames(user.tenant_ids, tenantNameById)}
                    </td>
                    <td>{user.updated_at}</td>
                    <td>
                      <button type="button" className="btn-secondary" onClick={() => startEditUser(user)} disabled={!canManage}>
                        {isSelf ? 'Edit self' : 'Edit user'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

      </section>

      <section className="management-surface">
        <header className="management-surface-header">
          <h3>Access request queue</h3>
          <p>Approve or deny pending signup requests with optional role and tenant overrides.</p>
        </header>

        <form className="inline-form mobile-filter-form" onSubmit={event => event.preventDefault()}>
          <label className="field">
            <span>Status</span>
            <select
              value={requestFilterStatus}
              onChange={event =>
                setRequestFilterStatus((event.currentTarget.value as OpenApiAdminAccessRequestStatus | '') || '')
              }
            >
              <option value="">all</option>
              {adminAccessRequestStatuses.map(status => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Role</span>
            <select
              value={requestFilterRole}
              onChange={event => setRequestFilterRole((event.currentTarget.value as OpenApiAdminRole | '') || '')}
            >
              <option value="">all</option>
              {adminRoleOrder.map(role => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Tenant ID</span>
            <input
              value={requestFilterTenantId}
              onChange={event => setRequestFilterTenantId(event.currentTarget.value)}
              placeholder="t_acme"
            />
          </label>

          <label className="field">
            <span>Search</span>
            <input
              value={requestFilterSearch}
              onChange={event => setRequestFilterSearch(event.currentTarget.value)}
              placeholder="email or subject"
            />
          </label>
        </form>

        <ErrorNotice error={accessRequestsQuery.error} />

        <MobileEntityList
          ariaLabel="Access request list"
          items={accessRequests}
          emptyState="No access requests found."
          getItemKey={request => request.request_id}
          getSummary={request => ({
            title: request.email,
            subtitle: request.request_id,
            statusTone: request.status === 'approved' ? 'positive' : 'neutral',
            meta: [{label: 'Status', value: request.status}]
          })}
          renderDetail={(request, controls) => (
            <div className="stack-form">
              <label className="field">
                <span>Requester</span>
                <input value={request.email} readOnly />
              </label>
              <label className="field">
                <span>Request ID</span>
                <input value={request.request_id} readOnly />
              </label>
              <label className="field">
                <span>Status</span>
                <input value={request.status} readOnly />
              </label>
              <label className="field wide">
                <span>Requested roles</span>
                <input value={summarizeRoles(request.requested_roles)} readOnly />
              </label>
              <label className="field wide">
                <span>Requested tenant scope</span>
                <input
                  value={summarizeTenantNames(request.requested_tenant_ids, tenantNameById)}
                  title={request.requested_tenant_ids.length > 0 ? summarizeTenantIds(request.requested_tenant_ids) : undefined}
                  readOnly
                />
              </label>
              <label className="field">
                <span>Created</span>
                <input value={request.created_at} readOnly />
              </label>
              <button
                type="button"
                className="btn-secondary"
                disabled={request.status !== 'pending' || !canManageAccessRequest(request)}
                onClick={() => {
                  startAccessRequestReview(request);
                  controls.close();
                }}
              >
                Review
              </button>
            </div>
          )}
        />

        <div className="table-shell desktop-table-shell">
          <table className="data-table">
            <thead>
              <tr>
                <th>Requester</th>
                <th>Status</th>
                <th>Requested roles</th>
                <th>Requested tenant scope</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {accessRequests.map(request => (
                <tr key={request.request_id}>
                  <td>
                    <strong>{request.email}</strong>
                    <div className="muted small-text">{request.request_id}</div>
                  </td>
                  <td>{request.status}</td>
                  <td>{summarizeRoles(request.requested_roles)}</td>
                  <td title={request.requested_tenant_ids.length > 0 ? summarizeTenantIds(request.requested_tenant_ids) : undefined}>
                    {summarizeTenantNames(request.requested_tenant_ids, tenantNameById)}
                  </td>
                  <td>{request.created_at}</td>
                  <td>
                    <button
                      type="button"
                      className="btn-secondary"
                      disabled={request.status !== 'pending' || !canManageAccessRequest(request)}
                      onClick={() => startAccessRequestReview(request)}
                    >
                      Review
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </section>

      {userDraft && activeUser ? (
        <section className="entity-screen">
          <header className="entity-screen-header">
            <button
              type="button"
              className="icon-back-button"
              aria-label="Back to admin users list"
              onClick={userEditorOverlay.requestClose}
            >
              <AppIcon name="arrow-left" />
            </button>
            <strong className="entity-screen-title">Edit admin user</strong>
            <span className="entity-screen-spacer" aria-hidden />
          </header>

          <div className="entity-screen-content">
            <section className="management-surface">
              <div className="management-surface-header">
                <h3>{activeUser.email}</h3>
                <p>Update status, roles, and tenant assignments.</p>
              </div>

              <div className="editor-grid">
                <label className="field">
                  <span>Status</span>
                  <select
                    value={userDraft.status}
                    onChange={event => {
                      const nextStatus = event.currentTarget.value as OpenApiAdminUserStatus;
                      const isLastOwner = activeUser.roles.includes('owner') && ownerCount <= 1;
                      if (isLastOwner && nextStatus !== 'active') {
                        setUserDraftError('At least one active owner must remain.');
                        return;
                      }

                      setUserDraftError(undefined);
                      setUserDraft(current => (current ? {...current, status: nextStatus} : current));
                    }}
                  >
                    {adminUserStatuses.map(status => (
                      <option key={status} value={status}>
                        {status}
                      </option>
                    ))}
                  </select>
                </label>

                <div className="field wide">
                  <span>Roles</span>
                  <div className="checkbox-grid">
                    {adminRoleOrder.map(role => {
                      const selected = userDraft.roles.includes(role);
                      const isLastOwnerRole = role === 'owner' && activeUser.roles.includes('owner') && ownerCount <= 1;
                      const disabled =
                        !allowedAssignableRoles.includes(role) ||
                        (selected && userDraft.roles.length === 1) ||
                        isLastOwnerRole;

                      return (
                        <label key={role} className="chip-checkbox chip-checkbox-role">
                          <input
                            type="checkbox"
                            checked={selected}
                            disabled={disabled}
                            onChange={() => {
                              setUserDraftError(undefined);
                              setUserDraft(current => {
                                if (!current) {
                                  return current;
                                }

                                const hasRole = current.roles.includes(role);
                                const nextRoles = hasRole
                                  ? current.roles.filter(candidate => candidate !== role)
                                  : [...current.roles, role];

                                return {
                                  ...current,
                                  roles: sortRoles(nextRoles)
                                };
                              });
                            }}
                          />
                          <span className="chip-label" title={role}>
                            {role}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <div className="field wide">
                  <span>Tenant assignments</span>
                  <div className="checkbox-grid">
                    {(tenantsQuery.data?.tenants ?? []).map(tenant => {
                      const checked = userDraft.tenantIds.includes(tenant.tenant_id);
                      const disabled = !isOwner && !actorTenantIdSet.has(tenant.tenant_id);
                      const checkboxId = `edit-user-tenant-${tenant.tenant_id}`;
                      return (
                        <div key={tenant.tenant_id} className="chip-checkbox chip-checkbox-tenant">
                          <input
                            id={checkboxId}
                            aria-label={`Assign tenant ${tenant.name}`}
                            type="checkbox"
                            checked={checked}
                            disabled={disabled}
                            onChange={() => {
                              setUserDraftError(undefined);
                              setUserDraft(current => {
                                if (!current) {
                                  return current;
                                }

                                const hasTenant = current.tenantIds.includes(tenant.tenant_id);
                                const nextTenantIds = hasTenant
                                  ? current.tenantIds.filter(candidate => candidate !== tenant.tenant_id)
                                  : [...current.tenantIds, tenant.tenant_id];

                                return {
                                  ...current,
                                  tenantIds: sortTenantIds(nextTenantIds)
                                };
                              });
                            }}
                          />
                          <label className="chip-text" htmlFor={checkboxId}>
                            <span className="chip-label" title={tenant.name}>
                              {tenant.name}
                            </span>
                            <small title={tenant.tenant_id}>{tenant.tenant_id}</small>
                          </label>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              <p className="helper-text">
                Updates are explicit replacements for status, roles, and tenant scope and are validated server-side.
              </p>

              {userDraftError ? <p className="error-notice">{userDraftError}</p> : null}
              <ErrorNotice error={updateUserMutation.error} />

              <div className="row-actions">
                <button
                  type="button"
                  disabled={!canSaveUserDraft || updateUserMutation.isPending}
                  onClick={() => {
                    if (!userDraft) {
                      return;
                    }

                    if (!isOwner) {
                      if (userDraft.roles.includes('owner')) {
                        setUserDraftError('Only owner can grant owner role.');
                        return;
                      }

                      if (userDraft.tenantIds.length === 0) {
                        setUserDraftError('Admin-assigned users must have explicit tenant scope.');
                        return;
                      }

                      if (userDraft.tenantIds.some(tenantId => !actorTenantIdSet.has(tenantId))) {
                        setUserDraftError('Admin assignments must stay within your tenant scope.');
                        return;
                      }
                    }

                    setUserDraftError(undefined);
                    updateUserMutation.mutate(userDraft);
                  }}
                >
                  Save user changes
                </button>
                <button type="button" className="btn-secondary" onClick={userEditorOverlay.requestClose}>
                  Cancel
                </button>
              </div>
            </section>
          </div>
        </section>
      ) : null}

      {requestDraft && activeAccessRequest ? (
        <section className="entity-screen">
          <header className="entity-screen-header">
            <button
              type="button"
              className="icon-back-button"
              aria-label="Back to access request queue"
              onClick={requestReviewOverlay.requestClose}
            >
              <AppIcon name="arrow-left" />
            </button>
            <strong className="entity-screen-title">Review access request</strong>
            <span className="entity-screen-spacer" aria-hidden />
          </header>

          <div className="entity-screen-content">
            <section className="management-surface">
              <div className="management-surface-header">
                <h3>{activeAccessRequest.email}</h3>
                <p>Approve or deny this request with optional role and tenant overrides.</p>
              </div>

              <div className="editor-grid">
                <div className="field wide">
                  <span>Approved roles</span>
                  <div className="checkbox-grid">
                    {adminRoleOrder.map(role => {
                      const selected = requestDraft.roles.includes(role);
                      const disabled =
                        !allowedAssignableRoles.includes(role) || (selected && requestDraft.roles.length === 1);

                      return (
                        <label key={role} className="chip-checkbox chip-checkbox-role">
                          <input
                            type="checkbox"
                            checked={selected}
                            disabled={disabled}
                            onChange={() => {
                              setRequestDraftError(undefined);
                              setRequestDraft(current => {
                                if (!current) {
                                  return current;
                                }

                                const hasRole = current.roles.includes(role);
                                const nextRoles = hasRole
                                  ? current.roles.filter(candidate => candidate !== role)
                                  : [...current.roles, role];

                                return {
                                  ...current,
                                  roles: sortRoles(nextRoles)
                                };
                              });
                            }}
                          />
                          <span className="chip-label" title={role}>
                            {role}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <div className="field wide">
                  <span>Approved tenant scope</span>
                  <div className="checkbox-grid">
                    {(tenantsQuery.data?.tenants ?? []).map(tenant => {
                      const checked = requestDraft.tenantIds.includes(tenant.tenant_id);
                      const disabled = !isOwner && !actorTenantIdSet.has(tenant.tenant_id);
                      const checkboxId = `approve-request-tenant-${tenant.tenant_id}`;
                      return (
                        <div key={tenant.tenant_id} className="chip-checkbox chip-checkbox-tenant">
                          <input
                            id={checkboxId}
                            aria-label={`Approve tenant scope ${tenant.name}`}
                            type="checkbox"
                            checked={checked}
                            disabled={disabled}
                            onChange={() => {
                              setRequestDraftError(undefined);
                              setRequestDraft(current => {
                                if (!current) {
                                  return current;
                                }

                                const hasTenant = current.tenantIds.includes(tenant.tenant_id);
                                const nextTenantIds = hasTenant
                                  ? current.tenantIds.filter(candidate => candidate !== tenant.tenant_id)
                                  : [...current.tenantIds, tenant.tenant_id];

                                return {
                                  ...current,
                                  tenantIds: sortTenantIds(nextTenantIds)
                                };
                              });
                            }}
                          />
                          <label className="chip-text" htmlFor={checkboxId}>
                            <span className="chip-label" title={tenant.name}>
                              {tenant.name}
                            </span>
                            <small title={tenant.tenant_id}>{tenant.tenant_id}</small>
                          </label>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <label className="field wide">
                  <span>Approval reason (optional)</span>
                  <textarea
                    value={requestDraft.approveReason}
                    onChange={event => {
                      const nextApproveReason = event.currentTarget.value;
                      setRequestDraft(current =>
                        current
                          ? {
                              ...current,
                              approveReason: nextApproveReason
                            }
                          : current
                      );
                    }}
                    placeholder="Optional note attached to approval audit trail"
                    rows={3}
                  />
                </label>

                <label className="field wide">
                  <span>Deny reason (required for deny)</span>
                  <textarea
                    value={requestDraft.denyReason}
                    onChange={event => {
                      const nextDenyReason = event.currentTarget.value;
                      setRequestDraft(current =>
                        current
                          ? {
                              ...current,
                              denyReason: nextDenyReason
                            }
                          : current
                      );
                    }}
                    placeholder="Explain why this request is denied"
                    rows={3}
                  />
                </label>
              </div>

              <p className="helper-text">
                Approve and deny operations are idempotent server-side and audited with actor + target metadata.
              </p>

              {requestDraftError ? <p className="error-notice">{requestDraftError}</p> : null}
              <ErrorNotice error={approveRequestMutation.error ?? denyRequestMutation.error} />

              <div className="row-actions">
                <button
                  type="button"
                  disabled={requestDraft.roles.length === 0 || approveRequestMutation.isPending}
                  onClick={() => {
                    if (!requestDraft) {
                      return;
                    }

                    if (!isOwner) {
                      if (requestDraft.roles.includes('owner')) {
                        setRequestDraftError('Only owner can approve owner role assignments.');
                        return;
                      }

                      if (requestDraft.tenantIds.length === 0) {
                        setRequestDraftError('Approved scope must be explicit for tenant-scoped admins.');
                        return;
                      }

                      if (requestDraft.tenantIds.some(tenantId => !actorTenantIdSet.has(tenantId))) {
                        setRequestDraftError('Approved tenant scope must stay within your own scope.');
                        return;
                      }
                    }

                    setRequestDraftError(undefined);
                    approveRequestMutation.mutate(requestDraft);
                  }}
                >
                  Approve request
                </button>
                <button
                  type="button"
                  className="btn-danger"
                  disabled={!normalizeSearch(requestDraft.denyReason) || denyRequestMutation.isPending}
                  onClick={() => {
                    if (!requestDraft) {
                      return;
                    }

                    if (!normalizeSearch(requestDraft.denyReason)) {
                      setRequestDraftError('Deny reason is required.');
                      return;
                    }

                    setRequestDraftError(undefined);
                    denyRequestMutation.mutate(requestDraft);
                  }}
                >
                  Deny request
                </button>
                <button type="button" className="btn-secondary" onClick={requestReviewOverlay.requestClose}>
                  Cancel
                </button>
              </div>
            </section>
          </div>
        </section>
      ) : null}
    </Panel>
  );
};
