import {describe, expect, it} from 'vitest';

import {useAdminStore} from './adminStore';

describe('admin store', () => {
  it('applies authenticated session values', () => {
    useAdminStore.getState().applySession({
      apiBaseUrl: 'http://localhost:8080',
      authToken: 'token-xyz',
      sessionId: 'sess_1',
      sessionExpiresAt: '2026-02-15T10:00:00.000Z',
      adminPrincipal: {
        subject: 'admin-user',
        issuer: 'https://idp.example.com',
        email: 'admin@example.com',
        roles: ['owner'],
        tenant_ids: ['*']
      }
    });

    expect(useAdminStore.getState().apiBaseUrl).toBe('http://localhost:8080');
    expect(useAdminStore.getState().authToken).toBe('token-xyz');
    expect(useAdminStore.getState().sessionId).toBe('sess_1');
    expect(useAdminStore.getState().sessionExpiresAt).toBe('2026-02-15T10:00:00.000Z');
    expect(useAdminStore.getState().adminPrincipal?.email).toBe('admin@example.com');
    expect(useAdminStore.getState().selectedTenantId).toBeUndefined();
  });

  it('keeps auth token in memory state', () => {
    useAdminStore.setState({authToken: ''});

    useAdminStore.getState().setAuthToken('token-123');

    expect(useAdminStore.getState().authToken).toBe('token-123');
  });

  it('updates active tenant selection', () => {
    useAdminStore.setState({selectedTenantId: undefined});

    useAdminStore.getState().setSelectedTenantId('tenant_42');

    expect(useAdminStore.getState().selectedTenantId).toBe('tenant_42');
  });

  it('updates admin principal metadata without changing token fields', () => {
    useAdminStore.setState({
      authToken: 'session-token',
      apiBaseUrl: 'http://localhost:8080',
      selectedTenantId: 'tenant_42'
    });

    useAdminStore.getState().setAdminSessionMetadata({
      sessionId: 'sess_2',
      sessionExpiresAt: '2026-02-16T10:00:00.000Z',
      adminPrincipal: {
        subject: 'auditor-user',
        issuer: 'https://idp.example.com',
        email: 'auditor@example.com',
        roles: ['auditor'],
        tenant_ids: []
      }
    });

    expect(useAdminStore.getState().authToken).toBe('session-token');
    expect(useAdminStore.getState().selectedTenantId).toBe('tenant_42');
    expect(useAdminStore.getState().adminPrincipal?.roles).toEqual(['auditor']);
  });

  it('clears session state', () => {
    useAdminStore.setState({
      apiBaseUrl: 'http://localhost:8080',
      authToken: 'token-xyz',
      selectedTenantId: 'tenant_42',
      sessionId: 'sess_3',
      sessionExpiresAt: '2026-02-16T10:00:00.000Z',
      adminPrincipal: {
        subject: 'admin-user',
        issuer: 'https://idp.example.com',
        email: 'admin@example.com',
        roles: ['owner'],
        tenant_ids: ['*']
      }
    });

    useAdminStore.getState().clearSession();

    expect(useAdminStore.getState().authToken).toBe('');
    expect(useAdminStore.getState().apiBaseUrl).toBe('');
    expect(useAdminStore.getState().selectedTenantId).toBeUndefined();
    expect(useAdminStore.getState().sessionId).toBeUndefined();
    expect(useAdminStore.getState().sessionExpiresAt).toBeUndefined();
    expect(useAdminStore.getState().adminPrincipal).toBeUndefined();
  });
});
