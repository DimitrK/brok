import {afterEach, describe, expect, it, vi} from 'vitest';

import {BrokerAdminApiClient} from './client';

const baseUrl = 'http://localhost:8080';

const jsonResponse = (status: number, payload: unknown) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json'
    }
  });

const toRequestUrl = (input: RequestInfo | URL | undefined) => {
  if (input instanceof Request) {
    return input.url;
  }

  if (input instanceof URL) {
    return input.toString();
  }

  if (typeof input === 'string') {
    return input;
  }

  return '';
};

describe('BrokerAdminApiClient', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns parsed tenant list for valid payloads', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(200, {
        tenants: [{tenant_id: 'tenant_1', name: 'prod'}]
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'test-token'
    });

    const result = await api.listTenants();
    expect(result?.tenants).toHaveLength(1);
    expect(result?.tenants[0]?.tenant_id).toBe('tenant_1');
  });

  it('fails closed when response contract is invalid', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(200, {
        tenants: [{tenant_id: 'tenant_1'}]
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'test-token'
    });

    await expect(api.listTenants()).rejects.toMatchObject({
      name: 'ApiClientError',
      reason: 'contract_violation'
    });
  });

  it('maps API error payloads into structured client errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(401, {
        error: 'unauthorized',
        message: 'invalid token',
        correlation_id: 'cid-1'
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'bad-token'
    });

    await expect(api.listTenants()).rejects.toMatchObject({
      name: 'ApiClientError',
      status: 401,
      reason: 'unauthorized',
      correlationId: 'cid-1'
    });
  });

  it('starts OAuth login with PKCE payload and no bearer token', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(200, {
        authorization_url: 'https://idp.example.com/oauth/authorize?state=test-state',
        state: 'test-state-value',
        nonce: 'test-nonce-value'
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => ''
    });

    const result = await api.startAdminLogin({
      provider: 'google',
      redirectUri: 'http://localhost:4173/login/callback',
      codeChallenge: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abc'
    });

    expect(result?.state).toBe('test-state-value');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [, options] = fetchSpy.mock.calls[0] ?? [];
    expect(options?.headers instanceof Headers ? options.headers.get('authorization') : 'present').toBeNull();
  });

  it('updates signup mode for owner controls', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(200, {
        new_user_mode: 'blocked',
        require_verified_email: true,
        allowed_email_domains: ['example.com'],
        updated_at: '2026-02-14T20:30:00.000Z',
        updated_by: 'admin-owner'
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'owner-token'
    });

    const result = await api.setSignupMode({mode: 'blocked'});
    expect(result?.new_user_mode).toBe('blocked');
    expect(result?.updated_by).toBe('admin-owner');
  });

  it('lists admin users with query filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(200, {
        users: [
          {
            identity_id: 'adm_1',
            issuer: 'https://issuer.example.com',
            subject: 'sub_1',
            email: 'owner@example.com',
            status: 'active',
            roles: ['owner'],
            tenant_ids: ['t_1'],
            created_at: '2026-02-15T11:00:00.000Z',
            updated_at: '2026-02-15T11:00:00.000Z'
          }
        ]
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'owner-token'
    });

    const result = await api.listAdminUsers({
      filter: {
        status: 'active',
        role: 'owner',
        tenant_id: 't_1',
        search: 'owner',
        limit: 25
      }
    });

    expect(result?.users).toHaveLength(1);
    const requestUrl = toRequestUrl(fetchSpy.mock.calls[0]?.[0]);
    expect(requestUrl).toContain('/v1/admin/users');
    expect(requestUrl).toContain('status=active');
    expect(requestUrl).toContain('role=owner');
    expect(requestUrl).toContain('tenant_id=t_1');
    expect(requestUrl).toContain('limit=25');
  });

  it('updates admin user role and tenant assignments', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(200, {
        identity_id: 'adm_2',
        issuer: 'https://issuer.example.com',
        subject: 'sub_2',
        email: 'admin@example.com',
        status: 'active',
        roles: ['admin', 'auditor'],
        tenant_ids: ['t_1', 't_2'],
        created_at: '2026-02-15T11:00:00.000Z',
        updated_at: '2026-02-15T11:30:00.000Z'
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'owner-token'
    });

    const result = await api.updateAdminUser({
      identityId: 'adm_2',
      payload: {
        status: 'active',
        roles: ['admin', 'auditor'],
        tenant_ids: ['t_1', 't_2']
      }
    });

    expect(result?.identity_id).toBe('adm_2');
    const [, options] = fetchSpy.mock.calls[0] ?? [];
    expect(options?.method).toBe('PATCH');
  });

  it('issues enrollment token for an existing workload', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(200, {
        enrollment_token: 'tok_new_1',
        expires_at: '2026-02-20T12:00:00.000Z'
      })
    );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'owner-token'
    });

    const response = await api.issueWorkloadEnrollmentToken({
      workloadId: 'w_1',
      payload: {
        rotation_mode: 'always'
      }
    });

    expect(response?.enrollment_token).toBe('tok_new_1');
    expect(toRequestUrl(fetchSpy.mock.calls[0]?.[0])).toContain('/v1/workloads/w_1/enrollment-token');
    const [, options] = fetchSpy.mock.calls[0] ?? [];
    expect(options?.method).toBe('POST');
  });

  it('approves and denies admin access requests', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        jsonResponse(200, {
          request_id: 'req_1',
          issuer: 'https://issuer.example.com',
          subject: 'sub_3',
          email: 'new-admin@example.com',
          requested_roles: ['admin'],
          requested_tenant_ids: ['t_1'],
          status: 'approved',
          reason: 'Approved for tenant operations',
          decided_by: 'owner@example.com',
          decided_at: '2026-02-15T11:35:00.000Z',
          created_at: '2026-02-15T11:20:00.000Z',
          updated_at: '2026-02-15T11:35:00.000Z'
        })
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          request_id: 'req_2',
          issuer: 'https://issuer.example.com',
          subject: 'sub_4',
          email: 'blocked-admin@example.com',
          requested_roles: ['admin'],
          requested_tenant_ids: ['t_2'],
          status: 'denied',
          reason: 'Tenant scope mismatch',
          decided_by: 'owner@example.com',
          decided_at: '2026-02-15T11:40:00.000Z',
          created_at: '2026-02-15T11:25:00.000Z',
          updated_at: '2026-02-15T11:40:00.000Z'
        })
      );

    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'owner-token'
    });

    const approved = await api.approveAdminAccessRequest({
      requestId: 'req_1',
      payload: {
        roles: ['admin'],
        tenant_ids: ['t_1'],
        reason: 'Approved for tenant operations'
      }
    });

    const denied = await api.denyAdminAccessRequest({
      requestId: 'req_2',
      payload: {
        reason: 'Tenant scope mismatch'
      }
    });

    expect(approved?.status).toBe('approved');
    expect(denied?.status).toBe('denied');
    expect(toRequestUrl(fetchSpy.mock.calls[0]?.[0])).toContain('/v1/admin/access-requests/req_1/approve');
    expect(toRequestUrl(fetchSpy.mock.calls[1]?.[0])).toContain('/v1/admin/access-requests/req_2/deny');
  });

  it('fails closed when configured with an invalid base URL', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const api = new BrokerAdminApiClient({
      baseUrl: 'not-a-valid-url',
      getToken: () => 'owner-token'
    });

    await expect(api.listTenants()).rejects.toMatchObject({
      name: 'ApiClientError',
      status: 400,
      reason: 'invalid_base_url'
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('invalidates admin session on sign out endpoint', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(null, {
        status: 204
      })
    );
    const api = new BrokerAdminApiClient({
      baseUrl,
      getToken: () => 'owner-token'
    });

    await api.logoutAdminSession();

    expect(toRequestUrl(fetchSpy.mock.calls[0]?.[0])).toContain('/v1/admin/auth/logout');
    const [, options] = fetchSpy.mock.calls[0] ?? [];
    expect(options?.method).toBe('POST');
    expect(options?.headers instanceof Headers ? options.headers.get('authorization') : null).toBe(
      'Bearer owner-token'
    );
  });
});
