import {
  OpenApiAdminAccessRequestApproveRequestSchema,
  OpenApiAdminAccessRequestDenyRequestSchema,
  OpenApiAdminAccessRequestListResponseSchema,
  OpenApiAdminAccessRequestSchema,
  OpenApiAdminAuthProviderListResponseSchema,
  OpenApiAdminOAuthCallbackRequestSchema,
  OpenApiAdminOAuthCallbackResponseSchema,
  OpenApiAdminOAuthStartRequestSchema,
  OpenApiAdminOAuthStartResponseSchema,
  OpenApiAdminSessionResponseSchema,
  OpenApiAdminSignupPolicySchema,
  OpenApiAdminSignupPolicyUpdateRequestSchema,
  OpenApiAdminUserListResponseSchema,
  OpenApiAdminUserSchema,
  OpenApiAdminUserUpdateRequestSchema,
  OpenApiApprovalDecisionRequestSchema,
  OpenApiApprovalListResponseSchema,
  OpenApiApprovalResponseSchema,
  OpenApiAuditEventListResponseSchema,
  OpenApiErrorSchema,
  OpenApiIntegrationCreateResponseSchema,
  OpenApiIntegrationListResponseSchema,
  OpenApiIntegrationSchema,
  OpenApiIntegrationUpdateRequestSchema,
  OpenApiIntegrationWriteSchema,
  OpenApiManifestKeysSchema,
  OpenApiPolicyCreateResponseSchema,
  OpenApiPolicyListResponseSchema,
  OpenApiPolicyRuleSchema,
  OpenApiTemplateCreateResponseSchema,
  OpenApiTemplateListResponseSchema,
  OpenApiTemplateSchema,
  OpenApiTenantCreateRequestSchema,
  OpenApiTenantCreateResponseSchema,
  OpenApiTenantListResponseSchema,
  OpenApiWorkloadCreateRequestSchema,
  OpenApiWorkloadCreateResponseSchema,
  OpenApiWorkloadEnrollRequestSchema,
  OpenApiWorkloadEnrollResponseSchema,
  OpenApiWorkloadEnrollmentTokenIssueRequestSchema,
  OpenApiWorkloadEnrollmentTokenIssueResponseSchema,
  OpenApiWorkloadListResponseSchema,
  OpenApiWorkloadSchema,
  OpenApiWorkloadUpdateRequestSchema,
  type OpenApiAdminAccessRequestApproveRequest,
  type OpenApiAdminAccessRequestDenyRequest,
  type OpenApiAdminAuthProvider,
  type OpenApiAdminUserUpdateRequest,
  type OpenApiApprovalDecisionRequest
} from '@broker-interceptor/schemas';
import {z, type ZodType} from 'zod';

import {
  adminAccessRequestFilterSchema,
  adminUserFilterSchema,
  type AdminAccessRequestFilter,
  type AdminUserFilter,
  type ApprovalStatusFilter,
  type AuditFilter
} from './querySchemas';
import {ApiClientError} from './errors';

type QueryValue = string | number | undefined;
const healthResponseSchema = z.object({status: z.string()}).strict();

const makeCorrelationId = () => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  return `cid-${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
};

const appendQuery = (url: URL, query?: Record<string, QueryValue>) => {
  if (!query) {
    return;
  }

  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== '') {
      url.searchParams.set(key, String(value));
    }
  }
};

type RequestOptions<TResponse, TBody> = {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  responseSchema?: ZodType<TResponse>;
  bodySchema?: ZodType<TBody>;
  body?: unknown;
  query?: Record<string, QueryValue>;
  signal?: AbortSignal;
  authRequired?: boolean;
};

export class BrokerAdminApiClient {
  private readonly baseUrl: string;

  private readonly getToken: () => string;

  public constructor(input: {baseUrl: string; getToken: () => string}) {
    this.baseUrl = input.baseUrl;
    this.getToken = input.getToken;
  }

  private resolveRequestUrl(path: string) {
    let parsedBaseUrl: URL;
    try {
      parsedBaseUrl = new URL(this.baseUrl);
    } catch {
      throw new ApiClientError({
        message: 'Broker Admin API base URL must be a valid absolute URL.',
        status: 400,
        reason: 'invalid_base_url'
      });
    }

    if (!['http:', 'https:'].includes(parsedBaseUrl.protocol)) {
      throw new ApiClientError({
        message: 'Broker Admin API base URL must use http or https.',
        status: 400,
        reason: 'invalid_base_url'
      });
    }

    return new URL(path, parsedBaseUrl);
  }

  private async request<TResponse, TBody = never>(
    input: RequestOptions<TResponse, TBody>
  ): Promise<TResponse | undefined> {
    const url = this.resolveRequestUrl(input.path);
    appendQuery(url, input.query);

    const headers = new Headers({
      accept: 'application/json',
      'x-correlation-id': makeCorrelationId()
    });

    const token = this.getToken();
    if (input.authRequired ?? true) {
      if (!token) {
        throw new ApiClientError({
          message: 'Admin token is required for this request.',
          status: 401,
          reason: 'auth_missing'
        });
      }
      headers.set('authorization', `Bearer ${token}`);
    } else if (token) {
      headers.set('authorization', `Bearer ${token}`);
    }

    let body: string | undefined;
    if (input.body !== undefined) {
      if (!input.bodySchema) {
        throw new ApiClientError({
          message: 'Request body schema is missing for a typed request.',
          status: 500,
          reason: 'request_schema_missing'
        });
      }
      const parsedBody = input.bodySchema.parse(input.body);
      headers.set('content-type', 'application/json');
      body = JSON.stringify(parsedBody);
    }

    const response = await fetch(url, {
      method: input.method,
      headers,
      ...(body ? {body} : {}),
      signal: input.signal
    });

    const responseText = await response.text();
    let parsedJson: unknown;
    if (responseText.length > 0) {
      try {
        parsedJson = JSON.parse(responseText);
      } catch {
        throw new ApiClientError({
          message: 'Server returned an invalid JSON payload.',
          status: 502,
          reason: 'invalid_json'
        });
      }
    }

    if (!response.ok) {
      const parsedError = OpenApiErrorSchema.safeParse(parsedJson);
      if (parsedError.success) {
        throw new ApiClientError({
          message: parsedError.data.message,
          status: response.status,
          reason: parsedError.data.error,
          correlationId: parsedError.data.correlation_id
        });
      }

      throw new ApiClientError({
        message: `Request failed with status ${response.status}.`,
        status: response.status,
        reason: 'request_failed'
      });
    }

    if (!input.responseSchema) {
      return undefined;
    }

    const parsedResponse = input.responseSchema.safeParse(parsedJson);
    if (!parsedResponse.success) {
      throw new ApiClientError({
        message: 'Server response did not match expected API contract.',
        status: 502,
        reason: 'contract_violation'
      });
    }

    return parsedResponse.data;
  }

  public async getHealth(signal?: AbortSignal): Promise<{status: string}> {
    const response = await this.request<{status: string}>({
      method: 'GET',
      path: '/healthz',
      responseSchema: healthResponseSchema,
      authRequired: false,
      signal
    });

    return response ?? {status: 'ok'};
  }

  public async listAdminAuthProviders(signal?: AbortSignal) {
    return this.request({
      method: 'GET',
      path: '/v1/admin/auth/providers',
      responseSchema: OpenApiAdminAuthProviderListResponseSchema,
      authRequired: false,
      signal
    });
  }

  public async startAdminLogin(input: {
    provider: OpenApiAdminAuthProvider;
    redirectUri: string;
    codeChallenge: string;
    signal?: AbortSignal;
  }) {
    return this.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/start',
      bodySchema: OpenApiAdminOAuthStartRequestSchema,
      body: {
        provider: input.provider,
        redirect_uri: input.redirectUri,
        code_challenge: input.codeChallenge,
        code_challenge_method: 'S256'
      },
      responseSchema: OpenApiAdminOAuthStartResponseSchema,
      authRequired: false,
      signal: input.signal
    });
  }

  public async handleAdminLoginCallback(input: {
    provider: OpenApiAdminAuthProvider;
    code: string;
    state: string;
    codeVerifier: string;
    redirectUri: string;
    signal?: AbortSignal;
  }) {
    return this.request({
      method: 'POST',
      path: '/v1/admin/auth/oauth/callback',
      bodySchema: OpenApiAdminOAuthCallbackRequestSchema,
      body: {
        provider: input.provider,
        code: input.code,
        state: input.state,
        code_verifier: input.codeVerifier,
        redirect_uri: input.redirectUri
      },
      responseSchema: OpenApiAdminOAuthCallbackResponseSchema,
      authRequired: false,
      signal: input.signal
    });
  }

  public async fetchCurrentAdminPrincipal(signal?: AbortSignal) {
    return this.request({
      method: 'GET',
      path: '/v1/admin/auth/session',
      responseSchema: OpenApiAdminSessionResponseSchema,
      signal
    });
  }

  public async logoutAdminSession(signal?: AbortSignal) {
    await this.request({
      method: 'POST',
      path: '/v1/admin/auth/logout',
      signal
    });
  }

  public async getAdminSignupPolicy(signal?: AbortSignal) {
    return this.request({
      method: 'GET',
      path: '/v1/admin/auth/signup-policy',
      responseSchema: OpenApiAdminSignupPolicySchema,
      signal
    });
  }

  public async setSignupMode(input: {mode: 'allowed' | 'blocked'; signal?: AbortSignal}) {
    return this.request({
      method: 'PATCH',
      path: '/v1/admin/auth/signup-policy',
      bodySchema: OpenApiAdminSignupPolicyUpdateRequestSchema,
      body: {
        new_user_mode: input.mode
      },
      responseSchema: OpenApiAdminSignupPolicySchema,
      signal: input.signal
    });
  }

  public async listAdminUsers(input: {filter?: AdminUserFilter; signal?: AbortSignal} = {}) {
    const filter = input.filter ? adminUserFilterSchema.parse(input.filter) : undefined;
    return this.request({
      method: 'GET',
      path: '/v1/admin/users',
      query: filter,
      responseSchema: OpenApiAdminUserListResponseSchema,
      signal: input.signal
    });
  }

  public async updateAdminUser(input: {
    identityId: string;
    payload: OpenApiAdminUserUpdateRequest;
    signal?: AbortSignal;
  }) {
    return this.request({
      method: 'PATCH',
      path: `/v1/admin/users/${encodeURIComponent(input.identityId)}`,
      bodySchema: OpenApiAdminUserUpdateRequestSchema,
      body: input.payload,
      responseSchema: OpenApiAdminUserSchema,
      signal: input.signal
    });
  }

  public async listAdminAccessRequests(input: {filter?: AdminAccessRequestFilter; signal?: AbortSignal} = {}) {
    const filter = input.filter ? adminAccessRequestFilterSchema.parse(input.filter) : undefined;
    return this.request({
      method: 'GET',
      path: '/v1/admin/access-requests',
      query: filter,
      responseSchema: OpenApiAdminAccessRequestListResponseSchema,
      signal: input.signal
    });
  }

  public async approveAdminAccessRequest(input: {
    requestId: string;
    payload: OpenApiAdminAccessRequestApproveRequest;
    signal?: AbortSignal;
  }) {
    return this.request({
      method: 'POST',
      path: `/v1/admin/access-requests/${encodeURIComponent(input.requestId)}/approve`,
      bodySchema: OpenApiAdminAccessRequestApproveRequestSchema,
      body: input.payload,
      responseSchema: OpenApiAdminAccessRequestSchema,
      signal: input.signal
    });
  }

  public async denyAdminAccessRequest(input: {
    requestId: string;
    payload: OpenApiAdminAccessRequestDenyRequest;
    signal?: AbortSignal;
  }) {
    return this.request({
      method: 'POST',
      path: `/v1/admin/access-requests/${encodeURIComponent(input.requestId)}/deny`,
      bodySchema: OpenApiAdminAccessRequestDenyRequestSchema,
      body: input.payload,
      responseSchema: OpenApiAdminAccessRequestSchema,
      signal: input.signal
    });
  }

  public submitAccessRequest(): Promise<never> {
    return Promise.reject(
      new ApiClientError({
        message:
          'Access request submission is unavailable because no OpenAPI endpoint is defined for this action yet.',
        status: 501,
        reason: 'contract_missing'
      })
    );
  }

  public async createTenant(input: unknown, signal?: AbortSignal) {
    return this.request({
      method: 'POST',
      path: '/v1/tenants',
      bodySchema: OpenApiTenantCreateRequestSchema,
      body: input,
      responseSchema: OpenApiTenantCreateResponseSchema,
      signal
    });
  }

  public async listTenants(signal?: AbortSignal) {
    return this.request({
      method: 'GET',
      path: '/v1/tenants',
      responseSchema: OpenApiTenantListResponseSchema,
      signal
    });
  }

  public async createWorkload(input: {tenantId: string; payload: unknown; signal?: AbortSignal}) {
    const {tenantId, payload, signal} = input;
    return this.request({
      method: 'POST',
      path: `/v1/tenants/${encodeURIComponent(tenantId)}/workloads`,
      bodySchema: OpenApiWorkloadCreateRequestSchema,
      body: payload,
      responseSchema: OpenApiWorkloadCreateResponseSchema,
      signal
    });
  }

  public async listWorkloads(input: {tenantId: string; signal?: AbortSignal}) {
    return this.request({
      method: 'GET',
      path: `/v1/tenants/${encodeURIComponent(input.tenantId)}/workloads`,
      responseSchema: OpenApiWorkloadListResponseSchema,
      signal: input.signal
    });
  }

  public async enrollWorkload(input: {workloadId: string; payload: unknown; signal?: AbortSignal}) {
    const {workloadId, payload, signal} = input;
    return this.request({
      method: 'POST',
      path: `/v1/workloads/${encodeURIComponent(workloadId)}/enroll`,
      bodySchema: OpenApiWorkloadEnrollRequestSchema,
      body: payload,
      responseSchema: OpenApiWorkloadEnrollResponseSchema,
      signal
    });
  }

  public async issueWorkloadEnrollmentToken(input: {workloadId: string; payload: unknown; signal?: AbortSignal}) {
    const {workloadId, payload, signal} = input;
    return this.request({
      method: 'POST',
      path: `/v1/workloads/${encodeURIComponent(workloadId)}/enrollment-token`,
      bodySchema: OpenApiWorkloadEnrollmentTokenIssueRequestSchema,
      body: payload,
      responseSchema: OpenApiWorkloadEnrollmentTokenIssueResponseSchema,
      signal
    });
  }

  public async updateWorkload(input: {workloadId: string; payload: unknown; signal?: AbortSignal}) {
    const {workloadId, payload, signal} = input;
    return this.request({
      method: 'PATCH',
      path: `/v1/workloads/${encodeURIComponent(workloadId)}`,
      bodySchema: OpenApiWorkloadUpdateRequestSchema,
      body: payload,
      responseSchema: OpenApiWorkloadSchema,
      signal
    });
  }

  public async createIntegration(input: {tenantId: string; payload: unknown; signal?: AbortSignal}) {
    const {tenantId, payload, signal} = input;
    return this.request({
      method: 'POST',
      path: `/v1/tenants/${encodeURIComponent(tenantId)}/integrations`,
      bodySchema: OpenApiIntegrationWriteSchema,
      body: payload,
      responseSchema: OpenApiIntegrationCreateResponseSchema,
      signal
    });
  }

  public async listIntegrations(input: {tenantId: string; signal?: AbortSignal}) {
    return this.request({
      method: 'GET',
      path: `/v1/tenants/${encodeURIComponent(input.tenantId)}/integrations`,
      responseSchema: OpenApiIntegrationListResponseSchema,
      signal: input.signal
    });
  }

  public async updateIntegration(input: {integrationId: string; payload: unknown; signal?: AbortSignal}) {
    const {integrationId, payload, signal} = input;
    return this.request({
      method: 'PATCH',
      path: `/v1/integrations/${encodeURIComponent(integrationId)}`,
      bodySchema: OpenApiIntegrationUpdateRequestSchema,
      body: payload,
      responseSchema: OpenApiIntegrationSchema,
      signal
    });
  }

  public async createTemplate(input: {payload: unknown; signal?: AbortSignal}) {
    return this.request({
      method: 'POST',
      path: '/v1/templates',
      bodySchema: OpenApiTemplateSchema,
      body: input.payload,
      responseSchema: OpenApiTemplateCreateResponseSchema,
      signal: input.signal
    });
  }

  public async listTemplates(signal?: AbortSignal) {
    return this.request({
      method: 'GET',
      path: '/v1/templates',
      responseSchema: OpenApiTemplateListResponseSchema,
      signal
    });
  }

  public async getTemplateVersion(input: {templateId: string; version: number; signal?: AbortSignal}) {
    return this.request({
      method: 'GET',
      path: `/v1/templates/${encodeURIComponent(input.templateId)}/versions/${input.version}`,
      responseSchema: OpenApiTemplateSchema,
      signal: input.signal
    });
  }

  public async createPolicy(input: {payload: unknown; signal?: AbortSignal}) {
    return this.request({
      method: 'POST',
      path: '/v1/policies',
      bodySchema: OpenApiPolicyRuleSchema,
      body: input.payload,
      responseSchema: OpenApiPolicyCreateResponseSchema,
      signal: input.signal
    });
  }

  public async listPolicies(signal?: AbortSignal) {
    return this.request({
      method: 'GET',
      path: '/v1/policies',
      responseSchema: OpenApiPolicyListResponseSchema,
      signal
    });
  }

  public async deletePolicy(input: {policyId: string; signal?: AbortSignal}) {
    await this.request({
      method: 'DELETE',
      path: `/v1/policies/${encodeURIComponent(input.policyId)}`,
      signal: input.signal
    });
  }

  public async listApprovals(input: {status?: ApprovalStatusFilter; signal?: AbortSignal}) {
    return this.request({
      method: 'GET',
      path: '/v1/approvals',
      query: {
        status: input.status
      },
      responseSchema: OpenApiApprovalListResponseSchema,
      signal: input.signal
    });
  }

  public async approveApproval(input: {
    approvalId: string;
    payload: OpenApiApprovalDecisionRequest;
    signal?: AbortSignal;
  }) {
    return this.request({
      method: 'POST',
      path: `/v1/approvals/${encodeURIComponent(input.approvalId)}/approve`,
      bodySchema: OpenApiApprovalDecisionRequestSchema,
      body: input.payload,
      responseSchema: OpenApiApprovalResponseSchema,
      signal: input.signal
    });
  }

  public async denyApproval(input: {
    approvalId: string;
    payload?: OpenApiApprovalDecisionRequest;
    signal?: AbortSignal;
  }) {
    return this.request({
      method: 'POST',
      path: `/v1/approvals/${encodeURIComponent(input.approvalId)}/deny`,
      ...(input.payload
        ? {
            bodySchema: OpenApiApprovalDecisionRequestSchema,
            body: input.payload
          }
        : {}),
      responseSchema: OpenApiApprovalResponseSchema,
      signal: input.signal
    });
  }

  public async listAuditEvents(input: {filter?: AuditFilter; signal?: AbortSignal}) {
    return this.request({
      method: 'GET',
      path: '/v1/audit/events',
      query: input.filter,
      responseSchema: OpenApiAuditEventListResponseSchema,
      signal: input.signal
    });
  }

  public async listManifestKeys(signal?: AbortSignal) {
    return this.request({
      method: 'GET',
      path: '/v1/keys/manifest',
      responseSchema: OpenApiManifestKeysSchema,
      signal
    });
  }
}
