import {OpenApiAuditEventSchema, type OpenApiAuditEvent} from '@broker-interceptor/schemas'

export const buildAuditEvent = (
  overrides: Partial<OpenApiAuditEvent> = {}
): OpenApiAuditEvent =>
  OpenApiAuditEventSchema.parse({
    event_id: 'evt_1',
    timestamp: '2026-02-07T10:00:00.000Z',
    tenant_id: 'tenant_1',
    workload_id: 'workload_1',
    integration_id: 'integration_1',
    correlation_id: 'corr_1',
    event_type: 'execute',
    decision: 'allowed',
    action_group: 'openai_responses',
    risk_tier: 'low',
    destination: {
      scheme: 'https',
      host: 'api.openai.com',
      port: 443,
      path_group: 'openai_responses'
    },
    latency_ms: 42,
    upstream_status_code: 200,
    canonical_descriptor: {
      tenant_id: 'tenant_1',
      workload_id: 'workload_1',
      integration_id: 'integration_1',
      template_id: 'tpl_openai_min_v1',
      template_version: 1,
      method: 'POST',
      canonical_url: 'https://api.openai.com/v1/responses',
      matched_path_group_id: 'openai_responses',
      normalized_headers: [
        {name: 'content-type', value: 'application/json'},
        {name: 'authorization', value: 'Bearer raw-secret'}
      ],
      query_keys: [],
      query_fingerprint_base64: null,
      body_sha256_base64: null
    },
    policy: {
      rule_id: 'policy_1',
      rule_type: 'allow',
      approval_id: null
    },
    message: 'raw upstream payload should not be stored',
    metadata: {
      action: 'execute',
      api_key: 'sk-live-secret',
      request_body: '{"secret":"value"}'
    },
    ...overrides
  })
