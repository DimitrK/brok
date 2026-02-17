import {createAuditService, createInMemoryAuditStore} from '@broker-interceptor/audit'
import {describe, expect, it} from 'vitest'

import {BrokerApiDependencyBridge} from '../dependencyBridge'
import {DataPlaneRepository} from '../repository'

const createRepositoryState = () => ({
  version: 1,
  workloads: [
    {
      workload_id: 'w_1',
      tenant_id: 't_1',
      name: 'workload-one',
      mtls_san_uri: 'spiffe://broker/tenants/t_1/workloads/w_1',
      enabled: true
    }
  ],
  integrations: [
    {
      integration_id: 'i_1',
      tenant_id: 't_1',
      provider: 'openai',
      name: 'OpenAI Integration',
      template_id: 'tpl_openai_safe',
      enabled: true
    }
  ],
  templates: [
    {
      template_id: 'tpl_openai_safe',
      version: 1,
      provider: 'openai',
      allowed_schemes: ['https'],
      allowed_ports: [443],
      allowed_hosts: ['api.openai.com'],
      redirect_policy: {mode: 'deny'},
      path_groups: [
        {
          group_id: 'openai_responses',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['POST'],
          path_patterns: ['^/v1/responses$'],
          query_allowlist: [],
          header_forward_allowlist: ['content-type'],
          body_policy: {
            max_bytes: 8192,
            content_types: ['application/json']
          }
        }
      ],
      network_safety: {
        deny_private_ip_ranges: true,
        deny_link_local: true,
        deny_loopback: true,
        deny_metadata_ranges: true,
        dns_resolution_required: true
      }
    }
  ],
  policies: [
    {
      policy_id: 'pol_allow',
      rule_type: 'allow',
      scope: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'i_1',
        template_id: 'tpl_openai_safe',
        template_version: 1,
        action_group: 'openai_responses',
        method: 'POST',
        host: 'api.openai.com',
        query_keys: []
      }
    }
  ],
  approvals: [],
  sessions: [],
  integration_secret_headers: {},
  dpop_required_workload_ids: []
})

describe('broker-api dependency bridge', () => {
  it('delegates repository lookups, approval creation, and audit appends', async () => {
    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 300,
      manifestTtlSeconds: 600
    })
    const auditService = createAuditService({
      store: createInMemoryAuditStore()
    })

    const bridge = new BrokerApiDependencyBridge({
      repository,
      auditService
    })

    expect(bridge.getWorkloadBySanUri({sanUri: 'spiffe://broker/tenants/t_1/workloads/w_1'})?.workload_id).toBe('w_1')
    expect(bridge.getIntegrationByTenantAndId({tenantId: 't_1', integrationId: 'i_1'})?.integration_id).toBe('i_1')
    expect(bridge.getLatestTemplateById({templateId: 'tpl_openai_safe'})?.version).toBe(1)
    expect(bridge.listTenantPolicies({tenantId: 't_1'})).toHaveLength(1)
    expect(bridge.isSharedInfrastructureEnabled()).toBe(false)

    const approval = await bridge.createApprovalRequest({
      descriptor: {
        tenant_id: 't_1',
        workload_id: 'w_1',
        integration_id: 'i_1',
        template_id: 'tpl_openai_safe',
        template_version: 1,
        method: 'POST',
        canonical_url: 'https://api.openai.com/v1/responses',
        matched_path_group_id: 'openai_responses',
        normalized_headers: [{name: 'content-type', value: 'application/json'}],
        query_keys: []
      },
      summary: {
        integration_id: 'i_1',
        action_group: 'openai_responses',
        risk_tier: 'medium',
        destination_host: 'api.openai.com',
        method: 'POST',
        path: '/v1/responses'
      },
      correlationId: 'corr_dep_1'
    })
    expect(approval.approval_id).toContain('appr_')

    const appended = await bridge.appendAuditEvent({
      event: {
        event_id: 'evt_dep_1',
        timestamp: new Date().toISOString(),
        tenant_id: 't_1',
        correlation_id: 'corr_dep_1',
        event_type: 'session_issued'
      }
    })
    expect(appended.delivery_status).toBe('stored')

    await expect(bridge.withSharedTransaction(() => Promise.resolve('no-op'))).rejects.toThrow(
      'Shared transaction requested while infrastructure is disabled'
    )
  })

  it('fails closed when audit append returns an error result', async () => {
    const repository = await DataPlaneRepository.create({
      initialState: createRepositoryState(),
      approvalTtlSeconds: 300,
      manifestTtlSeconds: 600
    })

    const bridge = new BrokerApiDependencyBridge({
      repository,
      auditService: {
        appendAuditEvent: () =>
          Promise.resolve({
            ok: false,
            error: {
              code: 'storage_write_failed',
              message: 'store down'
            }
          })
      } as never
    })

    await expect(
      bridge.appendAuditEvent({
        event: {
          event_id: 'evt_dep_2',
          timestamp: new Date().toISOString(),
          tenant_id: 't_1',
          correlation_id: 'corr_dep_2',
          event_type: 'execute'
        }
      })
    ).rejects.toThrow('store down')
  })
})
