import {describe, expect, it, vi} from 'vitest';

import {createCanonicalizerPersistenceBridge, type CanonicalizerPersistenceDependencies} from '../index';

describe('createCanonicalizerPersistenceBridge', () => {
  it('returns injected repositories without creating storage clients', async () => {
    const transactionClient = {id: 'tx_1'};
    const dependencies: CanonicalizerPersistenceDependencies<typeof transactionClient> = {
      template_store: {
        listTemplateVersionsByTenantAndTemplateId: vi.fn().mockResolvedValue([]),
        getTemplateByTenantTemplateIdVersion: vi.fn().mockResolvedValue(null),
        getIntegrationTemplateBindingByTenantAndId: vi.fn().mockResolvedValue(null)
      },
      approval_store: {
        findOpenApprovalByCanonicalDescriptor: vi.fn().mockResolvedValue(null),
        createApprovalRequestFromCanonicalDescriptor: vi.fn().mockResolvedValue({
          approval_id: 'appr_1',
          status: 'pending',
          expires_at: '2026-02-08T00:00:00.000Z',
          template_id: 'tpl_test',
          template_version: 1
        })
      },
      audit_store: {
        appendCanonicalizationAuditEvent: vi.fn().mockResolvedValue(undefined)
      },
      cache_store: {
        getTemplateCache: vi.fn().mockResolvedValue(null),
        setTemplateCache: vi.fn().mockResolvedValue(undefined),
        getApprovalOnceCache: vi.fn().mockResolvedValue(null),
        setApprovalOnceCache: vi.fn().mockResolvedValue(undefined),
        incrementRateLimitCounter: vi.fn().mockResolvedValue({
          allowed: true,
          remaining: 10,
          reset_at: '2026-02-08T00:01:00.000Z'
        })
      }
    };

    const bridge = createCanonicalizerPersistenceBridge(dependencies);
    expect(bridge).toBe(dependencies);

    await bridge.template_store.listTemplateVersionsByTenantAndTemplateId({
      tenant_id: 't_1',
      template_id: 'tpl_test',
      context: {transaction_client: transactionClient}
    });

    expect(bridge.template_store.listTemplateVersionsByTenantAndTemplateId).toHaveBeenCalledWith({
      tenant_id: 't_1',
      template_id: 'tpl_test',
      context: {transaction_client: transactionClient}
    });
  });
});
