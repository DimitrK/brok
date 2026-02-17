import type {CanonicalRequestDescriptorContract, TemplateContract} from './contracts';

export type CanonicalizerStorageContext<TTransactionClient = unknown> = {
  transaction_client?: TTransactionClient;
};

export type CanonicalizerIntegrationTemplateBinding = {
  tenant_id: string;
  integration_id: string;
  enabled: boolean;
  template_id: string;
  template_version: number;
};

export type CanonicalizerApprovalCacheRecord = {
  approval_id: string;
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'executed' | 'canceled';
  expires_at: string;
  template_id: string;
  template_version: number;
};

export type CanonicalizerRateLimitConsumeResult = {
  allowed: boolean;
  remaining: number;
  reset_at: string;
};

export type CanonicalizerTemplateStore<TTransactionClient = unknown> = {
  listTemplateVersionsByTenantAndTemplateId: (input: {
    tenant_id: string;
    template_id: string;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<TemplateContract[]>;
  getTemplateByTenantTemplateIdVersion: (input: {
    tenant_id: string;
    template_id: string;
    version: number;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<TemplateContract | null>;
  getIntegrationTemplateBindingByTenantAndId: (input: {
    tenant_id: string;
    integration_id: string;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<CanonicalizerIntegrationTemplateBinding | null>;
};

export type CanonicalizerApprovalStore<TTransactionClient = unknown> = {
  findOpenApprovalByCanonicalDescriptor: (input: {
    descriptor: CanonicalRequestDescriptorContract;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<CanonicalizerApprovalCacheRecord | null>;
  createApprovalRequestFromCanonicalDescriptor: (input: {
    descriptor: CanonicalRequestDescriptorContract;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<CanonicalizerApprovalCacheRecord>;
};

export type CanonicalizerAuditStore<TTransactionClient = unknown> = {
  appendCanonicalizationAuditEvent: (input: {
    descriptor: CanonicalRequestDescriptorContract;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<void>;
};

export type CanonicalizerCacheStore<TTransactionClient = unknown> = {
  getTemplateCache: (input: {
    tenant_id: string;
    template_id: string;
    version: number;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<TemplateContract | null>;
  setTemplateCache: (input: {
    tenant_id: string;
    template_id: string;
    version: number;
    template: TemplateContract;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<void>;
  getApprovalOnceCache: (input: {
    descriptor: CanonicalRequestDescriptorContract;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<CanonicalizerApprovalCacheRecord | null>;
  setApprovalOnceCache: (input: {
    descriptor: CanonicalRequestDescriptorContract;
    value: CanonicalizerApprovalCacheRecord;
    ttl_seconds: number;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<void>;
  incrementRateLimitCounter: (input: {
    tenant_id: string;
    workload_id: string;
    integration_id: string;
    action_group: string;
    method: string;
    host: string;
    interval_seconds: number;
    max_requests: number;
    context?: CanonicalizerStorageContext<TTransactionClient>;
  }) => Promise<CanonicalizerRateLimitConsumeResult>;
};

export type CanonicalizerStoreTransactionFactory<TTransactionClient = unknown> = <T>(input: {
  context?: CanonicalizerStorageContext<TTransactionClient>;
  operation: (transaction_client: TTransactionClient) => Promise<T>;
  fallback_operation: () => Promise<T>;
}) => Promise<T>;

export type CanonicalizerPersistenceDependencies<TTransactionClient = unknown> = {
  template_store: CanonicalizerTemplateStore<TTransactionClient>;
  approval_store: CanonicalizerApprovalStore<TTransactionClient>;
  audit_store: CanonicalizerAuditStore<TTransactionClient>;
  cache_store: CanonicalizerCacheStore<TTransactionClient>;
  run_with_transaction_context?: CanonicalizerStoreTransactionFactory<TTransactionClient>;
};

/**
 * Package-level dependency contract for storage-backed canonicalizer workflows.
 * Connections are owned by apps and injected here as repositories/adapters.
 */
export const createCanonicalizerPersistenceBridge = <TTransactionClient = unknown>(
  dependencies: CanonicalizerPersistenceDependencies<TTransactionClient>
) => dependencies;
