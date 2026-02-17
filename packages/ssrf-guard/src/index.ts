export {
  DEFAULT_DNS_RESOLUTION_CONFIG,
  DnsResolutionConfigSchema,
  GuardExecuteRequestInputSchema,
  GuardExecuteRequestOutputSchema,
  GuardUpstreamResponseInputSchema,
  type DnsResolutionConfig,
  type DnsResolver,
  type GuardExecuteRequestInput,
  type GuardExecuteRequestOptions,
  type GuardExecuteRequestOutput,
  type GuardUpstreamResponseInput,
  type OpenApiExecuteRequestContract,
  type OpenApiHeaderListContract,
  type TemplateContract
} from './contracts';
export {
  err,
  ok,
  ssrfGuardErrorCodes,
  type SsrfGuardError,
  type SsrfGuardErrorCode,
  type SsrfGuardFailure,
  type SsrfGuardResult,
  type SsrfGuardSuccess
} from './errors';
export {enforceRedirectDenyPolicy, guardExecuteRequestDestination} from './guard';
export {
  createSsrfGuardStorageBridge_INCOMPLETE,
  DnsRebindingObservationSchema,
  DnsResolutionCacheEntrySchema,
  SsrfDecisionProjectionSchema,
  SsrfGuardStorageBridge,
  type SsrfGuardStorageBridgeDependencies_INCOMPLETE,
  type SsrfGuardStorageRepositories_INCOMPLETE,
  StorageScopeSchema,
  TemplateInvalidationSignalSchema,
  type DnsRebindingObservation,
  type DnsResolutionCacheEntry,
  type IntegrationTemplateForExecute,
  type MaybePromise,
  type RequiredDependency,
  type SsrfDecisionProjection,
  type StorageScope,
  type TemplateInvalidationSignal,
  type TransactionClient
} from './storageBridge';

export const packageName = 'ssrf-guard';
