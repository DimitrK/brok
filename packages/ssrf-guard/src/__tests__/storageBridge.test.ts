import {TemplateSchema} from '@broker-interceptor/schemas';
import {describe, expect, it, vi} from 'vitest';

import {
  SsrfGuardStorageBridge,
  createSsrfGuardStorageBridge_INCOMPLETE
} from '../index';

const buildTemplate = () =>
  TemplateSchema.parse({
    template_id: 'tpl_ssrf_guard_bridge_v1',
    version: 1,
    provider: 'test_provider',
    allowed_schemes: ['https'],
    allowed_ports: [443],
    allowed_hosts: ['api.example.com'],
    redirect_policy: {
      mode: 'deny'
    },
    path_groups: [
      {
        group_id: 'group_a',
        risk_tier: 'low',
        approval_mode: 'none',
        methods: ['GET'],
        path_patterns: ['^/v1/messages$'],
        query_allowlist: [],
        header_forward_allowlist: ['accept'],
        body_policy: {
          max_bytes: 0,
          content_types: []
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
  });

const buildScope = () => ({
  tenant_id: 't_1',
  workload_id: 'w_1',
  integration_id: 'i_1'
});

const buildDnsCacheEntry = () => ({
  resolved_ips: ['93.184.216.34'],
  resolved_at_epoch_ms: 1_700_000_000_000,
  ttl_seconds: 30
});

const buildDecisionProjection = () => ({
  event_id: 'evt_1',
  timestamp: '2026-02-08T12:00:00Z',
  tenant_id: 't_1',
  workload_id: 'w_1',
  integration_id: 'i_1',
  template_id: 'tpl_ssrf_guard_bridge_v1',
  template_version: 1,
  destination_host: 'api.example.com',
  destination_port: 443,
  resolved_ips: ['93.184.216.34'],
  decision: 'denied' as const,
  reason_code: 'resolved_ip_denied_private_range' as const,
  correlation_id: 'corr_1'
});

const buildInvalidationSignal = () => ({
  template_id: 'tpl_ssrf_guard_bridge_v1',
  version: 2,
  tenant_id: 't_1',
  updated_at: '2026-02-08T12:01:00Z'
});

describe('SsrfGuardStorageBridge', () => {
  it('declares db integration requirements as *_INCOMPLETE', () => {
    const bridge = new SsrfGuardStorageBridge();
    const dependencies = bridge.listRequiredDependencies_INCOMPLETE();

    expect(dependencies).toEqual([
      {
        packageName: '@broker-interceptor/db',
        requiredMethods: [
          'getIntegrationTemplateForExecute',
          'getTemplateByIdVersion',
          'readDnsResolutionCache',
          'upsertDnsResolutionCache',
          'appendDnsRebindingObservation',
          'appendSsrfGuardDecisionProjection',
          'publishTemplateInvalidationSignal',
          'persistTemplateInvalidationOutbox',
          'runInTransaction'
        ],
        integrationStatus: 'mocked'
      }
    ]);
  });

  it('stores and loads active template mappings via fallback mock methods', async () => {
    const bridge = createSsrfGuardStorageBridge_INCOMPLETE();
    const template = buildTemplate();

    const persisted = await bridge.persistActiveTemplateForExecuteInDbMock_INCOMPLETE({
      scope: buildScope(),
      template
    });
    expect(persisted.template_id).toBe('tpl_ssrf_guard_bridge_v1');

    const loaded = await bridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope: buildScope()
    });
    expect(loaded?.template_id).toBe('tpl_ssrf_guard_bridge_v1');
  });

  it('returns null for missing fallback reads', async () => {
    const bridge = createSsrfGuardStorageBridge_INCOMPLETE();

    const missingTemplate = await bridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope: {
        tenant_id: 't_missing',
        workload_id: 'w_missing',
        integration_id: 'i_missing'
      }
    });
    expect(missingTemplate).toBeNull();

    const missingCache = await bridge.readDnsResolutionCacheFromRedis_INCOMPLETE({
      normalized_host: 'missing.example.com'
    });
    expect(missingCache).toBeNull();
  });

  it('accepts pre-seeded fallback state', async () => {
    const template = buildTemplate();
    const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
      initial_state: {
        activeTemplatesByScope: new Map([['t_1:w_1:i_1', template]]),
        dnsCacheByHost: new Map([['api.example.com', buildDnsCacheEntry()]])
      }
    });

    const loadedTemplate = await bridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope: buildScope()
    });
    expect(loadedTemplate?.template_id).toBe('tpl_ssrf_guard_bridge_v1');

    const loadedCache = await bridge.readDnsResolutionCacheFromRedis_INCOMPLETE({
      normalized_host: 'api.example.com'
    });
    expect(loadedCache?.ttl_seconds).toBe(30);
  });

  it('delegates storage operations to injected repositories and passes transaction client through', async () => {
    const transactionClient = {id: 'tx_1'};
    const template = buildTemplate();
    const scope = buildScope();
    type LoadTemplateInput = Parameters<
      SsrfGuardStorageBridge['loadActiveTemplateForExecuteFromDb_INCOMPLETE']
    >[0];
    type WriteDnsCacheInput = Parameters<
      SsrfGuardStorageBridge['writeDnsResolutionCacheToRedisMock_INCOMPLETE']
    >[0];
    type AppendProjectionInput = Parameters<
      SsrfGuardStorageBridge['appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE']
    >[0];

    const cacheEntry: WriteDnsCacheInput['entry'] = buildDnsCacheEntry();
    const projection: AppendProjectionInput['projection'] = buildDecisionProjection();

    const loadTemplateSpy = vi.fn((input: LoadTemplateInput) => {
      expect(input.scope).toEqual(scope);
      expect(input.transaction_client).toBe(transactionClient);
      return template;
    });
    const writeDnsCacheSpy = vi.fn((input: WriteDnsCacheInput) => {
      expect(input.normalized_host).toBe('api.example.com');
      expect(input.entry.ttl_seconds).toBe(30);
      expect(input.transaction_client).toBe(transactionClient);
      return input.entry;
    });
    const appendProjectionSpy = vi.fn((input: AppendProjectionInput) => {
      expect(input.projection.event_id).toBe('evt_1');
      expect(input.transaction_client).toBe(transactionClient);
      return input.projection;
    });

    const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        loadActiveTemplateForExecuteFromDb_INCOMPLETE: loadTemplateSpy,
        writeDnsResolutionCacheToRedisMock_INCOMPLETE: writeDnsCacheSpy,
        appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE: appendProjectionSpy
      }
    });

    const loaded = await bridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope,
      transaction_client: transactionClient
    });
    expect(loaded?.template_id).toBe('tpl_ssrf_guard_bridge_v1');

    const written = await bridge.writeDnsResolutionCacheToRedisMock_INCOMPLETE({
      normalized_host: 'api.example.com',
      entry: cacheEntry,
      transaction_client: transactionClient
    });
    expect(written.ttl_seconds).toBe(30);

    const projected = await bridge.appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE({
      projection,
      transaction_client: transactionClient
    });
    expect(projected.reason_code).toBe('resolved_ip_denied_private_range');

    expect(loadTemplateSpy).toHaveBeenCalledTimes(1);
    expect(writeDnsCacheSpy).toHaveBeenCalledTimes(1);
    expect(appendProjectionSpy).toHaveBeenCalledTimes(1);
  });

  it('uses db getIntegrationTemplateForExecute wiring when explicit load method is not injected', async () => {
    const scope = buildScope();
    const transactionClient = {id: 'tx_2'};
    const template = buildTemplate();

    const getIntegrationTemplateForExecuteSpy = vi.fn(
      (input: {
        tenant_id: string;
        workload_id: string;
        integration_id: string;
        transaction_client?: unknown;
      }) => {
        expect(input).toEqual({
          tenant_id: scope.tenant_id,
          workload_id: scope.workload_id,
          integration_id: scope.integration_id,
          transaction_client: transactionClient
        });
        return {
          workload_enabled: true,
          integration_enabled: true,
          executable: true,
          execution_status: 'executable' as const,
          template,
          template_id: template.template_id,
          template_version: template.version
        };
      }
    );

    const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        getIntegrationTemplateForExecute: getIntegrationTemplateForExecuteSpy
      }
    });

    const loaded = await bridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope,
      transaction_client: transactionClient
    });
    expect(loaded?.template_id).toBe('tpl_ssrf_guard_bridge_v1');
    expect(getIntegrationTemplateForExecuteSpy).toHaveBeenCalledTimes(1);
  });

  it('returns null for non-executable db template wiring results and not_found errors', async () => {
    const bridgeNonExecutable = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        getIntegrationTemplateForExecute: () => ({
          workload_enabled: true,
          integration_enabled: false,
          executable: false,
          execution_status: 'integration_disabled',
          template: buildTemplate(),
          template_id: 'tpl_ssrf_guard_bridge_v1',
          template_version: 1
        })
      }
    });

    const nonExecutable = await bridgeNonExecutable.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope: buildScope()
    });
    expect(nonExecutable).toBeNull();

    const bridgeNotFound = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        getIntegrationTemplateForExecute: () => {
          const error = new Error('Template binding not found') as Error & {
            code: string;
          };
          error.code = 'not_found';
          throw error;
        }
      }
    });

    const notFound = await bridgeNotFound.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
      scope: buildScope()
    });
    expect(notFound).toBeNull();
  });

  it('fails closed on invalid db getIntegrationTemplateForExecute payloads', async () => {
    const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        getIntegrationTemplateForExecute: () => ({
          workload_enabled: true,
          integration_enabled: true,
          executable: true,
          execution_status: 'executable',
          template: buildTemplate(),
          template_id: 'tpl_ssrf_guard_bridge_v1',
          template_version: 0
        })
      }
    });

    await expect(
      bridge.loadActiveTemplateForExecuteFromDb_INCOMPLETE({
        scope: buildScope()
      })
    ).rejects.toThrow();
  });

  it('supports db-style redis and projection repository methods with injected redis client context', async () => {
    type AppendDecisionInput = Parameters<
      SsrfGuardStorageBridge['appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE']
    >[0];

    const redisClient = {id: 'redis_1'};
    const transactionClient = {id: 'tx_3'};
    const cacheEntry = buildDnsCacheEntry();
    const observation = {
      ip_set_hash: 'hash_1',
      resolved_ips: ['93.184.216.34'],
      observed_at_epoch_ms: 1_700_000_000_001
    };
    const projection = buildDecisionProjection();
    const signal = buildInvalidationSignal();

    const readDnsSpy = vi.fn(
      (input: {normalized_host: string; context: {clients: {redis?: unknown}}}) => {
        expect(input.normalized_host).toBe('api.example.com');
        expect(input.context.clients.redis).toBe(redisClient);
        return cacheEntry;
      }
    );
    const upsertDnsSpy = vi.fn(
      (input: {
        normalized_host: string;
        entry: typeof cacheEntry;
        context: {clients: {redis?: unknown}};
      }) => {
        expect(input.context.clients.redis).toBe(redisClient);
        return {
          outcome: 'applied' as const,
          applied: true,
          entry: input.entry
        };
      }
    );
    const appendRebindingSpy = vi.fn(
      (input: {
        normalized_host: string;
        observation: typeof observation;
        context: {clients: {redis?: unknown}};
      }) => {
        expect(input.context.clients.redis).toBe(redisClient);
        return {
          observation: input.observation,
          history_size: 1
        };
      }
    );
    const appendDecisionSpy = vi.fn((input: AppendDecisionInput) => {
        expect(input.transaction_client).toBe(transactionClient);
        return input.projection;
    });
    const persistOutboxSpy = vi.fn((input: {signal: typeof signal; transaction_client?: unknown}) => {
      expect(input.transaction_client).toBe(transactionClient);
      return undefined;
    });
    const publishSignalSpy = vi.fn((input: {signal: typeof signal; context: {clients: {redis?: unknown}}}) => {
      expect(input.context.clients.redis).toBe(redisClient);
      return undefined;
    });

    const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        readDnsResolutionCache: readDnsSpy,
        upsertDnsResolutionCache: upsertDnsSpy,
        appendDnsRebindingObservation: appendRebindingSpy,
        appendSsrfGuardDecisionProjection: appendDecisionSpy,
        persistTemplateInvalidationOutbox: persistOutboxSpy,
        publishTemplateInvalidationSignal: publishSignalSpy
      },
      clients: {
        redis: redisClient
      }
    });

    const read = await bridge.readDnsResolutionCacheFromRedis_INCOMPLETE({
      normalized_host: 'api.example.com'
    });
    expect(read?.ttl_seconds).toBe(30);

    const write = await bridge.writeDnsResolutionCacheToRedisMock_INCOMPLETE({
      normalized_host: 'api.example.com',
      entry: cacheEntry
    });
    expect(write.ttl_seconds).toBe(30);

    const rebinding = await bridge.appendDnsRebindingObservationToRedisMock_INCOMPLETE({
      normalized_host: 'api.example.com',
      observation
    });
    expect(rebinding.ip_set_hash).toBe('hash_1');

    const projected = await bridge.appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE({
      projection,
      transaction_client: transactionClient
    });
    expect(projected.event_id).toBe('evt_1');

    const published = await bridge.publishTemplateInvalidationSignalToRedisMock_INCOMPLETE({
      signal,
      transaction_client: transactionClient
    });
    expect(published.version).toBe(2);

    expect(readDnsSpy).toHaveBeenCalledTimes(1);
    expect(upsertDnsSpy).toHaveBeenCalledTimes(1);
    expect(appendRebindingSpy).toHaveBeenCalledTimes(1);
    expect(appendDecisionSpy).toHaveBeenCalledTimes(1);
    expect(persistOutboxSpy).toHaveBeenCalledTimes(1);
    expect(publishSignalSpy).toHaveBeenCalledTimes(1);
  });

  it('fails closed when db-style redis methods are injected without redis client dependency', async () => {
    const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        readDnsResolutionCache: () => buildDnsCacheEntry()
      }
    });

    await expect(
      bridge.readDnsResolutionCacheFromRedis_INCOMPLETE({
        normalized_host: 'api.example.com'
      })
    ).rejects.toThrow();
  });

  it('validates delegated repository outputs and fails closed', async () => {
    const bridge = createSsrfGuardStorageBridge_INCOMPLETE({
      repositories: {
        readDnsResolutionCacheFromRedis_INCOMPLETE: () => ({
          resolved_ips: ['not_an_ip'],
          resolved_at_epoch_ms: 1_700_000_000_000,
          ttl_seconds: 30
        })
      }
    });

    await expect(
      bridge.readDnsResolutionCacheFromRedis_INCOMPLETE({
        normalized_host: 'api.example.com'
      })
    ).rejects.toThrow();
  });

  it('fails closed on invalid db-dependent payloads', async () => {
    const bridge = createSsrfGuardStorageBridge_INCOMPLETE();

    await expect(
      bridge.writeDnsResolutionCacheToRedisMock_INCOMPLETE({
        normalized_host: 'api.example.com',
        entry: {
          resolved_ips: ['93.184.216.34'],
          resolved_at_epoch_ms: 1_700_000_000_000,
          ttl_seconds: 120
        }
      })
    ).rejects.toThrow();

    await expect(
      bridge.appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE({
        projection: {
          ...buildDecisionProjection(),
          reason_code: 'not_a_reason_code'
        } as unknown as Parameters<
          SsrfGuardStorageBridge['appendSsrfDecisionProjectionToPostgresMock_INCOMPLETE']
        >[0]['projection']
      })
    ).rejects.toThrow();
  });
});
