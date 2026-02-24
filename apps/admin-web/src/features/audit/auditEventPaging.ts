import type {OpenApiAuditEventListResponse} from '@broker-interceptor/schemas';

import type {BrokerAdminApiClient} from '../../api/client';
import type {AuditFilter} from '../../api/querySchemas';

export const DEFAULT_AUDIT_PAGE_LIMIT = 50;

export const fetchAuditEventPage = async (input: {
  api: BrokerAdminApiClient;
  filter: AuditFilter;
  cursor?: string;
  limit?: number;
  signal?: AbortSignal;
}): Promise<OpenApiAuditEventListResponse> => {
  const response = await input.api.listAuditEvents({
    filter: {
      ...input.filter,
      limit: input.limit ?? DEFAULT_AUDIT_PAGE_LIMIT,
      ...(input.cursor ? {cursor: input.cursor} : {})
    },
    signal: input.signal
  });

  return {
    events: response?.events ?? [],
    ...(response?.next_cursor ? {next_cursor: response.next_cursor} : {})
  };
};
