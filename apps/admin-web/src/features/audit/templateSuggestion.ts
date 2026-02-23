import type {OpenApiAuditEvent} from '@broker-interceptor/schemas';

import {normalizeTemplateIdSuffix} from '../templates/templateHelpers';

export const TEMPLATE_DRAFT_STORAGE_KEY = 'admin-web-template-draft';

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const inferProviderFromHost = (host: string) => {
  const normalizedHost = host.toLowerCase();
  if (normalizedHost.includes('openai.com')) {
    return 'openai';
  }
  if (normalizedHost.includes('anthropic.com')) {
    return 'anthropic';
  }
  if (normalizedHost.includes('googleapis.com')) {
    return 'google';
  }

  return 'custom';
};

export const isFailingAuditEvent = (event: OpenApiAuditEvent) =>
  event.decision === 'denied' || event.decision === 'approval_required' || event.decision === 'throttled';

export const getCanonicalUrlFromEvent = (event: OpenApiAuditEvent) => event.canonical_descriptor?.canonical_url ?? '';

export const getMethodFromEvent = (event: OpenApiAuditEvent) => event.canonical_descriptor?.method ?? undefined;

export const getHostFromEvent = (event: OpenApiAuditEvent) => {
  const canonicalUrl = getCanonicalUrlFromEvent(event);
  if (canonicalUrl) {
    try {
      return new URL(canonicalUrl).host;
    } catch {
      return event.destination?.host ?? undefined;
    }
  }

  return event.destination?.host ?? undefined;
};

export const getPathFromEvent = (event: OpenApiAuditEvent) => {
  const canonicalUrl = getCanonicalUrlFromEvent(event);
  if (canonicalUrl) {
    try {
      const parsed = new URL(canonicalUrl);
      return parsed.pathname || '/';
    } catch {
      return undefined;
    }
  }

  return undefined;
};

export const buildPathPatternSuggestion = (paths: string[]) => {
  const uniquePaths = [...new Set(paths.filter(Boolean))];
  if (uniquePaths.length === 0) {
    return '^/.*$';
  }
  if (uniquePaths.length === 1) {
    return `^${escapeRegExp(uniquePaths[0] ?? '/')}$`;
  }

  const splitPaths = uniquePaths.map(path => path.split('/').filter(Boolean));
  const referenceLength = splitPaths[0]?.length ?? 0;
  const equalSegmentCount = splitPaths.every(segments => segments.length === referenceLength);

  if (equalSegmentCount) {
    const patternSegments = Array.from({length: referenceLength}, (_, index) => {
      const values = splitPaths.map(segments => segments[index] ?? '');
      const firstValue = values[0] ?? '';
      return values.every(value => value === firstValue) ? escapeRegExp(firstValue) : '[^/]+';
    });

    return `^/${patternSegments.join('/')}$`;
  }

  const minLength = Math.min(...splitPaths.map(segments => segments.length));
  let sharedCount = 0;
  while (sharedCount < minLength) {
    const current = splitPaths[0]?.[sharedCount] ?? '';
    if (!splitPaths.every(segments => segments[sharedCount] === current)) {
      break;
    }
    sharedCount += 1;
  }

  if (sharedCount === 0) {
    return '^/.*$';
  }

  const sharedPrefix = splitPaths[0]?.slice(0, sharedCount).map(value => escapeRegExp(value)).join('/') ?? '';
  return `^/${sharedPrefix}(?:/.*)?$`;
};

export const collectMatchingFailingEvents = (selected: OpenApiAuditEvent, events: OpenApiAuditEvent[]) => {
  const selectedMethod = getMethodFromEvent(selected);
  const selectedHost = getHostFromEvent(selected);
  if (!selectedMethod || !selectedHost) {
    return [];
  }

  return events.filter(event => {
    if (!isFailingAuditEvent(event)) {
      return false;
    }

    return getMethodFromEvent(event) === selectedMethod && getHostFromEvent(event) === selectedHost;
  });
};

export type AuditTemplateTraitSelection = {
  includeAllObservedHosts: boolean;
  includeQueryKeys: boolean;
  includeNormalizedHeaders: boolean;
  includeActionGroup: boolean;
  includeRiskTier: boolean;
  useSuggestedPathPattern: boolean;
};

export type TemplateDraftRouteState = {
  templateDraft: {
    source: 'audit';
    provider: string;
    template_name: string;
    template_id_suffix: string;
    description: string;
    allowed_hosts: string[];
    path_groups: Array<{
      group_id: string;
      risk_tier: 'low' | 'medium' | 'high';
      approval_mode: 'none' | 'required';
      methods: Array<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>;
      path_patterns: string[];
      query_allowlist: string[];
      header_forward_allowlist: string[];
      max_body_bytes: number;
      content_types: string[];
    }>;
  };
};

const toRiskTier = (value: OpenApiAuditEvent['risk_tier']) => {
  if (value === 'low' || value === 'medium' || value === 'high') {
    return value;
  }

  return 'medium';
};

export const buildTemplateDraftFromAuditEvent = (input: {
  selectedEvent: OpenApiAuditEvent;
  allEvents: OpenApiAuditEvent[];
  traits: AuditTemplateTraitSelection;
}): TemplateDraftRouteState | null => {
  const selectedMethod = getMethodFromEvent(input.selectedEvent);
  const selectedHost = getHostFromEvent(input.selectedEvent);
  const selectedPath = getPathFromEvent(input.selectedEvent);
  if (!selectedMethod || !selectedHost || !selectedPath) {
    return null;
  }

  const matchingEvents = collectMatchingFailingEvents(input.selectedEvent, input.allEvents);
  const allHosts = [...new Set(matchingEvents.map(event => getHostFromEvent(event)).filter(Boolean) as string[])];
  const pathCandidates = matchingEvents.map(event => getPathFromEvent(event)).filter(Boolean) as string[];
  const suggestedPathPattern = buildPathPatternSuggestion(pathCandidates);
  const canonicalDescriptor = input.selectedEvent.canonical_descriptor;

  const groupIdSeed =
    (input.traits.includeActionGroup ? canonicalDescriptor?.matched_path_group_id || input.selectedEvent.action_group : '') ||
    'group_1';
  const groupId = normalizeTemplateIdSuffix(groupIdSeed) || 'group_1';
  const provider = inferProviderFromHost(selectedHost);
  const templateName = `${provider} ${groupId}`.replace(/_/g, ' ');
  const templateIdSuffix =
    normalizeTemplateIdSuffix(`${provider}_${groupId}`) || normalizeTemplateIdSuffix(`${provider}_template`);
  const riskTier = input.traits.includeRiskTier ? toRiskTier(input.selectedEvent.risk_tier) : 'medium';

  return {
    templateDraft: {
      source: 'audit',
      provider,
      template_name: templateName,
      template_id_suffix: templateIdSuffix,
      description: `Drafted from audit event ${input.selectedEvent.event_id}`,
      allowed_hosts:
        input.traits.includeAllObservedHosts && allHosts.length > 0 ? allHosts : [selectedHost],
      path_groups: [
        {
          group_id: groupId,
          risk_tier: riskTier,
          approval_mode: riskTier === 'high' ? 'required' : 'none',
          methods: [selectedMethod],
          path_patterns: [
            input.traits.useSuggestedPathPattern ? suggestedPathPattern : `^${escapeRegExp(selectedPath)}$`
          ],
          query_allowlist: input.traits.includeQueryKeys ? (canonicalDescriptor?.query_keys ?? []) : [],
          header_forward_allowlist: input.traits.includeNormalizedHeaders
            ? [...new Set((canonicalDescriptor?.normalized_headers ?? []).map(header => header.name))]
            : [],
          max_body_bytes: 262144,
          content_types: ['application/json']
        }
      ]
    }
  };
};
