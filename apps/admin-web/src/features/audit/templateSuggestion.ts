import type {OpenApiAuditEvent} from '@broker-interceptor/schemas';

import type {TemplateDraftRouteState} from '../templates/templateDraftRoute';
import {normalizeTemplateIdSuffix} from '../templates/templateHelpers';

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

const inferAuditUpstreamAuth = (event: OpenApiAuditEvent) => {
  const host = getHostFromEvent(event)?.toLowerCase() ?? '';
  const queryKeys = new Set(event.canonical_descriptor?.query_keys ?? []);
  const templateId = event.canonical_descriptor?.template_id?.toLowerCase() ?? '';

  const looksLikeS3 =
    queryKeys.has('list-type') ||
    host.includes('storjshare.io') ||
    host.includes('amazonaws.com') ||
    host.includes('backblazeb2.com') ||
    host.startsWith('s3.') ||
    host.includes('.s3.') ||
    templateId.includes('storj') ||
    templateId.includes('s3');

  return looksLikeS3
    ? {
        type: 'aws_sigv4' as const,
        region: ''
      }
    : {
        type: 'none' as const
      };
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
  const matchedTemplateConfig = input.selectedEvent.matched_template_config;

  const groupIdSeed =
    (input.traits.includeActionGroup
      ? matchedTemplateConfig?.path_group_id ||
        canonicalDescriptor?.matched_path_group_id ||
        input.selectedEvent.action_group
      : '') ||
    'group_1';
  const groupId = normalizeTemplateIdSuffix(groupIdSeed) || 'group_1';
  const provider = inferProviderFromHost(selectedHost);
  const templateName = `${provider} ${groupId}`.replace(/_/g, ' ');
  const templateIdSuffix =
    normalizeTemplateIdSuffix(`${provider}_${groupId}`) || normalizeTemplateIdSuffix(`${provider}_template`);
  const riskTier = input.traits.includeRiskTier
    ? matchedTemplateConfig?.risk_tier ?? toRiskTier(input.selectedEvent.risk_tier)
    : 'medium';
  const approvalMode = matchedTemplateConfig?.approval_mode ?? (riskTier === 'high' ? 'required' : 'none');
  const upstreamAuth =
    matchedTemplateConfig?.constraints?.upstream_auth
      ? {
          type: 'aws_sigv4' as const,
          region: matchedTemplateConfig.constraints.upstream_auth.region ?? ''
        }
      : inferAuditUpstreamAuth(input.selectedEvent);
  const contentTypes =
    matchedTemplateConfig?.body_policy.content_types ??
    (selectedMethod === 'GET' || selectedMethod === 'DELETE'
      ? []
      : upstreamAuth.type === 'aws_sigv4'
        ? ['application/octet-stream']
        : ['application/json']);
  const maxBodyBytes =
    matchedTemplateConfig?.body_policy.max_bytes ??
    (selectedMethod === 'GET' || selectedMethod === 'DELETE' ? 0 : 262144);
  const methods = matchedTemplateConfig?.methods ?? [selectedMethod];
  const pathPatterns = input.traits.useSuggestedPathPattern
    ? [suggestedPathPattern]
    : matchedTemplateConfig?.path_patterns ?? [`^${escapeRegExp(selectedPath)}$`];
  const queryAllowlist = input.traits.includeQueryKeys
    ? matchedTemplateConfig?.query_allowlist ?? (canonicalDescriptor?.query_keys ?? [])
    : [];
  const headerForwardAllowlist = input.traits.includeNormalizedHeaders
    ? matchedTemplateConfig?.header_forward_allowlist ??
      [...new Set((canonicalDescriptor?.normalized_headers ?? []).map(header => header.name))]
    : [];

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
          approval_mode: approvalMode,
          methods,
          path_patterns: pathPatterns,
          query_allowlist: queryAllowlist,
          header_forward_allowlist: headerForwardAllowlist,
          max_body_bytes: maxBodyBytes,
          content_types: contentTypes,
          upstream_auth: upstreamAuth
        }
      ]
    }
  };
};
