import {manifestRuleMatchesUrl, matchUrl} from './matcher.js';
import {scopeMatchesUrl} from './match-patterns.js';
import type {RuleMismatchDetail} from './matcher.js';
import type {IntegrationOverride, MatchRule, ParsedManifest} from './types.js';

export type IntegrationSelectionResult =
  | {matched: true; integrationId: string; rule: MatchRule; source: 'manifest' | 'override'}
  | {matched: false; source: 'none'; details?: RuleMismatchDetail[]}
  | {matched: false; source: 'override'; error: string};

export function validateIntegrationOverridesAgainstManifest(
  overrides: IntegrationOverride[] | undefined,
  manifest: ParsedManifest
): {ok: true} | {ok: false; error: string} {
  if (!overrides || overrides.length === 0) {
    return {ok: true};
  }

  for (const [overrideIndex, override] of overrides.entries()) {
    const hasIntegration = manifest.match_rules.some(rule => rule.integration_id === override.integrationId);
    if (!hasIntegration) {
      return {
        ok: false,
        error: `integrationOverrides[${overrideIndex}] references unknown integration_id '${override.integrationId}'`
      };
    }
  }

  return {ok: true};
}

export function resolveInterceptionTarget(
  url: string | URL,
  manifest: ParsedManifest,
  overrides: IntegrationOverride[] | undefined
): IntegrationSelectionResult {
  // Routing is intentionally credential-agnostic. Selection depends only on
  // manifest match scope and an explicit integration override, never on
  // provider strings or future runtime-auth metadata.
  const matchingOverrides = (overrides ?? []).filter(override => scopeMatchesUrl(url, override.match));

  if (matchingOverrides.length > 1) {
    return {
      matched: false,
      source: 'override',
      error: `Multiple integration overrides matched request: [${matchingOverrides.map(override => override.integrationId).join(', ')}]`
    };
  }

  if (matchingOverrides.length === 1) {
    const selectedOverride = matchingOverrides[0];
    const overrideRule = manifest.match_rules.find(
      rule => rule.integration_id === selectedOverride.integrationId && manifestRuleMatchesUrl(url, rule)
    );

    if (!overrideRule) {
      return {
        matched: false,
        source: 'override',
        error: `Integration override '${selectedOverride.integrationId}' matched request scope but no manifest rule matched that integration for the request`
      };
    }

    return {
      matched: true,
      integrationId: selectedOverride.integrationId,
      rule: overrideRule,
      source: 'override'
    };
  }

  const manifestResult = matchUrl(url, manifest);
  if (!manifestResult.matched) {
    return {
      matched: false,
      source: 'none',
      details: manifestResult.details
    };
  }

  return {
    matched: true,
    integrationId: manifestResult.integrationId,
    rule: manifestResult.rule,
    source: 'manifest'
  };
}
