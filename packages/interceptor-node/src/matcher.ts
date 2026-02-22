/**
 * URL matching against manifest rules.
 *
 * This module determines which outgoing requests should be intercepted
 * and routed through the broker.
 */

import type {MatchRule, ParsedManifest} from './types.js';

/**
 * Details about why a rule didn't match.
 */
export interface RuleMismatchDetail {
  ruleIndex: number;
  integrationId: string;
  mismatches: string[];
}

/**
 * Result of matching a URL against the manifest.
 */
export type MatchResult =
  | {matched: true; rule: MatchRule; integrationId: string}
  | {matched: false; details?: RuleMismatchDetail[]};

/**
 * Parse a URL into components for matching.
 */
function parseUrl(url: string | URL): {
  scheme: string;
  host: string;
  port: number;
  path: string;
} {
  const parsed = typeof url === 'string' ? new URL(url) : url;

  // Extract scheme without trailing colon
  const scheme = parsed.protocol.replace(':', '');

  // Determine port (use default if not specified)
  let port: number;
  if (parsed.port) {
    port = parseInt(parsed.port, 10);
  } else if (scheme === 'https') {
    port = 443;
  } else if (scheme === 'http') {
    port = 80;
  } else {
    port = 0;
  }

  return {
    scheme,
    host: parsed.hostname,
    port,
    path: parsed.pathname
  };
}

/**
 * Check if a host matches a pattern.
 *
 * Supports exact matches and wildcard subdomains (e.g., *.openai.com).
 */
function hostMatches(actualHost: string, pattern: string): boolean {
  // Exact match
  if (actualHost === pattern) {
    return true;
  }

  // Wildcard subdomain match (e.g., *.openai.com matches api.openai.com)
  if (pattern.startsWith('*.')) {
    const baseDomain = pattern.slice(2); // Remove "*."
    // Check if actualHost ends with .baseDomain or equals baseDomain
    if (actualHost === baseDomain || actualHost.endsWith(`.${baseDomain}`)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a path matches any of the path group patterns.
 *
 * Supports:
 * - Regex patterns (e.g., ^/v1/chat/completions$)
 * - Glob-like patterns (e.g., /v1/*, *)
 * - Exact paths (e.g., /v1/chat/completions)
 */
function pathMatchesGroups(actualPath: string, pathGroups: string[]): boolean {
  for (const pattern of pathGroups) {
    // Regex pattern (starts with ^)
    if (pattern.startsWith('^')) {
      try {
        // eslint-disable-next-line security/detect-non-literal-regexp -- pattern comes from signed manifest
        const regex = new RegExp(pattern);
        if (regex.test(actualPath)) {
          return true;
        }
      } catch {
        // Invalid regex, skip
      }
      continue;
    }

    // Wildcard matching all paths
    if (pattern === '*' || pattern === '/*') {
      return true;
    }

    // Glob-like suffix wildcard (e.g., /v1/*)
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      if (actualPath.startsWith(prefix)) {
        return true;
      }
      continue;
    }

    // Exact match or path prefix
    if (actualPath === pattern || actualPath.startsWith(pattern + '/')) {
      return true;
    }
  }

  return false;
}

/**
 * Match a URL against a specific rule and return mismatches if any.
 */
function matchesRuleWithDetails(
  scheme: string,
  host: string,
  port: number,
  path: string,
  rule: MatchRule
): {matches: true} | {matches: false; mismatches: string[]} {
  const mismatches: string[] = [];

  // Check scheme
  if (!rule.match.schemes.includes(scheme as 'https')) {
    mismatches.push(`scheme '${scheme}' not in [${rule.match.schemes.join(', ')}]`);
  }

  // Check port
  if (!rule.match.ports.includes(port)) {
    mismatches.push(`port ${port} not in [${rule.match.ports.join(', ')}]`);
  }

  // Check host
  const hostMatch = rule.match.hosts.some(h => hostMatches(host, h));
  if (!hostMatch) {
    mismatches.push(`host '${host}' not matching [${rule.match.hosts.join(', ')}, ${host}]`);
  }

  // Check path groups
  if (!pathMatchesGroups(path, rule.match.path_groups)) {
    mismatches.push(`path '${path}' not matching [${rule.match.path_groups.join(', ')}]`);
  }

  if (mismatches.length === 0) {
    return {matches: true};
  }

  return {matches: false, mismatches};
}

/**
 * Match a URL against the manifest rules.
 *
 * Returns the first matching rule's integration_id, or details about why each rule didn't match.
 */
export function matchUrl(url: string | URL, manifest: ParsedManifest): MatchResult {
  const {scheme, host, port, path} = parseUrl(url);

  const mismatchDetails: RuleMismatchDetail[] = [];

  let ruleIndex = 0;
  for (const rule of manifest.match_rules) {
    const result = matchesRuleWithDetails(scheme, host, port, path, rule);

    if (result.matches) {
      return {
        matched: true,
        rule,
        integrationId: rule.integration_id
      };
    }

    mismatchDetails.push({
      ruleIndex,
      integrationId: rule.integration_id,
      mismatches: result.mismatches
    });

    ruleIndex++;
  }

  return {matched: false, details: mismatchDetails};
}

/**
 * Check if any URL in a list should be intercepted.
 */
export function shouldIntercept(url: string | URL, manifest: ParsedManifest | null): boolean {
  if (!manifest) {
    return false;
  }

  return matchUrl(url, manifest).matched;
}
