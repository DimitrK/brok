/**
 * Shared matching primitives for manifest rules and local interceptor overrides.
 */

export interface MatchScope {
  hosts: string[];
  schemes: string[];
  ports: number[];
  path_groups: string[];
}

export function parseUrlForMatching(url: string | URL): {
  scheme: string;
  host: string;
  port: number;
  path: string;
} {
  const parsed = typeof url === 'string' ? new URL(url) : url;

  const scheme = parsed.protocol.replace(':', '');

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

export function hostMatches(actualHost: string, pattern: string): boolean {
  return actualHost === pattern;
}

export function isRegexPattern(pattern: string): boolean {
  return pattern.startsWith('^');
}

export function validateHostPattern(host: string): string | null {
  if (host.includes('*')) {
    return 'wildcard hosts are not supported';
  }

  return null;
}

export function validatePathGroupPattern(pattern: string): string | null {
  if (isRegexPattern(pattern)) {
    if (!pattern.endsWith('$')) {
      return 'regex path pattern must be anchored with $';
    }

    if (/(^|[^\\])\/\*/.test(pattern)) {
      return 'regex path pattern uses /* which behaves as a regex quantifier; use /v1/* prefix pattern or ^/v1/.*$';
    }

    try {
      // eslint-disable-next-line security/detect-non-literal-regexp -- validated before use
      new RegExp(pattern);
    } catch {
      return 'regex path pattern is invalid';
    }

    return null;
  }

  if (pattern.endsWith('/*')) {
    if (!pattern.startsWith('/')) {
      return 'prefix path pattern must start with /';
    }
    if (pattern.length < 3) {
      return 'prefix path pattern must contain a non-root prefix';
    }
    return null;
  }

  if (!pattern.startsWith('/')) {
    return 'exact path pattern must start with /';
  }

  if (pattern.includes('*')) {
    return 'wildcards are only allowed as suffix /*';
  }

  return null;
}

export function pathMatchesGroups(actualPath: string, pathGroups: string[]): boolean {
  for (const pattern of pathGroups) {
    if (isRegexPattern(pattern)) {
      // eslint-disable-next-line security/detect-non-literal-regexp -- pattern validated during manifest/config load
      const regex = new RegExp(pattern);
      if (regex.test(actualPath)) {
        return true;
      }
      continue;
    }

    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -1);
      if (actualPath.startsWith(prefix)) {
        return true;
      }
      continue;
    }

    if (actualPath === pattern) {
      return true;
    }
  }

  return false;
}

export function scopeMatchesUrl(url: string | URL, scope: MatchScope): boolean {
  const {scheme, host, port, path} = parseUrlForMatching(url);

  if (!scope.schemes.includes(scheme)) {
    return false;
  }

  if (!scope.ports.includes(port)) {
    return false;
  }

  if (!scope.hosts.some(pattern => hostMatches(host, pattern))) {
    return false;
  }

  return pathMatchesGroups(path, scope.path_groups);
}
