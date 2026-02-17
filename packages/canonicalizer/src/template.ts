import {isIP} from 'node:net';
import {domainToASCII} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {z} from 'zod';

import type {HttpMethodContract, TemplateContract, TemplatePathGroupContract} from './contracts';
import {TemplateSchema} from './contracts';
import {err, ok, type CanonicalizerResult} from './errors';

const HTTP_HEADER_NAME_REGEX = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FORBIDDEN_BROAD_PATH_PATTERNS = new Set(['.*', '^.*$', '^/.*$']);
const UNSAFE_PATTERN_DETECTORS = [
  /\(\?[=!<]/u, // lookarounds
  /\\[1-9]/u, // backreferences
  /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/u, // nested quantified groups
  /(?:\.\*){2,}/u // repeated wildcard quantifiers
];

const DuplicateQueryKeysConstraintSchema = z
  .object({
    allow_duplicate_query_keys: z.union([z.boolean(), z.array(z.string())]).optional()
  })
  .loose();

export type DuplicateQueryPolicy =
  | {mode: 'none'}
  | {mode: 'all'}
  | {mode: 'allowlist'; keys: Set<string>};

export type CompiledPathGroup = {
  group: TemplatePathGroupContract;
  methods: Set<HttpMethodContract>;
  pathPatterns: RegExp[];
  queryAllowlist: Set<string>;
  headerAllowlist: Set<string>;
  duplicateQueryPolicy: DuplicateQueryPolicy;
};

export type CompiledTemplate = {
  template: TemplateContract;
  allowedSchemes: Set<string>;
  allowedPorts: Set<number>;
  allowedHosts: Set<string>;
  pathGroups: CompiledPathGroup[];
};

export type ValidateTemplatePublishInput = {
  candidate: unknown;
  existing_templates: unknown[];
};

const normalizeHost = (host: string): string | null => {
  const lowered = host.trim().toLowerCase();
  if (lowered.length === 0) {
    return null;
  }

  if (lowered.startsWith('[') && lowered.endsWith(']')) {
    const ipv6Literal = lowered.slice(1, -1);
    if (isIP(ipv6Literal) !== 6) {
      return null;
    }
    return `[${ipv6Literal}]`;
  }

  const withoutTrailingDot = lowered.endsWith('.') ? lowered.slice(0, -1) : lowered;
  if (withoutTrailingDot.length === 0) {
    return null;
  }

  const ascii = domainToASCII(withoutTrailingDot);
  if (ascii.length === 0) {
    return null;
  }

  return ascii.toLowerCase();
};

const parseDuplicateQueryPolicy = (constraints: unknown): DuplicateQueryPolicy => {
  const parsed = DuplicateQueryKeysConstraintSchema.safeParse(constraints);
  if (!parsed.success || parsed.data.allow_duplicate_query_keys === undefined) {
    return {mode: 'none'};
  }

  const policy = parsed.data.allow_duplicate_query_keys;
  if (policy === true) {
    return {mode: 'all'};
  }

  if (policy === false) {
    return {mode: 'none'};
  }

  return {mode: 'allowlist', keys: new Set(policy)};
};

const compilePathPattern = (pattern: string): CanonicalizerResult<RegExp> => {
  if (!pattern.startsWith('^') || !pattern.endsWith('$')) {
    return err('template_path_pattern_unanchored', `Path pattern must be anchored with ^ and $: ${pattern}`);
  }

  if (FORBIDDEN_BROAD_PATH_PATTERNS.has(pattern)) {
    return err('template_path_pattern_overbroad', `Overbroad path pattern is not allowed: ${pattern}`);
  }

  if (UNSAFE_PATTERN_DETECTORS.some(detector => detector.test(pattern))) {
    return err('template_path_pattern_unsafe', `Potentially unsafe regex pattern is not allowed: ${pattern}`);
  }

  try {
    // eslint-disable-next-line security/detect-non-literal-regexp -- patterns come from template configuration and are validated here.
    return ok(new RegExp(pattern, 'u'));
  } catch {
    return err('template_path_pattern_invalid', `Path pattern is not a valid regular expression: ${pattern}`);
  }
};

const toUniqueSet = <T>(values: ReadonlyArray<T>) => new Set(values);

export const compileCanonicalizerTemplate = (templateInput: unknown): CanonicalizerResult<CompiledTemplate> => {
  const parsedTemplate = TemplateSchema.safeParse(templateInput);
  if (!parsedTemplate.success) {
    return err('invalid_template', parsedTemplate.error.message);
  }

  const template = parsedTemplate.data;
  const normalizedSchemes = template.allowed_schemes.map(item => item.toLowerCase());
  const allowedSchemes = toUniqueSet(normalizedSchemes);
  if (allowedSchemes.size !== normalizedSchemes.length) {
    return err('template_allowlist_duplicate', 'Template allowed_schemes contains duplicates');
  }

  const normalizedPorts = template.allowed_ports.map(port => Number(port));
  const allowedPorts = toUniqueSet(normalizedPorts);
  if (allowedPorts.size !== normalizedPorts.length) {
    return err('template_allowlist_duplicate', 'Template allowed_ports contains duplicates');
  }
  const allowedHosts = new Set<string>();

  for (const host of template.allowed_hosts) {
    if (host.includes('*')) {
      return err('template_host_wildcard_forbidden', `Wildcard host allowlists are forbidden: ${host}`);
    }

    const normalizedHost = normalizeHost(host);
    if (!normalizedHost) {
      return err('template_host_invalid', `Template host is invalid: ${host}`);
    }

    if (allowedHosts.has(normalizedHost)) {
      return err('template_allowlist_duplicate', `Template host allowlist contains duplicates: ${host}`);
    }

    allowedHosts.add(normalizedHost);
  }

  const seenGroupIds = new Set<string>();
  const compiledGroups: CompiledPathGroup[] = [];

  for (const group of template.path_groups) {
    if (seenGroupIds.has(group.group_id)) {
      return err('template_group_duplicate', `Template contains duplicate path group id: ${group.group_id}`);
    }
    seenGroupIds.add(group.group_id);

    const methodSet = toUniqueSet(group.methods);
    if (methodSet.size !== group.methods.length) {
      return err('template_allowlist_duplicate', `Path group has duplicate methods: ${group.group_id}`);
    }

    const pathPatterns: RegExp[] = [];
    for (const pattern of group.path_patterns) {
      const compiledPattern = compilePathPattern(pattern);
      if (!compiledPattern.ok) {
        return compiledPattern;
      }
      pathPatterns.push(compiledPattern.value);
    }

    const queryAllowlist = toUniqueSet(group.query_allowlist);
    if (queryAllowlist.size !== group.query_allowlist.length) {
      return err('template_allowlist_duplicate', `Path group has duplicate query keys: ${group.group_id}`);
    }

    const headerAllowlist = toUniqueSet(group.header_forward_allowlist.map(header => header.trim().toLowerCase()));
    if (headerAllowlist.size !== group.header_forward_allowlist.length) {
      return err(
        'template_allowlist_duplicate',
        `Path group has duplicate header allowlist entries: ${group.group_id}`
      );
    }

    for (const headerName of headerAllowlist) {
      if (!HTTP_HEADER_NAME_REGEX.test(headerName)) {
        return err('template_header_allowlist_invalid', `Invalid header allowlist entry: ${headerName}`);
      }
    }

    compiledGroups.push({
      group,
      methods: methodSet,
      pathPatterns,
      queryAllowlist,
      headerAllowlist,
      duplicateQueryPolicy: parseDuplicateQueryPolicy(group.constraints)
    });
  }

  return ok({
    template,
    allowedSchemes,
    allowedPorts,
    allowedHosts,
    pathGroups: compiledGroups
  });
};

export const validateTemplateForUpload = (templateInput: unknown): CanonicalizerResult<TemplateContract> => {
  const compiled = compileCanonicalizerTemplate(templateInput);
  if (!compiled.ok) {
    return compiled;
  }

  return ok(compiled.value.template);
};

export const validateTemplatePublish = ({
  candidate,
  existing_templates: existingTemplates
}: ValidateTemplatePublishInput): CanonicalizerResult<TemplateContract> => {
  const compiledCandidate = compileCanonicalizerTemplate(candidate);
  if (!compiledCandidate.ok) {
    return compiledCandidate;
  }

  const parsedExistingTemplates: TemplateContract[] = [];
  for (const existingTemplate of existingTemplates) {
    const compiled = compileCanonicalizerTemplate(existingTemplate);
    if (!compiled.ok) {
      return compiled;
    }
    parsedExistingTemplates.push(compiled.value.template);
  }

  const candidateTemplate = compiledCandidate.value.template;
  const sameTemplateId = parsedExistingTemplates.filter(item => item.template_id === candidateTemplate.template_id);
  if (sameTemplateId.length === 0) {
    return ok(candidateTemplate);
  }

  const providerMismatch = sameTemplateId.some(item => item.provider !== candidateTemplate.provider);
  if (providerMismatch) {
    return err(
      'template_provider_mismatch',
      `Template ${candidateTemplate.template_id} cannot change provider across versions`
    );
  }

  const sameVersion = sameTemplateId.find(item => item.version === candidateTemplate.version);
  if (sameVersion) {
    if (isDeepStrictEqual(sameVersion, candidateTemplate)) {
      return err(
        'template_version_conflict',
        `Template ${candidateTemplate.template_id} version ${candidateTemplate.version} already exists`
      );
    }

    return err(
      'template_version_immutable',
      `Template ${candidateTemplate.template_id} version ${candidateTemplate.version} is immutable once published`
    );
  }

  const highestVersion = sameTemplateId.reduce(
    (maxVersion, item) => (item.version > maxVersion ? item.version : maxVersion),
    0
  );
  if (candidateTemplate.version <= highestVersion) {
    return err(
      'template_version_not_incremented',
      `Template ${candidateTemplate.template_id} version must be greater than ${highestVersion}`
    );
  }

  return ok(candidateTemplate);
};

export const selectMatchingPathGroup = ({
  compiledTemplate,
  method,
  normalizedPath
}: {
  compiledTemplate: CompiledTemplate;
  method: HttpMethodContract;
  normalizedPath: string;
}): CompiledPathGroup | null =>
  compiledTemplate.pathGroups.find(
    group => group.methods.has(method) && group.pathPatterns.some(pattern => pattern.test(normalizedPath))
  ) ?? null;

export const normalizeTemplateHost = normalizeHost;
