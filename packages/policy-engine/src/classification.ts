import {
  CanonicalRequestDescriptorSchema,
  type Template
} from '@broker-interceptor/schemas'

import {
  BuildCanonicalDescriptorInputSchema,
  BuildCanonicalDescriptorResultSchema,
  ClassifyPathGroupInputSchema,
  PathGroupClassificationResultSchema,
  type BuildCanonicalDescriptorInput,
  type BuildCanonicalDescriptorResult,
  type ClassifyPathGroupInput,
  type PathGroupClassificationResult
} from './contracts'

type CanonicalMethod = ReturnType<typeof parseCanonicalMethod>

type CompiledPathPattern = {
  source: string
  regex: RegExp
}

type CompiledPathGroup = {
  group_id: string
  risk_tier: 'low' | 'medium' | 'high'
  approval_mode: 'none' | 'required'
  methods: Set<CanonicalMethod>
  patterns: CompiledPathPattern[]
}

type CompiledPathGroupsResult =
  | {
      ok: true
      groups: CompiledPathGroup[]
    }
  | {
      ok: false
      reason_code: 'invalid_path_pattern'
    }

const isAnchoredRegex = (pattern: string) => pattern.startsWith('^') && pattern.endsWith('$')

const parseCanonicalMethod = (method: string) =>
  CanonicalRequestDescriptorSchema.shape.method.parse(method)

const parseCanonicalUrl = (canonicalUrl: string) => {
  const parsedUrl = new URL(canonicalUrl)
  return {
    host: parsedUrl.hostname.toLowerCase(),
    path: parsedUrl.pathname
  }
}

const compilePathGroups = (template: Template): CompiledPathGroupsResult => {
  const compiledGroups: CompiledPathGroup[] = []
  for (const pathGroup of template.path_groups) {
    const compiledPatterns: CompiledPathPattern[] = []
    for (const pattern of pathGroup.path_patterns) {
      if (!isAnchoredRegex(pattern)) {
        return {ok: false, reason_code: 'invalid_path_pattern'}
      }

      let regex: RegExp
      try {
        // eslint-disable-next-line security/detect-non-literal-regexp -- pattern is anchored and validated at template boundary
        regex = new RegExp(pattern, 'u')
      } catch {
        return {ok: false, reason_code: 'invalid_path_pattern'}
      }

      compiledPatterns.push({source: pattern, regex})
    }

    compiledGroups.push({
      group_id: pathGroup.group_id,
      risk_tier: pathGroup.risk_tier,
      approval_mode: pathGroup.approval_mode,
      methods: new Set(pathGroup.methods.map(parseCanonicalMethod)),
      patterns: compiledPatterns
    })
  }

  return {
    ok: true,
    groups: compiledGroups
  }
}

export const classifyPathGroup = (rawInput: ClassifyPathGroupInput): PathGroupClassificationResult => {
  const input = ClassifyPathGroupInputSchema.parse(rawInput)
  const method = parseCanonicalMethod(input.method)
  const {host, path} = parseCanonicalUrl(input.canonical_url)
  const allowedHosts = new Set(input.template.allowed_hosts.map(allowedHost => allowedHost.toLowerCase()))

  if (!allowedHosts.has(host)) {
    return PathGroupClassificationResultSchema.parse({
      matched: false,
      reason_code: 'no_matching_group'
    })
  }

  const compiledGroupsResult = compilePathGroups(input.template)
  if (!compiledGroupsResult.ok) {
    return PathGroupClassificationResultSchema.parse({
      matched: false,
      reason_code: 'invalid_path_pattern'
    })
  }

  for (const compiledGroup of compiledGroupsResult.groups) {
    if (!compiledGroup.methods.has(method)) {
      continue
    }

    for (const compiledPattern of compiledGroup.patterns) {
      if (compiledPattern.regex.test(path)) {
        return PathGroupClassificationResultSchema.parse({
          matched: true,
          path_group: {
            group_id: compiledGroup.group_id,
            risk_tier: compiledGroup.risk_tier,
            approval_mode: compiledGroup.approval_mode,
            matched_pattern: compiledPattern.source
          }
        })
      }
    }
  }

  return PathGroupClassificationResultSchema.parse({
    matched: false,
    reason_code: 'no_matching_group'
  })
}

export const buildCanonicalDescriptorWithPathGroup = (
  rawInput: BuildCanonicalDescriptorInput
): BuildCanonicalDescriptorResult => {
  const input = BuildCanonicalDescriptorInputSchema.parse(rawInput)
  const classification = classifyPathGroup({
    template: input.template,
    method: input.descriptor.method,
    canonical_url: input.descriptor.canonical_url
  })

  if (!classification.matched) {
    return BuildCanonicalDescriptorResultSchema.parse({
      ok: false,
      reason_code: classification.reason_code
    })
  }

  const descriptor = CanonicalRequestDescriptorSchema.parse({
    ...input.descriptor,
    matched_path_group_id: classification.path_group.group_id
  })

  return BuildCanonicalDescriptorResultSchema.parse({
    ok: true,
    descriptor,
    path_group: classification.path_group
  })
}
