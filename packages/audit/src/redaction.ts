import crypto from 'node:crypto'

import {
  OpenApiAuditEventSchema,
  type OpenApiAuditEvent,
  type OpenApiCanonicalRequestDescriptor
} from '@broker-interceptor/schemas'

import {
  AuditRedactionProfileSchema,
  type RedactionAction,
  type AuditRedactionProfile,
  type AuditStructuredLogRecord
} from './contracts'

const REDACTED_VALUE = '[REDACTED]'
const TRUNCATED_SUFFIX = '...[TRUNCATED]'
const REDACTED_DEPTH_VALUE = '[REDACTED_DEPTH]'
const DEFAULT_REDACTION_PROFILE_ID = 'default_strict_v1'

const DEFAULT_SENSITIVE_KEY_PATTERNS = [
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'api[-_]?key',
  'secret',
  'token',
  'password',
  'set-cookie',
  'cookie',
  'private[-_]?key',
  'refresh[-_]?token',
  'client[-_]?secret',
  'bearer'
]

const DEFAULT_METADATA_ALLOW_KEYS = [
  'action',
  'actor_auth',
  'actor_roles',
  'actor_subject',
  'action_group',
  'correlation_id',
  'decision',
  'delivery_status',
  'event_type',
  'integration_id',
  'latency_ms',
  'reason_code',
  'risk_tier',
  'tenant_id',
  'upstream_status_code',
  'workload_id'
]

type CompiledRedactionProfile = {
  profile: AuditRedactionProfile
  metadataAllowKeys: Set<string>
  metadataActionsByKey: Map<string, RedactionAction>
  sensitiveMatchers: RegExp[]
}

type RedactUnknownInput = {
  value: unknown
  profile: CompiledRedactionProfile
  depth: number
}

const normalizeKey = (value: string) => value.trim().toLowerCase()

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const truncateString = (value: string, maxLength: number): string => {
  if (value.length <= maxLength) {
    return value
  }

  return `${value.slice(0, maxLength)}${TRUNCATED_SUFFIX}`
}

const stableSerialize = (value: unknown): string => {
  if (value === null) {
    return 'null'
  }

  if (typeof value === 'string') {
    return JSON.stringify(value)
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value)
  }

  if (Array.isArray(value)) {
    return `[${value.map(item => stableSerialize(item)).join(',')}]`
  }

  if (isRecord(value)) {
    const parts = Object.keys(value)
      .sort()
      .map(key => {
        // eslint-disable-next-line security/detect-object-injection -- Key is from current object keys and used for deterministic serialization.
        const nextValue = value[key]
        return `${JSON.stringify(key)}:${stableSerialize(nextValue)}`
      })
    return `{${parts.join(',')}}`
  }

  if (typeof value === 'bigint') {
    return value.toString(10)
  }

  if (typeof value === 'symbol') {
    return value.description ? `symbol:${value.description}` : 'symbol'
  }

  if (typeof value === 'undefined') {
    return 'undefined'
  }

  if (typeof value === 'function') {
    return '[function]'
  }

  return '[unsupported]'
}

const hashValue = ({
  value,
  salt
}: {
  value: unknown
  salt: string | undefined
}): string => {
  const hash = crypto.createHash('sha256')
  if (salt) {
    hash.update(salt)
  }
  hash.update(stableSerialize(value))
  return `sha256:${hash.digest('hex')}`
}

const applyAction = ({
  action,
  value,
  maxStringLength,
  hashSalt
}: {
  action: RedactionAction
  value: unknown
  maxStringLength: number
  hashSalt: string | undefined
}): unknown => {
  switch (action) {
    case 'keep':
      if (typeof value === 'string') {
        return truncateString(value, maxStringLength)
      }
      return value
    case 'mask':
      return REDACTED_VALUE
    case 'hash':
      return hashValue({value, salt: hashSalt})
    case 'drop':
      return undefined
    default:
      return REDACTED_VALUE
  }
}

const compileRedactionProfile = (profile: AuditRedactionProfile): CompiledRedactionProfile => ({
  profile,
  metadataAllowKeys: new Set(profile.rules.metadata_allow_keys.map(normalizeKey)),
  metadataActionsByKey: new Map(
    Object.entries(profile.rules.metadata_key_actions).map(([key, action]) => [normalizeKey(key), action])
  ),
  sensitiveMatchers: [...DEFAULT_SENSITIVE_KEY_PATTERNS, ...profile.rules.sensitive_key_patterns].map(pattern => {
    // eslint-disable-next-line security/detect-non-literal-regexp -- Pattern is validated and scoped to redaction matching.
    return new RegExp(pattern, 'iu')
  })
})

const isSensitiveKey = ({
  key,
  profile
}: {
  key: string
  profile: CompiledRedactionProfile
}): boolean => profile.sensitiveMatchers.some(regex => regex.test(key))

const resolveMetadataAction = ({
  key,
  profile
}: {
  key: string
  profile: CompiledRedactionProfile
}): RedactionAction => {
  const normalizedKey = normalizeKey(key)

  if (isSensitiveKey({key: normalizedKey, profile})) {
    return 'mask'
  }

  const configuredAction = profile.metadataActionsByKey.get(normalizedKey)
  if (configuredAction) {
    return configuredAction
  }

  if (profile.metadataAllowKeys.has(normalizedKey)) {
    return 'keep'
  }

  return profile.profile.rules.metadata_default_action
}

const redactUnknown = ({value, profile, depth}: RedactUnknownInput): unknown => {
  if (depth > profile.profile.rules.max_depth) {
    return REDACTED_DEPTH_VALUE
  }

  if (Array.isArray(value)) {
    const limited = value.slice(0, profile.profile.rules.max_collection_size)
    return limited.map(item => redactUnknown({value: item, profile, depth: depth + 1}))
  }

  if (isRecord(value)) {
    const redactedEntries: Record<string, unknown> = {}
    const entries = Object.entries(value).slice(0, profile.profile.rules.max_collection_size)

    for (const [key, entryValue] of entries) {
      const action = resolveMetadataAction({key, profile})
      const actionValue = applyAction({
        action,
        value: entryValue,
        maxStringLength: profile.profile.rules.max_string_length,
        hashSalt: profile.profile.rules.hash_salt
      })
      if (actionValue === undefined) {
        continue
      }

      if (action === 'keep') {
        // eslint-disable-next-line security/detect-object-injection -- Key comes from validated metadata object and is preserved for structured redaction output.
        redactedEntries[key] = redactUnknown({
          value: actionValue,
          profile,
          depth: depth + 1
        })
        continue
      }

      // eslint-disable-next-line security/detect-object-injection -- Key comes from validated metadata object and is preserved for structured redaction output.
      redactedEntries[key] = actionValue
    }

    return redactedEntries
  }

  return applyAction({
    action: 'keep',
    value,
    maxStringLength: profile.profile.rules.max_string_length,
    hashSalt: profile.profile.rules.hash_salt
  })
}

const redactStructuredUnknown = ({
  value,
  profile,
  depth
}: RedactUnknownInput): unknown => {
  if (depth > profile.profile.rules.max_depth) {
    return REDACTED_DEPTH_VALUE
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, profile.profile.rules.max_collection_size)
      .map(item => redactStructuredUnknown({value: item, profile, depth: depth + 1}))
  }

  if (isRecord(value)) {
    const redactedEntries: Record<string, unknown> = {}
    const entries = Object.entries(value).slice(0, profile.profile.rules.max_collection_size)

    for (const [key, entryValue] of entries) {
      const normalizedKey = normalizeKey(key)
      if (isSensitiveKey({key: normalizedKey, profile})) {
        // eslint-disable-next-line security/detect-object-injection -- Key comes from validated log payload object.
        redactedEntries[key] = REDACTED_VALUE
        continue
      }

      // eslint-disable-next-line security/detect-object-injection -- Key comes from validated log payload object.
      redactedEntries[key] = redactStructuredUnknown({
        value: entryValue,
        profile,
        depth: depth + 1
      })
    }

    return redactedEntries
  }

  if (typeof value === 'string') {
    return truncateString(value, profile.profile.rules.max_string_length)
  }

  return value
}

const redactMessage = ({
  message,
  profile
}: {
  message: string | null | undefined
  profile: CompiledRedactionProfile
}): string | null => {
  if (message === null || message === undefined) {
    return null
  }

  const redactedMessage = applyAction({
    action: profile.profile.rules.message_action,
    value: message,
    maxStringLength: profile.profile.rules.max_string_length,
    hashSalt: profile.profile.rules.hash_salt
  })

  if (redactedMessage === undefined) {
    return null
  }

  if (typeof redactedMessage === 'string') {
    return redactedMessage
  }

  return REDACTED_VALUE
}

const redactMetadata = ({
  metadata,
  profile
}: {
  metadata: Record<string, unknown> | null | undefined
  profile: CompiledRedactionProfile
}): Record<string, unknown> | null => {
  if (!metadata) {
    return null
  }

  const redacted = redactUnknown({value: metadata, profile, depth: 1})
  if (!isRecord(redacted)) {
    return null
  }

  if (Object.keys(redacted).length === 0) {
    return null
  }

  return redacted
}

const redactCanonicalDescriptor = ({
  descriptor,
  profile
}: {
  descriptor: OpenApiCanonicalRequestDescriptor | null | undefined
  profile: CompiledRedactionProfile
}): OpenApiCanonicalRequestDescriptor | null => {
  if (!descriptor) {
    return null
  }

  const normalized_headers = descriptor.normalized_headers.flatMap(header => {
    const isSensitiveHeader = isSensitiveKey({
      key: normalizeKey(header.name),
      profile
    })
    const action = isSensitiveHeader ? 'mask' : profile.profile.rules.canonical_header_value_action
    const redactedValue = applyAction({
      action,
      value: header.value,
      maxStringLength: profile.profile.rules.max_string_length,
      hashSalt: profile.profile.rules.hash_salt
    }) as string | undefined

    if (redactedValue === undefined) {
      return []
    }

    return [{name: header.name, value: redactedValue}]
  })

  return {
    ...descriptor,
    normalized_headers
  }
}

const redactPolicy = ({
  policy,
  profile
}: {
  policy: OpenApiAuditEvent['policy']
  profile: CompiledRedactionProfile
}): OpenApiAuditEvent['policy'] => {
  if (!policy) {
    return null
  }

  const action = profile.profile.rules.policy_identifier_action
  const redactIdentifier = (value: string | null | undefined): string | null => {
    if (value === null || value === undefined) {
      return null
    }
    const redactedValue = applyAction({
      action,
      value,
      maxStringLength: profile.profile.rules.max_string_length,
      hashSalt: profile.profile.rules.hash_salt
    }) as string | undefined
    if (redactedValue === undefined) {
      return null
    }
    return redactedValue
  }

  return {
    ...policy,
    rule_id: redactIdentifier(policy.rule_id),
    approval_id: redactIdentifier(policy.approval_id)
  }
}

export const createDefaultAuditRedactionProfile = ({
  tenant_id
}: {
  tenant_id: string
}): AuditRedactionProfile =>
  AuditRedactionProfileSchema.parse({
    tenant_id,
    profile_id: DEFAULT_REDACTION_PROFILE_ID,
    rules: {
      message_action: 'mask',
      metadata_default_action: 'mask',
      metadata_key_actions: {},
      metadata_allow_keys: DEFAULT_METADATA_ALLOW_KEYS,
      sensitive_key_patterns: DEFAULT_SENSITIVE_KEY_PATTERNS,
      canonical_header_value_action: 'mask',
      policy_identifier_action: 'mask',
      max_depth: 5,
      max_collection_size: 100,
      max_string_length: 512
    }
  })

export const redactAuditEvent = ({
  event,
  profile
}: {
  event: OpenApiAuditEvent
  profile: AuditRedactionProfile
}): OpenApiAuditEvent => {
  const parsedEvent = OpenApiAuditEventSchema.parse(event)
  const parsedProfile = AuditRedactionProfileSchema.parse(profile)
  const compiledProfile = compileRedactionProfile(parsedProfile)

  const redacted = OpenApiAuditEventSchema.parse({
    ...parsedEvent,
    message: redactMessage({
      message: parsedEvent.message,
      profile: compiledProfile
    }),
    metadata: redactMetadata({
      metadata: parsedEvent.metadata,
      profile: compiledProfile
    }),
    canonical_descriptor: redactCanonicalDescriptor({
      descriptor: parsedEvent.canonical_descriptor,
      profile: compiledProfile
    }),
    policy: redactPolicy({
      policy: parsedEvent.policy,
      profile: compiledProfile
    })
  })

  return redacted
}

export const redactStructuredLogPayload = ({
  payload,
  profile
}: {
  payload: unknown
  profile: AuditRedactionProfile
}): unknown => {
  const parsedProfile = AuditRedactionProfileSchema.parse(profile)
  const compiledProfile = compileRedactionProfile(parsedProfile)
  return redactStructuredUnknown({
    value: payload,
    profile: compiledProfile,
    depth: 1
  })
}

export const toStructuredAuditLogRecord = ({
  event,
  delivery_status
}: {
  event: OpenApiAuditEvent
  delivery_status: 'stored'
}): AuditStructuredLogRecord =>
  ({
    message: 'audit.event',
    delivery_status,
    event_id: event.event_id,
    tenant_id: event.tenant_id,
    workload_id: event.workload_id ?? null,
    integration_id: event.integration_id ?? null,
    correlation_id: event.correlation_id,
    event_type: event.event_type,
    decision: event.decision ?? null,
    action_group: event.action_group ?? null,
    risk_tier: event.risk_tier ?? null,
    upstream_status_code: event.upstream_status_code ?? null,
    latency_ms: event.latency_ms ?? null
  }) satisfies AuditStructuredLogRecord
