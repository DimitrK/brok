import {describe, expect, it} from 'vitest'

import {AuditRedactionProfileSchema} from '../contracts'
import {
  createDefaultAuditRedactionProfile,
  redactAuditEvent,
  redactStructuredLogPayload
} from '../redaction'
import {buildAuditEvent} from './fixtures'

describe('redactAuditEvent', () => {
  it('uses strict defaults that mask message, metadata secrets, headers, and policy identifiers', () => {
    const event = buildAuditEvent()
    const profile = createDefaultAuditRedactionProfile({
      tenant_id: event.tenant_id
    })

    const redacted = redactAuditEvent({
      event,
      profile
    })

    expect(redacted.message).toBe('[REDACTED]')
    expect(redacted.metadata).toEqual({
      action: 'execute',
      api_key: '[REDACTED]',
      request_body: '[REDACTED]'
    })
    expect(redacted.canonical_descriptor?.normalized_headers).toEqual([
      {name: 'content-type', value: '[REDACTED]'},
      {name: 'authorization', value: '[REDACTED]'}
    ])
    expect(redacted.policy?.rule_id).toBe('[REDACTED]')
  })

  it('supports tenant-specific profile overrides', () => {
    const event = buildAuditEvent({
      metadata: {
        action: 'approval.decide',
        note: 'allow one-time approval',
        token: 'sensitive-token'
      }
    })
    const profile = AuditRedactionProfileSchema.parse({
      tenant_id: event.tenant_id,
      profile_id: 'tenant_custom_v1',
      rules: {
        message_action: 'keep',
        metadata_default_action: 'drop',
        metadata_key_actions: {
          note: 'hash'
        },
        metadata_allow_keys: ['action'],
        sensitive_key_patterns: ['token'],
        canonical_header_value_action: 'keep',
        policy_identifier_action: 'keep',
        max_depth: 5,
        max_collection_size: 100,
        max_string_length: 512,
        hash_salt: 'tenant-salt'
      }
    })

    const redacted = redactAuditEvent({
      event,
      profile
    })
    const metadata = redacted.metadata as Record<string, unknown>

    expect(redacted.message).toBe('raw upstream payload should not be stored')
    expect(metadata.action).toBe('approval.decide')
    expect(metadata.token).toBe('[REDACTED]')
    expect(typeof metadata.note).toBe('string')
    expect((metadata.note as string).startsWith('sha256:')).toBe(true)
    expect(redacted.canonical_descriptor?.normalized_headers).toEqual([
      {name: 'content-type', value: 'application/json'},
      {name: 'authorization', value: '[REDACTED]'}
    ])
    expect(redacted.policy?.rule_id).toBe('policy_1')
  })

  it('drops policy identifiers when configured and handles null policy safely', () => {
    const event = buildAuditEvent({
      policy: {
        rule_id: 'policy_1',
        rule_type: 'deny',
        approval_id: 'approval_1'
      }
    })

    const dropPolicyProfile = AuditRedactionProfileSchema.parse({
      tenant_id: event.tenant_id,
      profile_id: 'policy_drop_v1',
      rules: {
        message_action: 'mask',
        metadata_default_action: 'mask',
        metadata_key_actions: {},
        metadata_allow_keys: [],
        sensitive_key_patterns: ['token'],
        canonical_header_value_action: 'drop',
        policy_identifier_action: 'drop',
        max_depth: 5,
        max_collection_size: 100,
        max_string_length: 512
      }
    })

    const withPolicy = redactAuditEvent({
      event,
      profile: dropPolicyProfile
    })
    expect(withPolicy.policy).toEqual({
      rule_id: null,
      rule_type: 'deny',
      approval_id: null
    })
    expect(withPolicy.canonical_descriptor?.normalized_headers).toEqual([
      {name: 'authorization', value: '[REDACTED]'}
    ])

    const withoutPolicy = redactAuditEvent({
      event: buildAuditEvent({policy: null}),
      profile: dropPolicyProfile
    })
    expect(withoutPolicy.policy).toBeNull()
  })

  it('normalizes dropped message/metadata and missing canonical descriptor to null', () => {
    const event = buildAuditEvent({
      message: 'sensitive-message',
      metadata: {
        scratch: 'value'
      },
      canonical_descriptor: null
    })
    const profile = AuditRedactionProfileSchema.parse({
      tenant_id: event.tenant_id,
      profile_id: 'drop_paths_v1',
      rules: {
        message_action: 'drop',
        metadata_default_action: 'drop',
        metadata_key_actions: {
          scratch: 'drop'
        },
        metadata_allow_keys: [],
        sensitive_key_patterns: ['token'],
        canonical_header_value_action: 'mask',
        policy_identifier_action: 'mask',
        max_depth: 5,
        max_collection_size: 100,
        max_string_length: 512
      }
    })

    const redacted = redactAuditEvent({
      event,
      profile
    })

    expect(redacted.message).toBeNull()
    expect(redacted.metadata).toBeNull()
    expect(redacted.canonical_descriptor).toBeNull()
  })
})

describe('redactStructuredLogPayload', () => {
  it('returns structured redacted output suitable for logs', () => {
    const profile = createDefaultAuditRedactionProfile({tenant_id: 'tenant_1'})
    const payload = {
      correlation_id: 'corr_1',
      api_key: 'sk-live-secret',
      nested: {
        token: 'secret-token'
      }
    }

    const redacted = redactStructuredLogPayload({
      payload,
      profile
    }) as Record<string, unknown>

    expect(redacted.correlation_id).toBe('corr_1')
    expect(redacted.api_key).toBe('[REDACTED]')
    expect((redacted.nested as Record<string, unknown>).token).toBe('[REDACTED]')
  })

  it('enforces depth and collection/string limits for structured payloads', () => {
    const profile = AuditRedactionProfileSchema.parse({
      tenant_id: 'tenant_1',
      profile_id: 'structured_limits_v1',
      rules: {
        message_action: 'mask',
        metadata_default_action: 'mask',
        metadata_key_actions: {},
        metadata_allow_keys: [],
        sensitive_key_patterns: ['token'],
        canonical_header_value_action: 'mask',
        policy_identifier_action: 'mask',
        max_depth: 4,
        max_collection_size: 2,
        max_string_length: 64
      }
    })
    const longNote = `${'1'.repeat(64)}12345`
    const payload = {
      records: [
        {
          token: 'secret-1',
          note: longNote
        },
        {
          token: 'secret-2'
        }
      ],
      deep: {
        layer1: {
          layer2: {
            value: 'x'
          }
        }
      }
    }

    const redacted = redactStructuredLogPayload({
      payload,
      profile
    }) as Record<string, unknown>
    const records = redacted.records as Array<Record<string, unknown>>
    const firstRecord = records[0]

    expect(records).toHaveLength(2)
    expect(firstRecord?.token).toBe('[REDACTED]')
    expect(firstRecord?.note).toBe(`${'1'.repeat(64)}...[TRUNCATED]`)
    expect(((redacted.deep as Record<string, unknown>).layer1 as Record<string, unknown>).layer2).toEqual({
      value: '[REDACTED_DEPTH]'
    })
  })

  it('enforces collection limits for arrays', () => {
    const profile = AuditRedactionProfileSchema.parse({
      tenant_id: 'tenant_1',
      profile_id: 'structured_collection_limit_v1',
      rules: {
        message_action: 'mask',
        metadata_default_action: 'mask',
        metadata_key_actions: {},
        metadata_allow_keys: [],
        sensitive_key_patterns: ['token'],
        canonical_header_value_action: 'mask',
        policy_identifier_action: 'mask',
        max_depth: 5,
        max_collection_size: 1,
        max_string_length: 64
      }
    })

    const redacted = redactStructuredLogPayload({
      payload: ['first', 'second'],
      profile
    }) as unknown[]

    expect(redacted).toEqual(['first'])
  })
})
