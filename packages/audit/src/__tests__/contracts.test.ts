import {describe, expect, it} from 'vitest'

import {AuditRedactionProfileSchema} from '../contracts'

describe('AuditRedactionProfileSchema', () => {
  it('rejects invalid sensitive key regex patterns', () => {
    const result = AuditRedactionProfileSchema.safeParse({
      tenant_id: 'tenant_1',
      profile_id: 'profile_1',
      rules: {
        message_action: 'mask',
        metadata_default_action: 'mask',
        metadata_key_actions: {},
        metadata_allow_keys: [],
        sensitive_key_patterns: ['[unterminated'],
        canonical_header_value_action: 'mask',
        policy_identifier_action: 'mask',
        max_depth: 5,
        max_collection_size: 100,
        max_string_length: 256
      }
    })

    expect(result.success).toBe(false)
  })
})
