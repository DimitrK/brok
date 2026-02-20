import {describe, expect, it} from 'vitest'

import type {DatabaseClient} from '../types.js'
import {
  Base64PayloadSchema,
  CursorPairSchema,
  NonEmptyTrimmedStringSchema,
  NormalizedHostSchema,
  NormalizedHttpMethodSchema,
  NormalizedIpAllowlistSchema,
  NormalizedUniqueStringListSchema,
  assertNonEmptyString,
  decodeBase64ByteLength,
  ensureEnvelopeBounds,
  normalizeHost,
  normalizeIpAllowlist,
  normalizeMethod,
  normalizeUniqueStringList,
  parseCursorPair,
  resolveRepositoryDbClient
} from '../utils.js'

const notImplemented = <T>() => (): Promise<T> => Promise.reject(new Error('not_implemented'))

const createDbClientStub = (): DatabaseClient => ({
  adminSignupPolicy: {
    findUnique: notImplemented(),
    upsert: notImplemented()
  },
  adminIdentity: {
    create: notImplemented(),
    findUnique: notImplemented(),
    findMany: notImplemented(),
    count: notImplemented(),
    update: notImplemented()
  },
  adminAccessRequest: {
    create: notImplemented(),
    findUnique: notImplemented(),
    findMany: notImplemented(),
    update: notImplemented(),
    updateMany: notImplemented()
  },
  tenant: {
    create: notImplemented(),
    findUnique: notImplemented(),
    findMany: notImplemented()
  },
  humanUser: {
    create: notImplemented(),
    findUnique: notImplemented(),
    findMany: notImplemented(),
    update: notImplemented()
  },
  workload: {
    create: notImplemented(),
    findUnique: notImplemented(),
    findMany: notImplemented(),
    findFirst: notImplemented(),
    update: notImplemented()
  },
  enrollmentToken: {
    create: notImplemented(),
    findUnique: notImplemented(),
    findFirst: notImplemented(),
    updateMany: notImplemented()
  },
  workloadSession: {
    upsert: notImplemented(),
    findFirst: notImplemented(),
    update: notImplemented(),
    deleteMany: notImplemented()
  },
  integration: {
    create: notImplemented(),
    findFirst: notImplemented(),
    findMany: notImplemented(),
    update: notImplemented()
  },
  secret: {
    findUnique: notImplemented(),
    create: notImplemented(),
    update: notImplemented()
  },
  secretVersion: {
    findFirst: notImplemented(),
    create: notImplemented(),
    findUnique: notImplemented(),
    findMany: notImplemented()
  },
  manifestSigningKey: {
    findFirst: notImplemented(),
    findMany: notImplemented(),
    findUnique: notImplemented(),
    create: notImplemented(),
    update: notImplemented()
  },
  manifestKeysetMetadata: {
    findUnique: notImplemented(),
    upsert: notImplemented()
  },
  cryptoVerificationDefaults: {
    findUnique: notImplemented(),
    upsert: notImplemented()
  },
  templateVersion: {
    findMany: notImplemented(),
    create: notImplemented(),
    findUnique: notImplemented(),
    findFirst: notImplemented()
  },
  policyRule: {
    create: notImplemented(),
    findUnique: notImplemented(),
    update: notImplemented(),
    findMany: notImplemented()
  },
  approvalRequest: {
    create: notImplemented(),
    findUnique: notImplemented(),
    findMany: notImplemented(),
    update: notImplemented(),
    findFirst: notImplemented()
  },
  auditEvent: {
    create: notImplemented(),
    findMany: notImplemented()
  },
  ssrfGuardDecision: {
    upsert: notImplemented(),
    findUnique: notImplemented()
  },
  templateInvalidationOutbox: {
    upsert: notImplemented()
  },
  auditRedactionProfile: {
    findUnique: notImplemented(),
    create: notImplemented(),
    upsert: notImplemented()
  }
})

const expectValidationError = (operation: () => unknown): void => {
  try {
    operation()
    throw new Error('Expected operation to throw validation_error')
  } catch (error) {
    expect(error).toMatchObject({
      code: 'validation_error'
    })
  }
}

describe('zod schemas', () => {
  it('normalizes non-empty strings', () => {
    expect(NonEmptyTrimmedStringSchema.parse('  abc  ')).toBe('abc')
  })

  it('normalizes and sorts unique string lists', () => {
    expect(NormalizedUniqueStringListSchema.parse([' z ', 'a'])).toEqual(['a', 'z'])
  })

  it('normalizes and validates ip allowlist values', () => {
    expect(NormalizedIpAllowlistSchema.parse([' 203.0.113.10 ', '10.0.0.0/8'])).toEqual([
      '10.0.0.0/8',
      '203.0.113.10'
    ])
  })

  it('normalizes http methods', () => {
    expect(NormalizedHttpMethodSchema.parse(' post ')).toBe('POST')
  })

  it('normalizes exact hosts', () => {
    expect(NormalizedHostSchema.parse('Example.COM')).toBe('example.com')
  })

  it('accepts canonical cursor payloads', () => {
    expect(
      CursorPairSchema.parse({
        timestamp: '2026-02-08T00:00:00.000Z',
        event_id: 'evt_1',
        tenant_id: 't_1'
      })
    ).toEqual({
      timestamp: '2026-02-08T00:00:00.000Z',
      event_id: 'evt_1',
      tenant_id: 't_1'
    })
  })

  it('accepts canonical base64 payloads', () => {
    const payload = Buffer.from('hello', 'utf8').toString('base64')
    expect(Base64PayloadSchema.parse(` ${payload} `)).toBe(payload)
  })
})

describe('utils normalization and validation', () => {
  it('assertNonEmptyString trims valid values', () => {
    expect(assertNonEmptyString('  tenant_1 ', 'tenant_id')).toBe('tenant_1')
  })

  it('assertNonEmptyString rejects empty values', () => {
    expectValidationError(() => assertNonEmptyString('   ', 'tenant_id'))
  })

  it('normalizeUniqueStringList rejects duplicates', () => {
    expectValidationError(() => normalizeUniqueStringList(['a', ' a ']))
  })

  it('normalizeIpAllowlist rejects invalid CIDR entries', () => {
    expectValidationError(() => normalizeIpAllowlist(['192.168.0.1/33']))
  })

  it('normalizeMethod rejects unknown verbs', () => {
    expectValidationError(() => normalizeMethod('TRACE'))
  })

  it('normalizeHost rejects wildcard hosts', () => {
    expectValidationError(() => normalizeHost('*.example.com'))
  })
})

describe('utils binary and cursor helpers', () => {
  it('decodeBase64ByteLength validates and computes byte size', () => {
    const payload = Buffer.from('abc', 'utf8').toString('base64')
    expect(decodeBase64ByteLength(payload)).toBe(3)
  })

  it('decodeBase64ByteLength rejects malformed payloads', () => {
    expectValidationError(() => decodeBase64ByteLength('$$$'))
  })

  it('ensureEnvelopeBounds rejects oversized ciphertext', () => {
    expectValidationError(() =>
      ensureEnvelopeBounds({
        wrapped_data_key_b64: Buffer.alloc(32, 1).toString('base64'),
        ciphertext_b64: Buffer.alloc(1_048_577, 1).toString('base64')
      })
    )
  })

  it('parseCursorPair decodes and validates cursor tokens', () => {
    const cursor = Buffer.from('2026-02-08T00:00:00.000Z|evt_1|t_1', 'utf8').toString('base64url')
    expect(parseCursorPair(cursor)).toEqual({
      timestamp: '2026-02-08T00:00:00.000Z',
      event_id: 'evt_1',
      tenant_id: 't_1'
    })
  })

  it('parseCursorPair rejects malformed cursor payloads', () => {
    const cursor = Buffer.from('bad|cursor', 'utf8').toString('base64url')
    expectValidationError(() => parseCursorPair(cursor))
  })
})

describe('resolveRepositoryDbClient', () => {
  it('uses transaction_client when required methods exist', () => {
    const defaultClient = createDbClientStub()
    const transactionClient = createDbClientStub()
    const resolved = resolveRepositoryDbClient(
      defaultClient,
      {
        transaction_client: transactionClient
      },
      [
        {
          model: 'workload',
          method: 'findFirst'
        }
      ]
    )

    expect(resolved).toBe(transactionClient)
  })

  it('fails closed when transaction_client misses required method', () => {
    expectValidationError(() =>
      resolveRepositoryDbClient(
        createDbClientStub(),
        {
          transaction_client: {
            workload: {}
          }
        },
        [
          {
            model: 'workload',
            method: 'findFirst'
          }
        ]
      )
    )
  })
})
