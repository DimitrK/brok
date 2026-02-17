import {describe, expect, it} from 'vitest'
import type {EnrollmentTokenRecord} from '../redis/index.js'

describe('redis/index exports', () => {
  it('exposes EnrollmentTokenRecord from auth redis adapters', () => {
    const sample: EnrollmentTokenRecord = {
      tokenHash: 'a'.repeat(64),
      workloadId: 'w_1',
      expiresAt: '2026-02-13T00:00:00.000Z'
    }

    expect(sample.tokenHash).toHaveLength(64)
  })
})
