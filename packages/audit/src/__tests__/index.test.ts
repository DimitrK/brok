import {describe, expect, it} from 'vitest'

import {
  createAuditService,
  createInMemoryAuditStore,
  packageName
} from '../index'

describe('packageName', () => {
  it('exports the package name', () => {
    expect(packageName).toBe('audit')
  })
})

describe('package exports', () => {
  it('exposes core service and in-memory store factories', () => {
    expect(typeof createAuditService).toBe('function')
    expect(typeof createInMemoryAuditStore).toBe('function')
  })
})
