import {describe, expect, it} from 'vitest'

import {
  AppError,
  badRequest,
  conflict,
  forbidden,
  internal,
  isAppError,
  notFound,
  serviceUnavailable,
  unauthorized,
  unsupportedMediaType,
  unprocessable
} from '../errors'

describe('broker-api errors', () => {
  it('creates typed app errors with stable statuses', () => {
    const created = [
      badRequest('bad', 'bad request'),
      unauthorized('unauth', 'unauthorized'),
      forbidden('forbidden', 'forbidden'),
      notFound('missing', 'not found'),
      conflict('conflict', 'conflict'),
      unsupportedMediaType('content_type_invalid', 'unsupported media type'),
      unprocessable('unprocessable', 'unprocessable'),
      internal('internal_error', 'internal error'),
      serviceUnavailable('unavailable', 'service unavailable')
    ]

    expect(created.map(item => item.status)).toEqual([400, 401, 403, 404, 409, 415, 422, 500, 503])
    expect(created.every(item => item instanceof AppError)).toBe(true)
    expect(created.every(item => isAppError(item))).toBe(true)
    expect(isAppError(new Error('x'))).toBe(false)
  })
})
