import {describe, expect, it, vi} from 'vitest'

import {expressDecodeErrorMiddleware} from '../nest/expressDecodeErrorMiddleware'

const makeResponse = () => {
  const state: {status?: number; headers?: Record<string, string | number>; payload?: string} = {}

  return {
    state,
    writeHead: vi.fn((status: number, headers: Record<string, string | number>) => {
      state.status = status
      state.headers = headers
    }),
    end: vi.fn((payload?: Buffer | string) => {
      if (typeof payload === 'string') {
        state.payload = payload
      } else if (payload instanceof Buffer) {
        state.payload = payload.toString('utf8')
      } else {
        state.payload = ''
      }
    })
  }
}

describe('expressDecodeErrorMiddleware', () => {
  it('maps malformed path decoding errors to path_param_invalid', () => {
    const response = makeResponse()
    const next = vi.fn()

    expressDecodeErrorMiddleware(
      new URIError('URI malformed'),
      {headers: {}} as never,
      response as never,
      next as never
    )

    expect(response.writeHead).toHaveBeenCalledWith(
      400,
      expect.objectContaining({'content-type': 'application/json; charset=utf-8'})
    )
    expect(response.state.payload).toBeTypeOf('string')
    const parsed = JSON.parse(response.state.payload ?? '{}') as {error?: string}
    expect(parsed.error).toBe('path_param_invalid')
    expect(next).not.toHaveBeenCalled()
  })

  it('delegates non-path errors to next middleware', () => {
    const response = makeResponse()
    const next = vi.fn()

    expressDecodeErrorMiddleware(
      new Error('other'),
      {headers: {}} as never,
      response as never,
      next as never
    )

    expect(next).toHaveBeenCalledOnce()
    expect(response.writeHead).not.toHaveBeenCalled()
  })
})
