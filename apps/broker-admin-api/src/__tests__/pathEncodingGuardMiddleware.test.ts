import {describe, expect, it, vi} from 'vitest'

import {hasMalformedPercentEncoding, pathEncodingGuardMiddleware} from '../nest/pathEncodingGuardMiddleware'

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

describe('pathEncodingGuardMiddleware', () => {
  it('detects malformed percent encoding sequences', () => {
    expect(hasMalformedPercentEncoding('/v1/templates/%E0%A4%A/versions/1')).toBe(true)
    expect(hasMalformedPercentEncoding('/v1/templates/%2F/versions/1')).toBe(false)
    expect(hasMalformedPercentEncoding('/v1/templates/plain/versions/1')).toBe(false)
  })

  it('returns path_param_invalid for malformed encoded paths', () => {
    const response = makeResponse()
    const next = vi.fn()

    pathEncodingGuardMiddleware(
      {url: '/v1/templates/%E0%A4%A/versions/1', headers: {}} as never,
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

  it('passes through valid paths', () => {
    const response = makeResponse()
    const next = vi.fn()

    pathEncodingGuardMiddleware(
      {url: '/v1/templates/tpl_openai_safe/versions/1', headers: {}} as never,
      response as never,
      next as never
    )

    expect(next).toHaveBeenCalledOnce()
    expect(response.writeHead).not.toHaveBeenCalled()
  })
})
