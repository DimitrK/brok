import {Readable} from 'node:stream'

import {z} from 'zod'
import {describe, expect, it, vi} from 'vitest'

import {isAppError} from '../errors'
import {
  decodePathParam,
  extractCorrelationId,
  parseJsonBody,
  parseQuery,
  sendError,
  sendJson,
  sendNoContent
} from '../http'

const makeRequest = ({
  headers,
  body
}: {
  headers?: Record<string, string>
  body?: string
} = {}) => {
  const stream = body ? Readable.from([body]) : Readable.from([])
  const request = stream as Readable & {
    headers: Record<string, string | undefined>
  }
  request.headers = headers ?? {}
  return request as unknown as Parameters<typeof parseJsonBody>[0]['request']
}

const makeResponse = () => {
  const writeHead = vi.fn()
  const end = vi.fn()
  return {
    writeHead,
    end
  }
}

describe('broker-api http helpers', () => {
  it('parses JSON body when required and valid', async () => {
    const schema = z.object({name: z.string()}).strict()
    const request = makeRequest({
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({name: 'broker'})
    })

    const parsed = await parseJsonBody({
      request,
      schema,
      maxBodyBytes: 1024,
      required: true
    })

    expect(parsed.name).toBe('broker')
  })

  it('returns undefined for optional body when request has no body headers', async () => {
    const schema = z.object({name: z.string()}).strict()
    const request = makeRequest()

    const parsed = await parseJsonBody({
      request,
      schema,
      maxBodyBytes: 1024,
      required: false
    })

    expect(parsed).toBeUndefined()
  })

  it('fails closed for invalid content-type, invalid json, and invalid schema', async () => {
    const schema = z.object({name: z.string()}).strict()

    await expect(
      parseJsonBody({
        request: makeRequest({
          headers: {'content-type': 'text/plain'},
          body: '{}'
        }),
        schema,
        maxBodyBytes: 1024,
        required: true
      })
    ).rejects.toMatchObject({code: 'content_type_invalid'})

    await expect(
      parseJsonBody({
        request: makeRequest({
          headers: {'content-type': 'application/json'},
          body: '{nope'
        }),
        schema,
        maxBodyBytes: 1024,
        required: true
      })
    ).rejects.toMatchObject({code: 'request_body_invalid_json'})

    await expect(
      parseJsonBody({
        request: makeRequest({
          headers: {'content-type': 'application/json'},
          body: JSON.stringify({name: 42})
        }),
        schema,
        maxBodyBytes: 1024,
        required: true
      })
    ).rejects.toMatchObject({code: 'request_body_schema_invalid'})
  })

  it('enforces request body size limits', async () => {
    const schema = z.object({name: z.string()}).strict()
    const request = makeRequest({
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({name: 'a'.repeat(200)})
    })

    try {
      await parseJsonBody({
        request,
        schema,
        maxBodyBytes: 32,
        required: true
      })
      throw new Error('expected parseJsonBody to fail with max size enforcement')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('request_body_too_large')
    }
  })

  it('parses and validates query strings', () => {
    const parsed = parseQuery({
      searchParams: new URLSearchParams('status=pending'),
      schema: z
        .object({
          status: z.enum(['pending'])
        })
        .strict()
    })
    expect(parsed.status).toBe('pending')

    expect(() =>
      parseQuery({
        searchParams: new URLSearchParams('status=bad'),
        schema: z
          .object({
            status: z.enum(['pending'])
          })
          .strict()
      })
    ).toThrow()
  })

  it('decodes path params safely', () => {
    expect(decodePathParam('workload%2Fid')).toBe('workload/id')
    expect(() => decodePathParam('%')).toThrow()
  })

  it('emits JSON, error, and no-content responses with security headers', () => {
    const response = makeResponse()
    sendJson({
      response: response as never,
      status: 200,
      correlationId: 'corr_1',
      payload: {ok: true}
    })
    expect(response.writeHead).toHaveBeenCalledWith(
      200,
      expect.objectContaining({
        'x-correlation-id': 'corr_1',
        'content-type': 'application/json; charset=utf-8',
        'x-content-type-options': 'nosniff'
      })
    )
    expect(response.end).toHaveBeenCalled()

    const errorResponse = makeResponse()
    sendError({
      response: errorResponse as never,
      status: 401,
      error: 'unauthorized',
      message: 'Auth required',
      correlationId: 'corr_2'
    })
    expect(errorResponse.writeHead).toHaveBeenCalled()
    expect(errorResponse.end).toHaveBeenCalled()

    const noContentResponse = makeResponse()
    sendNoContent({
      response: noContentResponse as never,
      correlationId: 'corr_3'
    })
    expect(noContentResponse.writeHead).toHaveBeenCalledWith(
      204,
      expect.objectContaining({'x-correlation-id': 'corr_3'})
    )
  })

  it('extracts and normalizes correlation IDs', () => {
    expect(
      extractCorrelationId({
        headers: {'x-correlation-id': 'corr-inbound'}
      } as never)
    ).toBe('corr-inbound')

    const generated = extractCorrelationId({
      headers: {'x-correlation-id': ' '.repeat(5)}
    } as never)
    expect(generated).toBeTypeOf('string')
    expect(generated.length).toBeGreaterThan(8)
  })
})
