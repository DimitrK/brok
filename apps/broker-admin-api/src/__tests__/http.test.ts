import {Readable} from 'node:stream'

import {z} from 'zod'
import {describe, expect, it, vi} from 'vitest'

import {isAppError} from '../errors'
import {
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
}) => {
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

describe('http helpers', () => {
  it('parses json body and validates schema', async () => {
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

  it('fails closed on invalid content type and invalid json', async () => {
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
          body: '{not-json'
        }),
        schema,
        maxBodyBytes: 1024,
        required: true
      })
    ).rejects.toMatchObject({code: 'request_body_invalid_json'})
  })

  it('parses query values and emits json/error responses', () => {
    const parsedQuery = parseQuery({
      searchParams: new URLSearchParams('status=pending'),
      schema: z
        .object({
          status: z.enum(['pending'])
        })
        .strict()
    })
    expect(parsedQuery.status).toBe('pending')

    const response = makeResponse()
    sendJson({
      response: response as never,
      status: 200,
      correlationId: 'corr_1',
      payload: {ok: true}
    })
    expect(response.writeHead).toHaveBeenCalled()
    expect(response.end).toHaveBeenCalled()

    const errorResponse = makeResponse()
    sendError({
      response: errorResponse as never,
      status: 400,
      error: 'bad_request',
      message: 'Bad request',
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

  it('extracts correlation ids safely', () => {
    const value = extractCorrelationId({
      headers: {'x-correlation-id': 'corr-from-header'}
    } as never)
    expect(value).toBe('corr-from-header')

    const generated = extractCorrelationId({headers: {}} as never)
    expect(generated).toBeTypeOf('string')
    expect(generated.length).toBeGreaterThan(10)
  })

  it('rejects oversized request body', async () => {
    const schema = z.object({name: z.string()}).strict()
    try {
      await parseJsonBody({
        request: makeRequest({
          headers: {'content-type': 'application/json'},
          body: JSON.stringify({name: 'a'.repeat(512)})
        }),
        schema,
        maxBodyBytes: 64,
        required: true
      })
      throw new Error('expected request to exceed body limit')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('request_body_too_large')
    }
  })
})

