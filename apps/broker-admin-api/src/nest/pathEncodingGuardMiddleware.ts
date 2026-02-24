import type {NextFunction, Request, Response} from 'express'

import {extractCorrelationId, sendError} from '../http'

const malformedPercentEncodingPattern = /%(?![0-9A-Fa-f]{2})/u

export const hasMalformedPercentEncoding = (value: string) => malformedPercentEncodingPattern.test(value)

export const pathEncodingGuardMiddleware = (request: Request, response: Response, next: NextFunction) => {
  const pathOnly = (request.url ?? '/').split('?', 1)[0] ?? '/'
  if (!hasMalformedPercentEncoding(pathOnly)) {
    next()
    return
  }

  sendError({
    response,
    status: 400,
    error: 'path_param_invalid',
    message: 'Path parameter encoding is invalid',
    correlationId: extractCorrelationId(request)
  })
}
