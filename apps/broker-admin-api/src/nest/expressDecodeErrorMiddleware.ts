import type {NextFunction, Request, Response} from 'express'

import {sendError, extractCorrelationId} from '../http'

const pathParamDecodeErrorPattern = /decode param|uri malformed/u

const isPathParamDecodeError = (error: unknown) => {
  if (error instanceof URIError) {
    return true
  }

  if (!(error instanceof Error)) {
    return false
  }

  return pathParamDecodeErrorPattern.test(error.message)
}

export const expressDecodeErrorMiddleware = (
  error: unknown,
  request: Request,
  response: Response,
  next: NextFunction
) => {
  if (!isPathParamDecodeError(error)) {
    next(error)
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
