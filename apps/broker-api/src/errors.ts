export type ErrorStatus = 400 | 401 | 403 | 404 | 409 | 415 | 422 | 500 | 503

export class AppError extends Error {
  public readonly code: string
  public readonly status: ErrorStatus

  public constructor({code, message, status}: {code: string; message: string; status: ErrorStatus}) {
    super(message)
    this.name = 'AppError'
    this.code = code
    this.status = status
  }
}

export const badRequest = (code: string, message: string) =>
  new AppError({code, message, status: 400})

export const unauthorized = (code: string, message: string) =>
  new AppError({code, message, status: 401})

export const forbidden = (code: string, message: string) =>
  new AppError({code, message, status: 403})

export const notFound = (code: string, message: string) =>
  new AppError({code, message, status: 404})

export const conflict = (code: string, message: string) =>
  new AppError({code, message, status: 409})

export const unsupportedMediaType = (code: string, message: string) =>
  new AppError({code, message, status: 415})

export const unprocessable = (code: string, message: string) =>
  new AppError({code, message, status: 422})

export const internal = (code: string, message: string) =>
  new AppError({code, message, status: 500})

export const serviceUnavailable = (code: string, message: string) =>
  new AppError({code, message, status: 503})

export const isAppError = (value: unknown): value is AppError => value instanceof AppError
