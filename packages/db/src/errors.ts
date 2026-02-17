export type DbErrorCode =
  | 'validation_error'
  | 'not_found'
  | 'unique_violation'
  | 'conflict'
  | 'integrity_violation'
  | 'state_transition_invalid'
  | 'dependency_missing'
  | 'unexpected_error'

export class DbRepositoryError extends Error {
  public readonly code: DbErrorCode

  public constructor(code: DbErrorCode, message: string) {
    super(message)
    this.name = 'DbRepositoryError'
    this.code = code
  }
}

type ErrorWithCode = {
  code?: unknown
}

const isErrorWithCode = (value: unknown): value is ErrorWithCode =>
  typeof value === 'object' && value !== null && 'code' in value

export const mapDatabaseError = (error: unknown): never => {
  if (error instanceof DbRepositoryError) {
    throw error
  }

  if (isErrorWithCode(error)) {
    switch (error.code) {
      case 'P2002':
        throw new DbRepositoryError('unique_violation', 'Unique constraint violated')
      case 'P2003':
      case 'P2014':
        throw new DbRepositoryError('integrity_violation', 'Relational integrity violation')
      case 'P2025':
        throw new DbRepositoryError('not_found', 'Record not found')
      default:
        break
    }
  }

  throw new DbRepositoryError('unexpected_error', 'Unexpected database error')
}
