export const auditErrorCodes = [
  'invalid_input',
  'invalid_search_query',
  'invalid_time_range',
  'redaction_profile_invalid',
  'storage_write_failed',
  'storage_query_failed'
] as const

export type AuditErrorCode = (typeof auditErrorCodes)[number]

export type AuditError = {
  code: AuditErrorCode
  message: string
}

export type AuditSuccess<T> = {ok: true; value: T}
export type AuditFailure = {ok: false; error: AuditError}
export type AuditResult<T> = AuditSuccess<T> | AuditFailure

export const ok = <T>(value: T): AuditSuccess<T> => ({ok: true, value})

export const err = (code: AuditErrorCode, message: string): AuditFailure => ({
  ok: false,
  error: {code, message}
})
