export const ssrfGuardErrorCodes = [
  'invalid_input',
  'request_url_invalid',
  'request_url_userinfo_forbidden',
  'request_url_fragment_forbidden',
  'request_scheme_not_allowed',
  'request_host_not_allowed',
  'request_port_not_allowed',
  'request_ip_literal_forbidden',
  'template_host_invalid',
  'dns_resolution_required',
  'dns_resolution_failed',
  'dns_resolution_empty',
  'resolved_ip_invalid',
  'resolved_ip_denied_private_range',
  'resolved_ip_denied_loopback',
  'resolved_ip_denied_link_local',
  'resolved_ip_denied_metadata_range',
  'redirect_denied'
] as const;

export type SsrfGuardErrorCode = (typeof ssrfGuardErrorCodes)[number];

export type SsrfGuardError = {
  code: SsrfGuardErrorCode;
  message: string;
};

export type SsrfGuardSuccess<T> = {ok: true; value: T};
export type SsrfGuardFailure = {ok: false; error: SsrfGuardError};
export type SsrfGuardResult<T> = SsrfGuardSuccess<T> | SsrfGuardFailure;

export const ok = <T>(value: T): SsrfGuardSuccess<T> => ({ok: true, value});

export const err = (code: SsrfGuardErrorCode, message: string): SsrfGuardFailure => ({
  ok: false,
  error: {code, message}
});
