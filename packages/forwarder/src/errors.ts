export const forwarderErrorCodes = [
  'invalid_input',
  'invalid_header_name',
  'invalid_header_value',
  'invalid_connection_header',
  'template_group_not_found',
  'redirect_policy_not_supported',
  'request_url_invalid',
  'request_method_not_allowed',
  'request_scheme_not_allowed',
  'request_host_not_allowed',
  'request_port_not_allowed',
  'request_body_base64_invalid',
  'request_body_too_large',
  'request_streaming_not_supported',
  'ambiguous_framing_invalid_content_length',
  'ambiguous_framing_multiple_content_length',
  'ambiguous_framing_conflicting_content_length_transfer_encoding',
  'ambiguous_framing_transfer_encoding_invalid',
  'ambiguous_framing_content_length_mismatch',
  'forbidden_upstream_header',
  'upstream_timeout',
  'upstream_network_error',
  'redirect_denied',
  'upstream_streaming_not_supported',
  'upstream_response_too_large',
  'invalid_upstream_response'
] as const;

export type ForwarderErrorCode = (typeof forwarderErrorCodes)[number];

export type ForwarderError = {
  code: ForwarderErrorCode;
  message: string;
};

export type ForwarderSuccess<T> = {ok: true; value: T};
export type ForwarderFailure = {ok: false; error: ForwarderError};
export type ForwarderResult<T> = ForwarderSuccess<T> | ForwarderFailure;

export const ok = <T>(value: T): ForwarderSuccess<T> => ({ok: true, value});

export const err = (code: ForwarderErrorCode, message: string): ForwarderFailure => ({
  ok: false,
  error: {code, message}
});
