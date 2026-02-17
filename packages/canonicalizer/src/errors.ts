export const canonicalizerErrorCodes = [
  'invalid_input',
  'request_integration_mismatch',
  'invalid_template',
  'template_host_invalid',
  'template_host_wildcard_forbidden',
  'template_group_duplicate',
  'template_path_pattern_unanchored',
  'template_path_pattern_invalid',
  'template_path_pattern_overbroad',
  'template_path_pattern_unsafe',
  'template_allowlist_duplicate',
  'template_header_allowlist_invalid',
  'template_version_conflict',
  'template_version_not_incremented',
  'template_provider_mismatch',
  'template_version_immutable',
  'no_matching_group',
  'request_url_invalid',
  'request_url_userinfo_forbidden',
  'request_url_fragment_forbidden',
  'request_scheme_not_allowed',
  'request_host_not_allowed',
  'request_port_not_allowed',
  'request_percent_encoding_invalid',
  'request_query_key_not_allowlisted',
  'request_query_duplicate_key_forbidden',
  'request_header_name_invalid',
  'request_header_value_invalid',
  'request_body_base64_invalid',
  'request_body_too_large',
  'request_content_type_missing',
  'request_content_type_not_allowed',
  'internal_descriptor_invalid'
] as const;

export type CanonicalizerErrorCode = (typeof canonicalizerErrorCodes)[number];

export type CanonicalizerError = {
  code: CanonicalizerErrorCode;
  message: string;
};

export type CanonicalizerSuccess<T> = {ok: true; value: T};
export type CanonicalizerFailure = {ok: false; error: CanonicalizerError};
export type CanonicalizerResult<T> = CanonicalizerSuccess<T> | CanonicalizerFailure;

export const ok = <T>(value: T): CanonicalizerSuccess<T> => ({ok: true, value});

export const err = (code: CanonicalizerErrorCode, message: string): CanonicalizerFailure => ({
  ok: false,
  error: {code, message}
});
