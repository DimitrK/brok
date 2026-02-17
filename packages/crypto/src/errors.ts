import {z} from 'zod';

export const cryptoErrorCodeSchema = z.enum([
  'invalid_input',
  'invalid_base64',
  'invalid_key_id',
  'invalid_key_length',
  'invalid_algorithm',
  'invalid_envelope_payload',
  'kms_key_not_found',
  'kms_wrap_failed',
  'kms_unwrap_failed',
  'decrypt_auth_failed',
  'aad_mismatch',
  'manifest_invalid',
  'manifest_key_not_found',
  'manifest_key_mismatch',
  'manifest_signature_invalid',
  'manifest_payload_mismatch',
  'manifest_expired',
  'manifest_not_yet_valid',
  'manifest_time_invalid',
  'manifest_signing_key_invalid',
  'manifest_signing_failed',
  'manifest_key_rotation_invalid',
  'manifest_keys_etag_failed'
]);

export type CryptoErrorCode = z.infer<typeof cryptoErrorCodeSchema>;

export type CryptoError = {
  code: CryptoErrorCode;
  message: string;
};

export type CryptoSuccess<T> = {
  ok: true;
  value: T;
};

export type CryptoFailure = {
  ok: false;
  error: CryptoError;
};

export type CryptoResult<T> = CryptoSuccess<T> | CryptoFailure;

export const ok = <T>(value: T): CryptoSuccess<T> => ({ok: true, value});

export const err = (code: CryptoErrorCode, message: string): CryptoFailure => ({
  ok: false,
  error: {code, message}
});
