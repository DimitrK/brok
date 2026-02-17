import type {
  ExternalCaEnrollmentError,
  ExternalCaEnrollmentErrorCode,
  ExternalCaEnrollmentProvider,
  IssueExternalCaEnrollmentInput,
  IssueExternalCaEnrollmentOutput,
  IssueExternalCaEnrollmentResult
} from './types';

const DEFAULT_PROVIDER_TIMEOUT_MS = 5_000;
const MAX_PROVIDER_TIMEOUT_MS = 30_000;
const MAX_MTLS_CA_PEM_BYTES = 64 * 1024;

const EXTERNAL_CA_ERROR_CODES: ReadonlySet<ExternalCaEnrollmentErrorCode> = new Set([
  'external_ca_not_configured',
  'external_ca_unreachable',
  'external_ca_profile_invalid',
  'external_ca_enrollment_denied'
]);

const getErrorMessage = (code: ExternalCaEnrollmentErrorCode) => {
  switch (code) {
    case 'external_ca_not_configured': {
      return 'External CA enrollment provider is not configured';
    }
    case 'external_ca_unreachable': {
      return 'External CA enrollment provider is unreachable';
    }
    case 'external_ca_profile_invalid': {
      return 'External CA provider returned an invalid response';
    }
    case 'external_ca_enrollment_denied': {
      return 'External CA enrollment request was denied';
    }
  }
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;

const normalizeTimeoutMs = (value: unknown) => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    return DEFAULT_PROVIDER_TIMEOUT_MS;
  }

  return Math.min(Math.floor(value), MAX_PROVIDER_TIMEOUT_MS);
};

const makeError = ({code}: {code: ExternalCaEnrollmentErrorCode}): IssueExternalCaEnrollmentResult => ({
  ok: false,
  error: {
    code,
    message: getErrorMessage(code)
  }
});

const isKnownErrorCode = (value: unknown): value is ExternalCaEnrollmentErrorCode =>
  typeof value === 'string' && EXTERNAL_CA_ERROR_CODES.has(value as ExternalCaEnrollmentErrorCode);

const extractKnownErrorCode = (value: unknown): ExternalCaEnrollmentErrorCode | null => {
  if (!isRecord(value)) {
    return null;
  }

  if (isKnownErrorCode(value.code)) {
    return value.code;
  }

  if (isRecord(value.error) && isKnownErrorCode(value.error.code)) {
    return value.error.code;
  }

  return null;
};

const normalizeProviderError = (value: unknown): ExternalCaEnrollmentError => {
  const extractedCode = extractKnownErrorCode(value);
  if (!extractedCode) {
    return {
      code: 'external_ca_profile_invalid',
      message: getErrorMessage('external_ca_profile_invalid')
    };
  }

  return {
    code: extractedCode,
    message: getErrorMessage(extractedCode)
  };
};

const CERTIFICATE_BLOCK_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/u;
const PRIVATE_KEY_BLOCK_PATTERN = /-----BEGIN [^-]*PRIVATE KEY-----/iu;

const hasCertificateBlock = (value: string) => CERTIFICATE_BLOCK_PATTERN.test(value);
const hasPrivateKeyBlock = (value: string) => PRIVATE_KEY_BLOCK_PATTERN.test(value);

const normalizeProviderSuccess = (value: unknown): IssueExternalCaEnrollmentOutput | null => {
  if (!isRecord(value)) {
    return null;
  }

  const mtlsCaPem = value.mtlsCaPem;
  if (!isNonEmptyString(mtlsCaPem)) {
    return null;
  }

  if (Buffer.byteLength(mtlsCaPem, 'utf8') > MAX_MTLS_CA_PEM_BYTES) {
    return null;
  }

  if (!hasCertificateBlock(mtlsCaPem) || hasPrivateKeyBlock(mtlsCaPem)) {
    return null;
  }

  const enrollmentReferenceRaw = value.enrollmentReference;
  if (enrollmentReferenceRaw === undefined) {
    return {mtlsCaPem};
  }

  if (!isNonEmptyString(enrollmentReferenceRaw)) {
    return null;
  }

  return {
    mtlsCaPem,
    enrollmentReference: enrollmentReferenceRaw
  };
};

const issueProviderEnrollmentWithTimeout = async ({
  provider,
  input,
  timeoutMs,
  signal
}: {
  provider: ExternalCaEnrollmentProvider;
  input: IssueExternalCaEnrollmentInput;
  timeoutMs: number;
  signal?: AbortSignal;
}) => {
  const abortController = new AbortController();
  const onAbort = () => abortController.abort(signal?.reason);

  if (signal) {
    if (signal.aborted) {
      abortController.abort(signal.reason);
    } else {
      signal.addEventListener('abort', onAbort, {once: true});
    }
  }

  const timeout = setTimeout(() => {
    abortController.abort(new Error('external_ca_timeout'));
  }, timeoutMs);

  try {
    return await provider.issueEnrollment({
      tenantId: input.tenantId,
      workloadName: input.workloadName,
      signal: abortController.signal
    });
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', onAbort);
  }
};

export const issueExternalCaEnrollment = async ({
  input,
  provider,
  timeoutMs = DEFAULT_PROVIDER_TIMEOUT_MS,
  signal
}: {
  input: IssueExternalCaEnrollmentInput;
  provider?: ExternalCaEnrollmentProvider;
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<IssueExternalCaEnrollmentResult> => {
  if (!provider) {
    return makeError({code: 'external_ca_not_configured'});
  }

  if (!isNonEmptyString(input.tenantId) || !isNonEmptyString(input.workloadName)) {
    return makeError({code: 'external_ca_profile_invalid'});
  }

  if (signal?.aborted) {
    return makeError({code: 'external_ca_unreachable'});
  }

  let providerResultRaw: unknown;
  try {
    providerResultRaw = await issueProviderEnrollmentWithTimeout({
      provider,
      input,
      timeoutMs: normalizeTimeoutMs(timeoutMs),
      signal
    });
  } catch (error: unknown) {
    const thrownCode = extractKnownErrorCode(error);
    if (thrownCode) {
      return makeError({code: thrownCode});
    }

    return makeError({code: 'external_ca_unreachable'});
  }

  if (!isRecord(providerResultRaw)) {
    return makeError({code: 'external_ca_profile_invalid'});
  }

  const hasResultEnvelope = Object.prototype.hasOwnProperty.call(providerResultRaw, 'ok');
  if (hasResultEnvelope) {
    if (providerResultRaw.ok === false) {
      const normalizedError = normalizeProviderError(providerResultRaw.error);
      return makeError(normalizedError);
    }

    if (providerResultRaw.ok !== true) {
      return makeError({code: 'external_ca_profile_invalid'});
    }

    const normalizedValue = normalizeProviderSuccess(providerResultRaw.value);
    if (!normalizedValue) {
      return makeError({code: 'external_ca_profile_invalid'});
    }

    return {ok: true, value: normalizedValue};
  }

  const normalizedValue = normalizeProviderSuccess(providerResultRaw);
  if (!normalizedValue) {
    return makeError({code: 'external_ca_profile_invalid'});
  }

  return {ok: true, value: normalizedValue};
};
