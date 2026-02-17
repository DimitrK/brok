import type {OpenApiHeaderList} from '@broker-interceptor/schemas';

import {err, ok, type ForwarderResult} from './errors';
import {normalizeHeaderName, validateHeaderValue} from './headers';

const TRANSFER_ENCODING_TOKEN_REGEX = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

const parseContentLength = (headers: OpenApiHeaderList): ForwarderResult<number | null> => {
  const contentLengthValues: string[] = [];

  for (const header of headers) {
    const normalizedName = normalizeHeaderName(header.name);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    if (normalizedName.value !== 'content-length') {
      continue;
    }

    const normalizedValue = validateHeaderValue(header.value);
    if (!normalizedValue.ok) {
      return normalizedValue;
    }
    contentLengthValues.push(normalizedValue.value);
  }

  if (contentLengthValues.length === 0) {
    return ok(null);
  }

  if (contentLengthValues.length > 1) {
    return err(
      'ambiguous_framing_multiple_content_length',
      'Multiple Content-Length headers are not allowed'
    );
  }

  const [rawContentLength] = contentLengthValues;
  if (!/^\d+$/u.test(rawContentLength)) {
    return err('ambiguous_framing_invalid_content_length', 'Content-Length must be a positive integer');
  }

  const parsedContentLength = Number.parseInt(rawContentLength, 10);
  if (!Number.isSafeInteger(parsedContentLength) || parsedContentLength < 0) {
    return err('ambiguous_framing_invalid_content_length', 'Content-Length is out of range');
  }

  return ok(parsedContentLength);
};

const parseTransferEncoding = (headers: OpenApiHeaderList): ForwarderResult<string[]> => {
  const encodingTokens: string[] = [];

  for (const header of headers) {
    const normalizedName = normalizeHeaderName(header.name);
    if (!normalizedName.ok) {
      return normalizedName;
    }

    if (normalizedName.value !== 'transfer-encoding') {
      continue;
    }

    const normalizedValue = validateHeaderValue(header.value);
    if (!normalizedValue.ok) {
      return normalizedValue;
    }

    const splitTokens = normalizedValue.value.split(',');
    for (const token of splitTokens) {
      const normalizedToken = token.trim().toLowerCase();
      if (normalizedToken.length === 0) {
        continue;
      }

      if (!TRANSFER_ENCODING_TOKEN_REGEX.test(normalizedToken)) {
        return err(
          'ambiguous_framing_transfer_encoding_invalid',
          `Transfer-Encoding contains an invalid token: ${token}`
        );
      }

      encodingTokens.push(normalizedToken);
    }
  }

  if (encodingTokens.length > 0 && encodingTokens.at(-1) !== 'chunked') {
    return err(
      'ambiguous_framing_transfer_encoding_invalid',
      'Transfer-Encoding must end with chunked when present'
    );
  }

  return ok(encodingTokens);
};

export type RequestFramingValidationResult = {
  content_length: number | null;
  has_transfer_encoding: boolean;
};

export const validateRequestFraming = ({
  headers,
  body_byte_length
}: {
  headers: OpenApiHeaderList;
  body_byte_length: number;
}): ForwarderResult<RequestFramingValidationResult> => {
  const parsedContentLength = parseContentLength(headers);
  if (!parsedContentLength.ok) {
    return parsedContentLength;
  }

  const parsedTransferEncoding = parseTransferEncoding(headers);
  if (!parsedTransferEncoding.ok) {
    return parsedTransferEncoding;
  }

  if (parsedContentLength.value !== null && parsedTransferEncoding.value.length > 0) {
    return err(
      'ambiguous_framing_conflicting_content_length_transfer_encoding',
      'Conflicting Content-Length and Transfer-Encoding headers are not allowed'
    );
  }

  if (
    parsedContentLength.value !== null &&
    parsedContentLength.value !== body_byte_length
  ) {
    return err(
      'ambiguous_framing_content_length_mismatch',
      `Content-Length (${parsedContentLength.value}) does not match decoded body size (${body_byte_length})`
    );
  }

  return ok({
    content_length: parsedContentLength.value,
    has_transfer_encoding: parsedTransferEncoding.value.length > 0
  });
};
