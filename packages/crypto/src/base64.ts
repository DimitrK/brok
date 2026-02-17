import {timingSafeEqual} from 'node:crypto';

const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/u;
const BASE64_PAD_MOD = 4;

const padBase64 = (value: string) => {
  const normalized = value.trim();
  if (normalized.length === 0) {
    return null;
  }

  if (/[^A-Za-z0-9+/=]/u.test(normalized)) {
    return null;
  }

  const remainder = normalized.length % BASE64_PAD_MOD;
  if (remainder === 1) {
    return null;
  }

  if (remainder === 0) {
    return normalized;
  }

  const missingPadding = BASE64_PAD_MOD - remainder;
  return `${normalized}${'='.repeat(missingPadding)}`;
};

export const decodeBase64 = (value: string): Buffer | null => {
  const padded = padBase64(value);
  if (!padded || !BASE64_REGEX.test(padded)) {
    return null;
  }

  try {
    const decoded = Buffer.from(padded, 'base64');
    if (decoded.length === 0) {
      return null;
    }

    if (decoded.toString('base64') !== padded) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
};

export const encodeBase64 = (value: Uint8Array) => Buffer.from(value).toString('base64');

export const equalByteArrays = (left: Uint8Array, right: Uint8Array) => {
  if (left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(Buffer.from(left), Buffer.from(right));
};
