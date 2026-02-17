import {randomUUID} from 'node:crypto';

import {KeyIdSchema} from './contracts.js';
import {err, ok, type CryptoResult} from './errors.js';

export type GenerateKeyIdInput = {
  prefix?: string;
};

export const generateKeyId = ({prefix = 'kid_'}: GenerateKeyIdInput = {}): CryptoResult<string> => {
  const candidate = `${prefix}${randomUUID().replaceAll('-', '')}`;
  const parsedCandidate = KeyIdSchema.safeParse(candidate);
  if (!parsedCandidate.success) {
    return err('invalid_key_id', parsedCandidate.error.message);
  }

  return ok(parsedCandidate.data);
};
