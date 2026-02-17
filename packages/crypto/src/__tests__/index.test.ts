import {describe, expect, it} from 'vitest';

import {buildManifestKeySet, createAesGcmKeyManagementService, encryptWithEnvelope} from '../index';

describe('package exports', () => {
  it('exposes crypto primitives', async () => {
    const kms = createAesGcmKeyManagementService({
      active_key_id: 'kek_v1',
      keys: {
        kek_v1: Buffer.alloc(32, 1).toString('base64')
      }
    });

    expect(kms.ok).toBe(true);

    if (!kms.ok) {
      return;
    }

    const encrypted = await encryptWithEnvelope({
      plaintext: Buffer.from('secret-value'),
      key_management_service: kms.value
    });

    expect(encrypted.ok).toBe(true);

    const keySet = buildManifestKeySet({
      keys: []
    });
    expect(keySet.ok).toBe(true);
  });
});
