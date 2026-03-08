import {afterEach, describe, expect, it, vi} from 'vitest';

import {listManifestKeys} from '../s3.js';

describe('listManifestKeys', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('follows S3 list pagination to find manifest keys across pages', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        text: async () => `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>token-2</NextContinuationToken>
  <Contents>
    <Key>backups/broker/v000001-20260228T120000Z/manifest.json</Key>
  </Contents>
</ListBucketResult>`
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        text: async () => `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>backups/broker/v000002-20260228T121000Z/manifest.json</Key>
  </Contents>
</ListBucketResult>`
      } as Response);

    await expect(
      listManifestKeys({
        endpoint: 'https://backup-bucket.s3.eu-west-1.amazonaws.com',
        prefix: 'backups/broker',
        manifestFilename: 'manifest.json'
      })
    ).resolves.toEqual([
      'backups/broker/v000001-20260228T120000Z/manifest.json',
      'backups/broker/v000002-20260228T121000Z/manifest.json'
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[1]?.[0])).toContain('continuation-token=token-2');
  });
});
