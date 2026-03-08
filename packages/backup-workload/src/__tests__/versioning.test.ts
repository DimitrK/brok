import {describe, expect, it} from 'vitest';

import {
  buildBackupId,
  buildManifestKey,
  determineNextBackupVersion,
  parseBackupDescriptorFromManifestKey
} from '../versioning.js';

describe('backup versioning', () => {
  it('builds sortable backup identifiers', () => {
    expect(buildBackupId({version: 7, timestamp: '20260228T120000Z'})).toBe('v000007-20260228T120000Z');
  });

  it('parses manifest keys into descriptors', () => {
    const manifestKey = buildManifestKey({
      prefix: 'backups/broker',
      backupId: 'v000042-20260228T120000Z',
      manifestFilename: 'manifest.json'
    });

    expect(
      parseBackupDescriptorFromManifestKey({
        manifestKey,
        prefix: 'backups/broker'
      })
    ).toEqual({
      backupId: 'v000042-20260228T120000Z',
      version: 42,
      timestamp: '20260228T120000Z',
      manifestKey
    });
  });

  it('selects the next monotonically increasing version number', () => {
    expect(
      determineNextBackupVersion([
        {
          backupId: 'v000003-20260228T115000Z',
          version: 3,
          timestamp: '20260228T115000Z',
          manifestKey: 'backups/broker/v000003-20260228T115000Z/manifest.json'
        },
        {
          backupId: 'v000017-20260228T120000Z',
          version: 17,
          timestamp: '20260228T120000Z',
          manifestKey: 'backups/broker/v000017-20260228T120000Z/manifest.json'
        }
      ])
    ).toBe(18);
  });
});
