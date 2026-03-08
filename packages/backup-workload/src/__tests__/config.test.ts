import {describe, expect, it} from 'vitest';

import {loadConfig} from '../config.js';

const encryptionKeyB64 = Buffer.alloc(32, 7).toString('base64');

describe('loadConfig', () => {
  it('ignores unrelated process environment keys', () => {
    const config = loadConfig({
      BACKUP_WORKLOAD_BROKER_URL: 'https://localhost:8081',
      BACKUP_WORKLOAD_WORKLOAD_ID: 'w_backup_workload',
      BACKUP_WORKLOAD_S3_INTEGRATION_ID: 'int_backup_primary',
      BACKUP_WORKLOAD_MTLS_CERT_PATH: './certs/workload.crt',
      BACKUP_WORKLOAD_MTLS_KEY_PATH: './certs/workload.key',
      BACKUP_WORKLOAD_S3_ENDPOINT: 'https://backup-bucket.s3.eu-west-1.amazonaws.com',
      BACKUP_WORKLOAD_S3_PREFIX: 'backups/broker-prod',
      BACKUP_WORKLOAD_ENCRYPTION_KEY_B64: encryptionKeyB64,
      BACKUP_WORKLOAD_DATABASE_URL: 'postgresql://broker:broker@127.0.0.1:5432/broker',
      PATH: '/usr/bin',
      HOME: '/tmp/home',
      PNPM_SCRIPT_SRC_DIR: '/tmp/project',
      BROKER_URL: 'https://localhost:8081'
    });

    expect(config.broker.brokerUrl).toBe('https://localhost:8081');
    expect(config.broker.workloadId).toBe('w_backup_workload');
    expect(config.broker.s3IntegrationId).toBe('int_backup_primary');
    expect(config.broker.mtlsCertPath).toContain('/certs/workload.crt');
    expect(config.s3Endpoint).toBe('https://backup-bucket.s3.eu-west-1.amazonaws.com');
    expect(config.s3Prefix).toBe('backups/broker-prod');
    expect(config.databaseUrl).toBe('postgresql://broker:broker@127.0.0.1:5432/broker');
    expect(config.encryptionKey).toHaveLength(32);
  });
});
