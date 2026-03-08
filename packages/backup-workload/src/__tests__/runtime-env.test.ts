import {describe, expect, it} from 'vitest';

import {parseDotEnv} from '../runtime-env.js';

describe('runtime env', () => {
  it('parses dotenv content used by the package launcher', () => {
    expect(
      parseDotEnv(`
# comment
export BACKUP_WORKLOAD_BROKER_URL=https://localhost:8081
BACKUP_WORKLOAD_WORKLOAD_ID="w_backup_workload"
BACKUP_WORKLOAD_MTLS_CERT_PATH='./certs/workload.crt'
INVALID-KEY=value
`)
    ).toEqual({
      BACKUP_WORKLOAD_BROKER_URL: 'https://localhost:8081',
      BACKUP_WORKLOAD_WORKLOAD_ID: 'w_backup_workload',
      BACKUP_WORKLOAD_MTLS_CERT_PATH: './certs/workload.crt'
    });
  });
});
