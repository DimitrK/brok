import {describe, expect, expectTypeOf, it} from 'vitest';

import {
  OpenApiIntegrationSecretMaterialWriteSchema,
  type OpenApiIntegrationSecretMaterialWrite
} from '@broker-interceptor/schemas';

import {issueSession} from '../session';

describe('shared contract compatibility', () => {
  it('typechecks against the expanded integration secret material union', () => {
    expectTypeOf<OpenApiIntegrationSecretMaterialWrite>().toMatchTypeOf<
      | {type: 'api_key'; value: string}
      | {type: 'oauth_refresh_token'; value: string}
      | {
          type: 'aws_sigv4';
          access_key_id: string;
          secret_access_key: string;
          region: string;
          session_token?: string;
        }
    >();
  });

  it('accepts aws sigv4 secret material via the shared OpenAPI source of truth', () => {
    const parsed = OpenApiIntegrationSecretMaterialWriteSchema.safeParse({
      type: 'aws_sigv4',
      access_key_id: 'AKIAIOSFODNN7EXAMPLE',
      secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      session_token: 'session-token',
      region: 'eu-central-1'
    });

    expect(parsed.success).toBe(true);
  });

  it('keeps auth session issuance independent from integration secret variants', () => {
    const issued = issueSession({
      workloadId: 'workload-1',
      tenantId: 'tenant-1',
      certFingerprint256: 'AA:BB:CC',
      ttlSeconds: 300,
      now: new Date('2026-02-28T00:00:00.000Z')
    });

    expect(issued.session).toMatchObject({
      workloadId: 'workload-1',
      tenantId: 'tenant-1',
      certFingerprint256: 'AA:BB:CC'
    });
  });
});
