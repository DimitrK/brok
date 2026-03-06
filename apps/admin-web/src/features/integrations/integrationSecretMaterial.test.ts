import {describe, expect, it} from 'vitest';

import {
  buildIntegrationSecretMaterial,
  hasRequiredIntegrationSecretMaterial
} from './integrationSecretMaterial';

describe('integrationSecretMaterial', () => {
  it('builds api key secret material', () => {
    expect(
      buildIntegrationSecretMaterial({
        secretType: 'api_key',
        secretValue: ' sk-test ',
        accessKeyId: '',
        secretAccessKey: '',
        sessionToken: '',
        region: ''
      })
    ).toEqual({
      type: 'api_key',
      value: 'sk-test'
    });
  });

  it('builds aws sigv4 secret material with optional session token', () => {
    expect(
      buildIntegrationSecretMaterial({
        secretType: 'aws_sigv4',
        secretValue: '',
        accessKeyId: ' AKIA123 ',
        secretAccessKey: ' secret ',
        sessionToken: ' token ',
        region: ' eu-west-1 '
      })
    ).toEqual({
      type: 'aws_sigv4',
      access_key_id: 'AKIA123',
      secret_access_key: 'secret',
      session_token: 'token',
      region: 'eu-west-1'
    });
  });

  it('requires access key, secret key, and region for aws sigv4', () => {
    expect(
      hasRequiredIntegrationSecretMaterial({
        secretType: 'aws_sigv4',
        secretValue: '',
        accessKeyId: 'AKIA123',
        secretAccessKey: '',
        sessionToken: '',
        region: 'eu-west-1'
      })
    ).toBe(false);
  });

  it('requires a value for legacy secret types', () => {
    expect(
      hasRequiredIntegrationSecretMaterial({
        secretType: 'oauth_refresh_token',
        secretValue: '   ',
        accessKeyId: '',
        secretAccessKey: '',
        sessionToken: '',
        region: ''
      })
    ).toBe(false);
  });
});
