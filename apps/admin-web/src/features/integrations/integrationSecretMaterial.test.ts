import {describe, expect, it} from 'vitest';

import {
  buildIntegrationSecretMaterial,
  createEmptyIntegrationSecretDraft,
  getIntegrationSecretAdapter,
  hasRequiredIntegrationSecretMaterial,
  integrationSecretTypeOptions
} from './integrationSecretMaterial';

describe('integrationSecretMaterial', () => {
  it('builds api key secret material', () => {
    expect(
      buildIntegrationSecretMaterial({
        ...createEmptyIntegrationSecretDraft('api_key'),
        secretValue: ' sk-test '
      })
    ).toEqual({
      type: 'api_key',
      value: 'sk-test'
    });
  });

  it('builds aws sigv4 secret material with optional session token', () => {
    expect(
      buildIntegrationSecretMaterial({
        ...createEmptyIntegrationSecretDraft('aws_sigv4'),
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
        ...createEmptyIntegrationSecretDraft('aws_sigv4'),
        accessKeyId: 'AKIA123',
        secretAccessKey: '',
        region: 'eu-west-1'
      })
    ).toBe(false);
  });

  it('requires a value for legacy secret types', () => {
    expect(
      hasRequiredIntegrationSecretMaterial({
        ...createEmptyIntegrationSecretDraft('oauth_refresh_token'),
        secretValue: '   '
      })
    ).toBe(false);
  });

  it('exposes registry-backed options and field metadata', () => {
    expect(integrationSecretTypeOptions).toEqual([
      {value: 'api_key', label: 'API key'},
      {value: 'oauth_refresh_token', label: 'OAuth refresh token'},
      {value: 'aws_sigv4', label: 'AWS SigV4'}
    ]);
    expect(getIntegrationSecretAdapter('aws_sigv4').fields.map(field => field.key)).toEqual([
      'accessKeyId',
      'region',
      'secretAccessKey',
      'sessionToken'
    ]);
  });
});
