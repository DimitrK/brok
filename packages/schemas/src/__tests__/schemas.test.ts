import {describe, expect, it} from 'vitest';

import {
  OpenApiIntegrationSecretMaterialWriteSchema,
  SecretMaterialTypeSchema,
  SecretMaterialSchema,
  TemplatePathGroupConstraintsSchema,
  UpstreamAuthStrategySchema,
  UpstreamAuthTypeSchema
} from '../index';

describe('@broker-interceptor/schemas secret material contracts', () => {
  it('exports secret material types for downstream envelope and repository contracts', () => {
    expect(SecretMaterialTypeSchema.parse('aws_sigv4')).toBe('aws_sigv4');
    expect(SecretMaterialTypeSchema.safeParse('unsupported').success).toBe(false);
  });

  it('accepts aws_sigv4 secret material with optional session token', () => {
    const payload = {
      type: 'aws_sigv4',
      access_key_id: 'AKIAIOSFODNN7EXAMPLE',
      secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      session_token: 'temporary-session-token',
      region: 'eu-central-1'
    };

    expect(SecretMaterialSchema.parse(payload)).toEqual(payload);
    expect(OpenApiIntegrationSecretMaterialWriteSchema.parse(payload)).toEqual(payload);
  });

  it('preserves storage compatibility for typed secret material', () => {
    const payload = {
      type: 'aws_sigv4',
      access_key_id: 'AKIAIOSFODNN7EXAMPLE',
      secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      region: 'eu-central-1'
    };

    expect(SecretMaterialSchema.safeParse(payload).success).toBe(true);
  });

  it('rejects mixed secret-material variants at the write boundary', () => {
    const payload = {
      type: 'aws_sigv4',
      value: 'should-not-be-accepted',
      access_key_id: 'AKIAIOSFODNN7EXAMPLE',
      secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      region: 'eu-central-1'
    };

    expect(OpenApiIntegrationSecretMaterialWriteSchema.safeParse(payload).success).toBe(false);
  });

  it('rejects incomplete aws_sigv4 secret material at the write boundary', () => {
    const payload = {
      type: 'aws_sigv4',
      access_key_id: 'AKIAIOSFODNN7EXAMPLE',
      region: 'eu-central-1'
    };

    expect(SecretMaterialSchema.safeParse(payload).success).toBe(false);
    expect(OpenApiIntegrationSecretMaterialWriteSchema.safeParse(payload).success).toBe(false);
  });
});

describe('@broker-interceptor/schemas template constraints', () => {
  it('exports upstream auth discriminator types for downstream strategy selection', () => {
    expect(UpstreamAuthTypeSchema.parse('aws_sigv4')).toBe('aws_sigv4');
    expect(UpstreamAuthTypeSchema.safeParse('unsupported').success).toBe(false);
  });

  it('accepts aws_sigv4 s3 upstream auth constraints with optional region override', () => {
    const upstreamAuth = {
      type: 'aws_sigv4',
      service: 's3',
      region: 'us-east-1'
    };
    const payload = {
      upstream_auth: upstreamAuth
    };

    expect(UpstreamAuthStrategySchema.parse(upstreamAuth)).toEqual(upstreamAuth);
    expect(TemplatePathGroupConstraintsSchema.parse(payload)).toEqual(payload);
  });

  it('rejects unsupported upstream auth services for aws_sigv4', () => {
    const payload = {
      upstream_auth: {
        type: 'aws_sigv4',
        service: 'execute-api',
        region: 'us-east-1'
      }
    };

    expect(TemplatePathGroupConstraintsSchema.safeParse(payload).success).toBe(false);
  });
});
