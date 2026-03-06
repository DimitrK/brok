import {describe, expect, it} from 'vitest';

import {
  buildTemplatePathGroupConstraints,
  resolveTemplateUpstreamAuthMode,
  resolveTemplateUpstreamAuthRegion,
  s3ListObjectsPathGroupPreset
} from './templateS3Auth';

describe('templateS3Auth', () => {
  it('builds aws sigv4 template constraints with optional region', () => {
    expect(
      buildTemplatePathGroupConstraints({
        upstreamAuthMode: 'aws_sigv4',
        upstreamAuthRegion: ' eu-west-1 '
      })
    ).toEqual({
      upstream_auth: {
        type: 'aws_sigv4',
        service: 's3',
        region: 'eu-west-1'
      }
    });
  });

  it('omits constraints when upstream auth is disabled', () => {
    expect(
      buildTemplatePathGroupConstraints({
        upstreamAuthMode: 'none',
        upstreamAuthRegion: 'eu-west-1'
      })
    ).toBeUndefined();
  });

  it('reads upstream auth state from template path groups', () => {
    const pathGroup = {
      constraints: {
        upstream_auth: {
          type: 'aws_sigv4' as const,
          service: 's3' as const,
          region: 'us-east-1'
        }
      }
    };

    expect(resolveTemplateUpstreamAuthMode(pathGroup)).toBe('aws_sigv4');
    expect(resolveTemplateUpstreamAuthRegion(pathGroup)).toBe('us-east-1');
  });

  it('exposes bucket-root list objects preset guidance', () => {
    expect(s3ListObjectsPathGroupPreset.pathPatterns).toBe('^/$');
    expect(s3ListObjectsPathGroupPreset.upstreamAuthMode).toBe('aws_sigv4');
    expect(s3ListObjectsPathGroupPreset.queryAllowlist).toContain('list-type');
  });
});
