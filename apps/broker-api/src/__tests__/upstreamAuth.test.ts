import {describe, expect, it} from 'vitest';

import {OpenApiTemplateSchema} from '@broker-interceptor/schemas';

import {buildExecuteAuthHeaders} from '../upstreamAuth';

const baseTemplate = OpenApiTemplateSchema.parse({
  template_id: 'tpl_backup_s3',
  version: 1,
  provider: 'aws_s3',
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: ['backup-bucket.s3.eu-west-1.amazonaws.com'],
  redirect_policy: {
    mode: 'deny'
  },
  path_groups: [
    {
      group_id: 'bucket-object',
      risk_tier: 'medium',
      approval_mode: 'none',
      methods: ['GET', 'PUT', 'POST'],
      path_patterns: ['/**'],
      query_allowlist: ['uploads', 'partNumber', 'uploadId', 'list-type', 'prefix', 'continuation-token'],
      header_forward_allowlist: ['content-type', 'range'],
      body_policy: {
        max_bytes: 1024 * 1024,
        content_types: ['application/octet-stream', 'application/xml', 'application/json']
      },
      constraints: {
        upstream_auth: {
          type: 'aws_sigv4',
          service: 's3'
        }
      }
    }
  ],
  network_safety: {
    deny_private_ip_ranges: true,
    deny_link_local: true,
    deny_loopback: true,
    deny_metadata_ranges: true,
    dns_resolution_required: true
  }
});

describe('buildExecuteAuthHeaders', () => {
  it('returns bearer auth when no special upstream auth is configured', () => {
    const headers = buildExecuteAuthHeaders({
      secretValue: 'plain-token',
      request: {
        method: 'GET',
        url: 'https://example.com/healthz',
        headers: []
      },
      template: OpenApiTemplateSchema.parse({
        ...baseTemplate,
        allowed_hosts: ['example.com'],
        path_groups: [
          {
            ...baseTemplate.path_groups[0],
            constraints: {}
          }
        ]
      }),
      matchedPathGroupId: 'bucket-object',
      now: new Date('2026-02-28T12:00:00.000Z')
    });

    expect(headers).toEqual([{name: 'Authorization', value: 'Bearer plain-token'}]);
  });

  it('builds SigV4 headers for S3 requests using the request body hash', () => {
    const headers = buildExecuteAuthHeaders({
      secretValue: JSON.stringify({
        access_key_id: 'AKIDEXAMPLE',
        secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
      }),
      request: {
        method: 'PUT',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/backup-000001-20260228T120000Z/payload.bin',
        headers: [{name: 'content-type', value: 'application/octet-stream'}],
        body_base64: Buffer.from('backup-payload', 'utf8').toString('base64')
      },
      template: baseTemplate,
      matchedPathGroupId: 'bucket-object',
      now: new Date('2026-02-28T12:00:00.000Z')
    });

    expect(headers).toEqual([
      {
        name: 'Authorization',
        value:
          'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260228/eu-west-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=ccb490fad1fffe3af2c65dadf32107f879c0f691e2750079fca9fcc55e8f803c'
      },
      {
        name: 'x-amz-content-sha256',
        value: '969013ee227b12e4b1024fc474aaded7b0decbf32e858e1d6e14dd2c940cfba2'
      },
      {
        name: 'x-amz-date',
        value: '20260228T120000Z'
      }
    ]);
  });

  it('adds the session token when temporary AWS credentials are used', () => {
    const headers = buildExecuteAuthHeaders({
      secretValue: JSON.stringify({
        access_key_id: 'AKIDEXAMPLE',
        secret_access_key: 'secret',
        session_token: 'session-token-value',
        region: 'eu-west-1'
      }),
      request: {
        method: 'GET',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/latest.json',
        headers: [{name: 'range', value: 'bytes=0-511'}]
      },
      template: baseTemplate,
      matchedPathGroupId: 'bucket-object',
      now: new Date('2026-02-28T12:00:00.000Z')
    });

    expect(headers.find(header => header.name === 'x-amz-security-token')).toEqual({
      name: 'x-amz-security-token',
      value: 'session-token-value'
    });
    expect(headers.find(header => header.name === 'Authorization')?.value).toContain(
      'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date;x-amz-security-token'
    );
  });

  it('signs bucket-root list-object requests deterministically', () => {
    const headers = buildExecuteAuthHeaders({
      secretValue: JSON.stringify({
        access_key_id: 'AKIDEXAMPLE',
        secret_access_key: 'secret',
        region: 'eu-west-1'
      }),
      request: {
        method: 'GET',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/?prefix=backups%2F&continuation-token=next-page&list-type=2',
        headers: []
      },
      template: baseTemplate,
      matchedPathGroupId: 'bucket-object',
      now: new Date('2026-02-28T12:00:00.000Z')
    });

    expect(headers.find(header => header.name === 'Authorization')?.value).toContain(
      'Credential=AKIDEXAMPLE/20260228/eu-west-1/s3/aws4_request'
    );
    expect(headers.find(header => header.name === 'Authorization')?.value).toContain(
      'SignedHeaders=host;x-amz-content-sha256;x-amz-date'
    );
  });

  it('signs non-AWS S3-compatible hosts when an explicit region is configured', () => {
    const template = OpenApiTemplateSchema.parse({
      ...baseTemplate,
      allowed_hosts: ['storage.example.internal'],
      path_groups: [
        {
          ...baseTemplate.path_groups[0],
          constraints: {
            upstream_auth: {
              type: 'aws_sigv4',
              service: 's3',
              region: 'eu-central-1'
            }
          }
        }
      ]
    });

    const headers = buildExecuteAuthHeaders({
      secretValue: JSON.stringify({
        access_key_id: 'AKIDEXAMPLE',
        secret_access_key: 'secret'
      }),
      request: {
        method: 'GET',
        url: 'https://storage.example.internal/backups/latest.json',
        headers: []
      },
      template,
      matchedPathGroupId: 'bucket-object',
      now: new Date('2026-02-28T12:00:00.000Z')
    });

    expect(headers.find(header => header.name === 'Authorization')?.value).toContain(
      'Credential=AKIDEXAMPLE/20260228/eu-central-1/s3/aws4_request'
    );
  });

  it('does not double-encode percent-escaped S3 object key segments when signing', () => {
    const headers = buildExecuteAuthHeaders({
      secretValue: JSON.stringify({
        access_key_id: 'AKIDEXAMPLE',
        secret_access_key: 'secret',
        region: 'eu-west-1'
      }),
      request: {
        method: 'GET',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/quarter%201/report%252F2026.json',
        headers: []
      },
      template: baseTemplate,
      matchedPathGroupId: 'bucket-object',
      now: new Date('2026-02-28T12:00:00.000Z')
    });

    expect(headers.find(header => header.name === 'Authorization')).toEqual({
      name: 'Authorization',
      value:
        'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260228/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=dd4af051c8303788cab0370fcbe6bd4a5daeb8f39ff12d8cfe5d8210d6949f0d'
    });
  });

  it('fails closed for non-AWS S3-compatible hosts when no explicit region is available', () => {
    const template = OpenApiTemplateSchema.parse({
      ...baseTemplate,
      allowed_hosts: ['storage.example.internal']
    });

    expect(() =>
      buildExecuteAuthHeaders({
        secretValue: JSON.stringify({
          access_key_id: 'AKIDEXAMPLE',
          secret_access_key: 'secret'
        }),
        request: {
          method: 'GET',
          url: 'https://storage.example.internal/backups/latest.json',
          headers: []
        },
        template,
        matchedPathGroupId: 'bucket-object',
        now: new Date('2026-02-28T12:00:00.000Z')
      })
    ).toThrow('Unable to derive AWS region for S3 request host storage.example.internal');
  });

  it('does not sign headers that are not forwarded by the matched path group allowlist', () => {
    const headers = buildExecuteAuthHeaders({
      secretValue: JSON.stringify({
        access_key_id: 'AKIDEXAMPLE',
        secret_access_key: 'secret',
        region: 'eu-west-1'
      }),
      request: {
        method: 'PUT',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/latest.bin',
        headers: [
          {name: 'content-type', value: 'application/octet-stream'},
          {name: 'x-extra-debug-header', value: 'should-not-be-signed'}
        ],
        body_base64: Buffer.from('payload', 'utf8').toString('base64')
      },
      template: baseTemplate,
      matchedPathGroupId: 'bucket-object',
      now: new Date('2026-02-28T12:00:00.000Z')
    });

    expect(headers.find(header => header.name === 'Authorization')?.value).toContain(
      'SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date'
    );
    expect(headers.find(header => header.name === 'Authorization')?.value).not.toContain('x-extra-debug-header');
  });
});
