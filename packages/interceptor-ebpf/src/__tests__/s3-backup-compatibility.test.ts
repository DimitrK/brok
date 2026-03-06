import {describe, expect, it} from 'vitest';

import {verifyS3BackupEbpfCompatibility} from '../verification/s3-backup-compatibility.js';

const baseSecretMaterial = {
  type: 'aws_sigv4' as const,
  access_key_id: 'AKIAIOSFODNN7EXAMPLE',
  secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
  region: 'eu-west-1'
};

const baseConstraints = {
  upstream_auth: {
    type: 'aws_sigv4' as const,
    service: 's3' as const,
    region: 'eu-west-1'
  }
};

describe('verifyS3BackupEbpfCompatibility', () => {
  it('verifies bucket-root list requests as eBPF-compatible', () => {
    const result = verifyS3BackupEbpfCompatibility({
      secret_material: baseSecretMaterial,
      constraints: baseConstraints,
      request: {
        method: 'GET',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=backups%2Fbroker%2F'
      }
    });

    expect(result).toEqual({
      compatible: true,
      request_kind: 'bucket_list',
      transport: 'tcp',
      network_protocol: 'https',
      required_hooks: ['connect4', 'connect6'],
      http_shape_affects_socket_matching: false,
      reason:
        'Bucket-root list requests remain eBPF-compatible because socket interception depends on destination host/port over HTTPS, not on HTTP query shape.'
    });
  });

  it('verifies paginated bucket-root list requests as eBPF-compatible', () => {
    const result = verifyS3BackupEbpfCompatibility({
      secret_material: baseSecretMaterial,
      constraints: baseConstraints,
      request: {
        method: 'GET',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=backups%2Fbroker%2F&continuation-token=next-page-token'
      }
    });

    expect(result.request_kind).toBe('bucket_list');
    expect(result.required_hooks).toEqual(['connect4', 'connect6']);
  });

  it('verifies object write requests as eBPF-compatible', () => {
    const result = verifyS3BackupEbpfCompatibility({
      secret_material: {
        ...baseSecretMaterial,
        session_token: 'temporary-session-token'
      },
      constraints: baseConstraints,
      request: {
        method: 'PUT',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/broker/v000001-20260301T100000Z/manifest.json'
      }
    });

    expect(result.request_kind).toBe('object_write');
    expect(result.required_hooks).toEqual(['connect4', 'connect6']);
    expect(result.http_shape_affects_socket_matching).toBe(false);
  });

  it('verifies object read requests as eBPF-compatible', () => {
    const result = verifyS3BackupEbpfCompatibility({
      secret_material: baseSecretMaterial,
      constraints: baseConstraints,
      request: {
        method: 'GET',
        url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/broker/latest.json'
      }
    });

    expect(result.request_kind).toBe('object_read');
  });

  it('rejects non-S3 upstream auth constraints', () => {
    expect(() =>
      verifyS3BackupEbpfCompatibility({
        secret_material: baseSecretMaterial,
        constraints: {
          upstream_auth: {
            type: 'aws_sigv4',
            service: 'execute-api',
            region: 'eu-west-1'
          }
        },
        request: {
          method: 'GET',
          url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=backups%2Fbroker%2F'
        }
      })
    ).toThrow();
  });

  it('rejects non-SigV4 secret material', () => {
    expect(() =>
      verifyS3BackupEbpfCompatibility({
        secret_material: {
          type: 'api_key',
          value: 'not-valid-for-s3'
        },
        constraints: baseConstraints,
        request: {
          method: 'GET',
          url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=backups%2Fbroker%2F'
        }
      })
    ).toThrow('secret_material must be aws_sigv4');
  });

  it('rejects non-https requests', () => {
    expect(() =>
      verifyS3BackupEbpfCompatibility({
        secret_material: baseSecretMaterial,
        constraints: baseConstraints,
        request: {
          method: 'GET',
          url: 'http://backup-bucket.s3.eu-west-1.amazonaws.com/backups/broker/latest.json'
        }
      })
    ).toThrow('backup-workload S3 compatibility verification only supports https URLs');
  });

  it('rejects bucket-root GET requests that do not match list-object shape', () => {
    expect(() =>
      verifyS3BackupEbpfCompatibility({
        secret_material: baseSecretMaterial,
        constraints: baseConstraints,
        request: {
          method: 'GET',
          url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/'
        }
      })
    ).toThrow();
  });

  it('rejects root-path object writes', () => {
    expect(() =>
      verifyS3BackupEbpfCompatibility({
        secret_material: baseSecretMaterial,
        constraints: baseConstraints,
        request: {
          method: 'PUT',
          url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/'
        }
      })
    ).toThrow('object write requests must target an object path');
  });
});
