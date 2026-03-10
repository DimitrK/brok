import type {Template} from '@broker-interceptor/schemas';

export const buildTemplate = (): Template => ({
  template_id: 'tpl_google_gmail_v1',
  version: 1,
  provider: 'google_gmail',
  description: 'Gmail minimal safe template',
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: ['gmail.googleapis.com'],
  redirect_policy: {
    mode: 'deny'
  },
  path_groups: [
    {
      group_id: 'gmail_read',
      risk_tier: 'low',
      approval_mode: 'none',
      methods: ['GET'],
      path_patterns: ['^/gmail/v1/users/[^/]+/messages(?:/[^/]+)?$'],
      query_allowlist: ['format', 'q'],
      header_forward_allowlist: ['accept', 'user-agent', 'x-custom'],
      body_policy: {
        max_bytes: 0,
        content_types: []
      }
    },
    {
      group_id: 'gmail_send',
      risk_tier: 'high',
      approval_mode: 'required',
      methods: ['POST'],
      path_patterns: ['^/gmail/v1/users/[^/]+/messages/send$'],
      query_allowlist: ['q'],
      header_forward_allowlist: ['content-type', 'accept'],
      body_policy: {
        max_bytes: 1_048_576,
        content_types: ['application/json']
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

export const buildS3Template = (): Template => ({
  template_id: 'tpl_s3_v1',
  version: 1,
  provider: 's3_compatible',
  description: 'S3-compatible minimal template',
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: ['storage.example.com'],
  redirect_policy: {
    mode: 'deny'
  },
  path_groups: [
    {
      group_id: 's3_list_objects',
      risk_tier: 'low',
      approval_mode: 'none',
      methods: ['GET'],
      path_patterns: ['^/$'],
      query_allowlist: ['continuation-token', 'list-type', 'prefix'],
      header_forward_allowlist: ['accept', 'x-amz-content-sha256', 'x-amz-date', 'x-amz-security-token'],
      body_policy: {
        max_bytes: 0,
        content_types: []
      },
      constraints: {
        upstream_auth: {
          type: 'aws_sigv4',
          service: 's3'
        }
      }
    },
    {
      group_id: 's3_object_rw',
      risk_tier: 'high',
      approval_mode: 'required',
      methods: ['GET', 'PUT'],
      path_patterns: ['^/[^?]+$'],
      query_allowlist: [],
      header_forward_allowlist: [
        'content-type',
        'x-amz-content-sha256',
        'x-amz-date',
        'x-amz-security-token'
      ],
      body_policy: {
        max_bytes: 10_485_760,
        content_types: ['application/json', 'application/octet-stream', 'text/plain']
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

export const buildAuthSensitiveTemplate = (): Template => ({
  template_id: 'tpl_signed_auth_v1',
  version: 1,
  provider: 'signed_example',
  description: 'Auth-sensitive canonicalization template',
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: ['signed.example.com'],
  redirect_policy: {
    mode: 'deny'
  },
  path_groups: [
    {
      group_id: 'signed_query',
      risk_tier: 'high',
      approval_mode: 'required',
      methods: ['GET'],
      path_patterns: ['^/signed$'],
      query_allowlist: [
        'X-Amz-Algorithm',
        'X-Amz-Credential',
        'X-Amz-Date',
        'X-Amz-Expires',
        'X-Amz-SignedHeaders',
        'X-Amz-Signature',
        'X-Amz-Security-Token'
      ],
      header_forward_allowlist: ['host', 'x-amz-date', 'x-amz-security-token'],
      body_policy: {
        max_bytes: 0,
        content_types: []
      },
      constraints: {
        allow_duplicate_query_keys: false,
        upstream_auth: {
          type: 'aws_sigv4',
          service: 's3'
        }
      }
    },
    {
      group_id: 'signed_body',
      risk_tier: 'high',
      approval_mode: 'required',
      methods: ['POST'],
      path_patterns: ['^/signed-body$'],
      query_allowlist: [],
      header_forward_allowlist: ['content-type', 'x-amz-content-sha256', 'x-amz-date'],
      body_policy: {
        max_bytes: 1_024,
        content_types: ['application/json']
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
