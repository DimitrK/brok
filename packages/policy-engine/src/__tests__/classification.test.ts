import {CanonicalRequestDescriptorSchema, TemplateSchema} from '@broker-interceptor/schemas'
import {describe, expect, it} from 'vitest'

import {buildCanonicalDescriptorWithPathGroup, classifyPathGroup} from '../classification'
import {PathGroupClassificationSchema} from '../contracts'

const baseTemplate = TemplateSchema.parse({
  template_id: 'tpl_gmail_safe',
  version: 1,
  provider: 'google_gmail',
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
      path_patterns: ['^/gmail/v1/users/[^/]+/messages$', '^/gmail/v1/users/[^/]+/messages/[^/]+$'],
      query_allowlist: ['q', 'pageToken'],
      header_forward_allowlist: ['accept'],
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
      query_allowlist: [],
      header_forward_allowlist: ['accept', 'content-type'],
      body_policy: {
        max_bytes: 1048576,
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
})

const expectMatchedPathGroup = (
  result: ReturnType<typeof classifyPathGroup>,
  expected: Record<string, unknown>
) => {
  expect(result).toMatchObject({
    matched: true,
    path_group: expected
  })
}

describe('classifyPathGroup', () => {
  it('classifies by host + method + path pattern', () => {
    const result = classifyPathGroup({
      template: baseTemplate,
      method: 'POST',
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send'
    })

    expectMatchedPathGroup(result, {
      path_group_id: 'gmail_send',
      group_id: 'gmail_send',
      risk_tier: 'high',
      approval_mode: 'required',
      methods: ['POST'],
      path_patterns: ['^/gmail/v1/users/[^/]+/messages/send$'],
      matched_pattern: '^/gmail/v1/users/[^/]+/messages/send$'
    })
  })

  it('returns no_matching_group when host is outside template host allowlist', () => {
    const result = classifyPathGroup({
      template: baseTemplate,
      method: 'POST',
      canonical_url: 'https://api.openai.com/gmail/v1/users/me/messages/send'
    })

    expect(result).toEqual({
      matched: false,
      reason_code: 'no_matching_group'
    })
  })

  it('returns invalid_path_pattern for unanchored template path pattern', () => {
    const templateWithUnanchoredPattern = TemplateSchema.parse({
      ...baseTemplate,
      path_groups: [
        {
          ...baseTemplate.path_groups[0],
          path_patterns: ['gmail/v1/users/[^/]+/messages']
        }
      ]
    })

    const result = classifyPathGroup({
      template: templateWithUnanchoredPattern,
      method: 'GET',
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages'
    })

    expect(result).toEqual({
      matched: false,
      reason_code: 'invalid_path_pattern'
    })
  })

  it('returns invalid_path_pattern for anchored but invalid regex', () => {
    const templateWithInvalidRegex = TemplateSchema.parse({
      ...baseTemplate,
      path_groups: [
        {
          ...baseTemplate.path_groups[0],
          path_patterns: ['^/gmail/v1/users/(messages$']
        }
      ]
    })

    const result = classifyPathGroup({
      template: templateWithInvalidRegex,
      method: 'GET',
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages'
    })

    expect(result).toEqual({
      matched: false,
      reason_code: 'invalid_path_pattern'
    })
  })

  it('classifies S3 bucket-root list operations using safe glob path patterns', () => {
    const s3Template = TemplateSchema.parse({
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
          group_id: 'bucket-objects',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['GET', 'PUT'],
          path_patterns: ['/', '/backups/**'],
          query_allowlist: ['list-type', 'prefix', 'continuation-token'],
          header_forward_allowlist: ['content-type', 'range'],
          body_policy: {
            max_bytes: 1048576,
            content_types: ['application/octet-stream', 'application/json']
          },
          constraints: {
            upstream_auth: {
              type: 'aws_sigv4',
              service: 's3',
              region: 'eu-west-1'
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
    })

    const result = classifyPathGroup({
      template: s3Template,
      method: 'GET',
      canonical_url:
        'https://backup-bucket.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=backups%2Fbroker%2F'
    })

    expectMatchedPathGroup(result, {
      path_group_id: 'bucket-objects',
      group_id: 'bucket-objects',
      risk_tier: 'medium',
      approval_mode: 'none',
      matched_pattern: '/',
      constraints: {
        upstream_auth: {
          type: 'aws_sigv4',
          service: 's3',
          region: 'eu-west-1'
        }
      }
    })
  })

  it('classifies S3 object operations using recursive safe glob path patterns', () => {
    const s3Template = TemplateSchema.parse({
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
          group_id: 'bucket-objects',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['GET', 'PUT'],
          path_patterns: ['/', '/backups/**'],
          query_allowlist: ['list-type', 'prefix', 'continuation-token'],
          header_forward_allowlist: ['content-type', 'range'],
          body_policy: {
            max_bytes: 1048576,
            content_types: ['application/octet-stream', 'application/json']
          },
          constraints: {
            upstream_auth: {
              type: 'aws_sigv4',
              service: 's3',
              region: 'eu-west-1'
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
    })

    const result = classifyPathGroup({
      template: s3Template,
      method: 'PUT',
      canonical_url:
        'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/broker/v000001-20260228T120000Z/manifest.json'
    })

    expectMatchedPathGroup(result, {
      path_group_id: 'bucket-objects',
      group_id: 'bucket-objects',
      risk_tier: 'medium',
      approval_mode: 'none',
      matched_pattern: '/backups/**',
      constraints: {
        upstream_auth: {
          type: 'aws_sigv4',
          service: 's3',
          region: 'eu-west-1'
        }
      }
    })
  })

  it('uses authored path-group order deterministically when overlapping auth-strategy groups match', () => {
    const overlappingTemplate = TemplateSchema.parse({
      template_id: 'tpl_runtime_auth_overlap',
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
          group_id: 'signed-primary',
          risk_tier: 'medium',
          approval_mode: 'none',
          methods: ['GET'],
          path_patterns: ['/backups/**'],
          query_allowlist: [],
          header_forward_allowlist: ['accept'],
          body_policy: {
            max_bytes: 0,
            content_types: []
          },
          constraints: {
            upstream_auth: {
              type: 'aws_sigv4',
              service: 's3',
              region: 'eu-west-1'
            }
          }
        },
        {
          group_id: 'signed-secondary',
          risk_tier: 'high',
          approval_mode: 'required',
          methods: ['GET'],
          path_patterns: ['/backups/**'],
          query_allowlist: [],
          header_forward_allowlist: ['accept'],
          body_policy: {
            max_bytes: 0,
            content_types: []
          },
          constraints: {
            upstream_auth: {
              type: 'aws_sigv4',
              service: 's3',
              region: 'us-east-1'
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
    })

    const result = classifyPathGroup({
      template: overlappingTemplate,
      method: 'GET',
      canonical_url: 'https://backup-bucket.s3.eu-west-1.amazonaws.com/backups/broker/manifest.json'
    })

    expectMatchedPathGroup(result, {
      path_group_id: 'signed-primary',
      group_id: 'signed-primary',
      risk_tier: 'medium',
      approval_mode: 'none',
      matched_pattern: '/backups/**',
      constraints: {
        upstream_auth: {
          type: 'aws_sigv4',
          service: 's3',
          region: 'eu-west-1'
        }
      }
    })
  })
})

describe('buildCanonicalDescriptorWithPathGroup', () => {
  it('builds a canonical descriptor with matched_path_group_id', () => {
    const descriptorInput = CanonicalRequestDescriptorSchema.omit({
      matched_path_group_id: true
    }).parse({
      tenant_id: 'tenant-1',
      workload_id: 'workload-1',
      integration_id: 'integration-1',
      template_id: baseTemplate.template_id,
      template_version: baseTemplate.version,
      method: 'GET',
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages',
      normalized_headers: [
        {
          name: 'accept',
          value: 'application/json'
        }
      ],
      query_keys: []
    })

    const result = buildCanonicalDescriptorWithPathGroup({
      descriptor: descriptorInput,
      template: baseTemplate
    })

    expect(result.ok).toBe(true)
    if (!result.ok) {
      return
    }

    expect(result.descriptor.matched_path_group_id).toBe('gmail_read')
    expect(result.path_group.risk_tier).toBe('low')
    expect(result.path_group.path_group_id).toBe('gmail_read')
  })

  it('returns failure when descriptor cannot be classified', () => {
    const descriptorInput = CanonicalRequestDescriptorSchema.omit({
      matched_path_group_id: true
    }).parse({
      tenant_id: 'tenant-1',
      workload_id: 'workload-1',
      integration_id: 'integration-1',
      template_id: baseTemplate.template_id,
      template_version: baseTemplate.version,
      method: 'GET',
      canonical_url: 'https://gmail.googleapis.com/gmail/v1/users/me/threads',
      normalized_headers: [],
      query_keys: []
    })

    const result = buildCanonicalDescriptorWithPathGroup({
      descriptor: descriptorInput,
      template: baseTemplate
    })

    expect(result).toEqual({
      ok: false,
      reason_code: 'no_matching_group'
    })
  })
})

describe('PathGroupClassificationSchema', () => {
  it('rejects mismatched compatibility aliases for path group ids', () => {
    expect(() =>
      PathGroupClassificationSchema.parse({
        path_group_id: 'gmail_send',
        group_id: 'gmail_read',
        risk_tier: 'high',
        approval_mode: 'required',
        methods: ['POST'],
        path_patterns: ['^/gmail/v1/users/[^/]+/messages/send$'],
        query_allowlist: [],
        header_forward_allowlist: ['accept', 'content-type'],
        body_policy: {
          max_bytes: 1048576,
          content_types: ['application/json']
        },
        matched_pattern: '^/gmail/v1/users/[^/]+/messages/send$'
      })
    ).toThrow('group_id must match path_group_id')
  })
})
