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
