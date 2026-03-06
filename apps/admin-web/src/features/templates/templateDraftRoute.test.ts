import {describe, expect, it} from 'vitest';

import {parseTemplateDraftRouteState, readTemplateDraftFromStorage} from './templateDraftRoute';

const validDraftRouteState = {
  templateDraft: {
    source: 'audit',
    provider: 'custom',
    template_name: 'Custom backup create',
    template_id_suffix: 'custom_backup_create',
    description: 'Drafted from audit event evt_123',
    allowed_hosts: ['gateway.storjshare.io'],
    path_groups: [
      {
        group_id: 'backup_create',
        risk_tier: 'low',
        approval_mode: 'none',
        methods: ['GET', 'PUT'],
        path_patterns: ['^/.*$'],
        query_allowlist: ['list-type', 'prefix'],
        header_forward_allowlist: ['accept', 'content-type'],
        max_body_bytes: 262144,
        content_types: ['application/octet-stream'],
        upstream_auth: {
          type: 'aws_sigv4',
          region: 'eu-west-1'
        }
      }
    ]
  }
} as const;

describe('templateDraftRoute', () => {
  it('parses a valid route-state payload', () => {
    expect(parseTemplateDraftRouteState(validDraftRouteState)).toEqual(validDraftRouteState.templateDraft);
  });

  it('rejects invalid route-state payloads', () => {
    expect(parseTemplateDraftRouteState({templateDraft: {source: 'audit'}})).toBeUndefined();
  });

  it('reads and parses a stored draft payload', () => {
    const storage = {
      getItem: () => JSON.stringify(validDraftRouteState)
    };

    expect(readTemplateDraftFromStorage(storage)).toEqual(validDraftRouteState.templateDraft);
  });

  it('fails closed for malformed storage payloads', () => {
    const storage = {
      getItem: () => '{bad json'
    };

    expect(readTemplateDraftFromStorage(storage)).toBeUndefined();
  });
});
