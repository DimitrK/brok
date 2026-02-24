import type {OpenApiTemplate} from '@broker-interceptor/schemas';
import {describe, expect, it} from 'vitest';

import {buildTemplateVersionIndex, getLatestTemplateVersions, summarizeTemplateVersionDiff} from './templateVersioning';

const makeTemplate = (overrides: Partial<OpenApiTemplate>): OpenApiTemplate => ({
  template_id: overrides.template_id ?? 'tpl_openai_core_v1',
  version: overrides.version ?? 1,
  provider: overrides.provider ?? 'openai',
  ...(overrides.description ? {description: overrides.description} : {}),
  allowed_schemes: ['https'],
  allowed_ports: [443],
  allowed_hosts: overrides.allowed_hosts ?? ['api.openai.com'],
  redirect_policy: {mode: 'deny'},
  path_groups: overrides.path_groups ?? [
    {
      group_id: 'responses_create',
      risk_tier: 'low',
      approval_mode: 'none',
      methods: ['POST'],
      path_patterns: ['^/v1/responses$'],
      query_allowlist: [],
      header_forward_allowlist: ['content-type'],
      body_policy: {
        max_bytes: 262144,
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

describe('templateVersioning', () => {
  it('indexes templates by id and sorts version history descending', () => {
    const index = buildTemplateVersionIndex([
      makeTemplate({template_id: 'tpl_a', version: 1}),
      makeTemplate({template_id: 'tpl_a', version: 3}),
      makeTemplate({template_id: 'tpl_a', version: 2}),
      makeTemplate({template_id: 'tpl_b', version: 1})
    ]);

    expect(index.get('tpl_a')?.map(template => template.version)).toEqual([3, 2, 1]);
    expect(index.get('tpl_b')?.map(template => template.version)).toEqual([1]);
  });

  it('returns latest version only for each template id', () => {
    const index = buildTemplateVersionIndex([
      makeTemplate({template_id: 'tpl_a', version: 2}),
      makeTemplate({template_id: 'tpl_a', version: 3}),
      makeTemplate({template_id: 'tpl_a', version: 1}),
      makeTemplate({template_id: 'tpl_b', version: 1})
    ]);

    const latest = getLatestTemplateVersions(index);
    expect(
      latest.map(template => ({
        id: template.template_id,
        version: template.version
      }))
    ).toEqual([
      {id: 'tpl_a', version: 3},
      {id: 'tpl_b', version: 1}
    ]);
  });

  it('summarizes meaningful diffs between adjacent versions', () => {
    const previous = makeTemplate({
      version: 2,
      allowed_hosts: ['api.openai.com'],
      path_groups: [
        {
          group_id: 'responses_create',
          risk_tier: 'low',
          approval_mode: 'none',
          methods: ['POST'],
          path_patterns: ['^/v1/responses$'],
          query_allowlist: [],
          header_forward_allowlist: ['content-type'],
          body_policy: {
            max_bytes: 262144,
            content_types: ['application/json']
          }
        }
      ]
    });

    const current = makeTemplate({
      version: 3,
      allowed_hosts: ['api.openai.com', 'api.openai.eu'],
      path_groups: [
        {
          group_id: 'responses_create',
          risk_tier: 'high',
          approval_mode: 'required',
          methods: ['POST', 'GET'],
          path_patterns: ['^/v1/responses(?:/.*)?$'],
          query_allowlist: ['model'],
          header_forward_allowlist: ['content-type', 'accept'],
          body_policy: {
            max_bytes: 524288,
            content_types: ['application/json']
          }
        }
      ]
    });

    const summary = summarizeTemplateVersionDiff(previous, current);
    expect(summary.some(line => line.includes('Allowed hosts'))).toBe(true);
    expect(summary.some(line => line.includes('risk tier changed'))).toBe(true);
    expect(summary.some(line => line.includes('approval mode changed'))).toBe(true);
    expect(summary.some(line => line.includes('methods'))).toBe(true);
  });
});
