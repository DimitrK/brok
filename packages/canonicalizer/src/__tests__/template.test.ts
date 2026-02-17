import {describe, expect, it} from 'vitest';

import {compileCanonicalizerTemplate, validateTemplateForUpload, validateTemplatePublish} from '../index';
import {buildTemplate} from './fixtures/canonicalization-vectors';

describe('compileCanonicalizerTemplate', () => {
  it('compiles a valid template', () => {
    const compiled = compileCanonicalizerTemplate(buildTemplate());
    expect(compiled.ok).toBe(true);
    if (!compiled.ok) {
      return;
    }

    expect(compiled.value.template.template_id).toBe('tpl_google_gmail_v1');
    expect(compiled.value.allowedHosts.has('gmail.googleapis.com')).toBe(true);
    expect(compiled.value.pathGroups).toHaveLength(2);
  });

  it('rejects wildcard hosts', () => {
    const template = buildTemplate();
    template.allowed_hosts = ['*.googleapis.com'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_host_wildcard_forbidden');
    expect(compiled.error.message).toContain('Wildcard host allowlists');
  });

  it('normalizes IDNA and trailing-dot hosts', () => {
    const template = buildTemplate();
    template.allowed_hosts = ['BÜCHER.EXAMPLE.'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(true);
    if (!compiled.ok) {
      return;
    }

    expect(compiled.value.allowedHosts.has('xn--bcher-kva.example')).toBe(true);
  });

  it('rejects invalid bracketed IPv6 hosts', () => {
    const template = buildTemplate();
    template.allowed_hosts = ['[invalid-ipv6]'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_host_invalid');
  });

  it('rejects domain hosts that fail IDNA normalization', () => {
    const template = buildTemplate();
    template.allowed_hosts = ['exa mple.com'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_host_invalid');
  });

  it('rejects duplicate allowed schemes', () => {
    const template = buildTemplate();
    template.allowed_schemes = ['https', 'https'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_allowlist_duplicate');
  });

  it('rejects duplicate allowed ports', () => {
    const template = buildTemplate();
    template.allowed_ports = [443, 443];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_allowlist_duplicate');
  });

  it('rejects duplicate hosts after normalization', () => {
    const template = buildTemplate();
    template.allowed_hosts = ['gmail.googleapis.com.', 'GMAIL.GOOGLEAPIS.COM'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_allowlist_duplicate');
  });

  it('rejects unanchored path regex', () => {
    const template = buildTemplate();
    template.path_groups[0].path_patterns = ['/gmail/v1/users/[^/]+/messages'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_path_pattern_unanchored');
    expect(compiled.error.message).toContain('must be anchored');
  });

  it('rejects overbroad regex', () => {
    const template = buildTemplate();
    template.path_groups[0].path_patterns = ['^.*$'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_path_pattern_overbroad');
    expect(compiled.error.message).toContain('Overbroad path pattern');
  });

  it('rejects potentially unsafe regex', () => {
    const template = buildTemplate();
    template.path_groups[0].path_patterns = ['^/(a+)+$'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_path_pattern_unsafe');
  });

  it('rejects duplicate path groups', () => {
    const template = buildTemplate();
    template.path_groups[1].group_id = template.path_groups[0].group_id;

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_group_duplicate');
    expect(compiled.error.message).toContain('duplicate path group id');
  });

  it('rejects duplicate methods in a path group', () => {
    const template = buildTemplate();
    template.path_groups[0].methods = ['GET', 'GET'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_allowlist_duplicate');
  });

  it('rejects duplicate query allowlist entries in a path group', () => {
    const template = buildTemplate();
    template.path_groups[0].query_allowlist = ['q', 'q'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_allowlist_duplicate');
  });

  it('rejects duplicate header allowlist entries in a path group', () => {
    const template = buildTemplate();
    template.path_groups[0].header_forward_allowlist = ['accept', 'Accept'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_allowlist_duplicate');
  });

  it('rejects invalid regular expression syntax in path patterns', () => {
    const template = buildTemplate();
    template.path_groups[0].path_patterns = ['^(/gmail$'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_path_pattern_invalid');
  });

  it('rejects invalid header allowlist entry', () => {
    const template = buildTemplate();
    template.path_groups[0].header_forward_allowlist = ['content type'];

    const compiled = compileCanonicalizerTemplate(template);
    expect(compiled.ok).toBe(false);
    if (compiled.ok) {
      return;
    }
    expect(compiled.error.code).toBe('template_header_allowlist_invalid');
    expect(compiled.error.message).toContain('Invalid header allowlist entry');
  });

  it('validates template for upload', () => {
    const result = validateTemplateForUpload(buildTemplate());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.version).toBe(1);
  });

  it('rejects invalid template for upload', () => {
    const template = buildTemplate();
    template.allowed_hosts = ['*.googleapis.com'];

    const result = validateTemplateForUpload(template);
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('template_host_wildcard_forbidden');
  });

  it('allows publishing when template_id differs from existing templates', () => {
    const published = buildTemplate();
    const candidate = buildTemplate();
    candidate.template_id = 'tpl_google_calendar_v1';

    const result = validateTemplatePublish({
      candidate,
      existing_templates: [published]
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.template_id).toBe('tpl_google_calendar_v1');
  });

  it('allows publishing a strictly newer template version', () => {
    const published = buildTemplate();
    const nextVersion = buildTemplate();
    nextVersion.version = 2;

    const result = validateTemplatePublish({
      candidate: nextVersion,
      existing_templates: [published]
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.version).toBe(2);
  });

  it('rejects publishing the same version with changed contents', () => {
    const published = buildTemplate();
    const sameVersionChanged = buildTemplate();
    sameVersionChanged.description = 'changed';

    const result = validateTemplatePublish({
      candidate: sameVersionChanged,
      existing_templates: [published]
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('template_version_immutable');
  });

  it('rejects non-incrementing version publish', () => {
    const v2 = buildTemplate();
    v2.version = 2;
    const v3 = buildTemplate();
    v3.version = 3;

    const stale = buildTemplate();
    stale.version = 2;

    const result = validateTemplatePublish({
      candidate: stale,
      existing_templates: [v2, v3]
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('template_version_conflict');
  });

  it('rejects version lower than latest published version', () => {
    const v2 = buildTemplate();
    v2.version = 2;
    const v3 = buildTemplate();
    v3.version = 3;

    const stale = buildTemplate();
    stale.version = 1;

    const result = validateTemplatePublish({
      candidate: stale,
      existing_templates: [v2, v3]
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('template_version_not_incremented');
  });

  it('rejects provider change for the same template id', () => {
    const published = buildTemplate();
    const nextVersion = buildTemplate();
    nextVersion.version = 2;
    nextVersion.provider = 'openai';

    const result = validateTemplatePublish({
      candidate: nextVersion,
      existing_templates: [published]
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('template_provider_mismatch');
  });

  it('rejects publish when candidate template is invalid', () => {
    const candidate = buildTemplate();
    candidate.allowed_hosts = ['*.googleapis.com'];

    const result = validateTemplatePublish({
      candidate,
      existing_templates: []
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('template_host_wildcard_forbidden');
  });

  it('rejects publish when existing_templates contains invalid template entries', () => {
    const result = validateTemplatePublish({
      candidate: buildTemplate(),
      existing_templates: [{template_id: 'invalid'}]
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.code).toBe('invalid_template');
  });
});
