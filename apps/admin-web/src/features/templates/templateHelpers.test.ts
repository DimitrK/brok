import {describe, expect, it} from 'vitest';

import {
  TEMPLATE_ID_PREFIX,
  buildTemplateId,
  normalizeTemplateIdSuffix,
  splitTemplateId,
  toCsvList,
  toLineList
} from './templateHelpers';

describe('templateHelpers', () => {
  it('normalizes template id suffix values', () => {
    expect(normalizeTemplateIdSuffix(' Gmail Send v1 ')).toBe('gmail_send_v1');
    expect(normalizeTemplateIdSuffix('___OPENAI---RESPONSES___')).toBe('openai_responses');
  });

  it('builds template ids with fixed prefix', () => {
    expect(buildTemplateId('google_calendar')).toBe(`${TEMPLATE_ID_PREFIX}google_calendar`);
  });

  it('extracts template id suffix from full ids', () => {
    expect(splitTemplateId('tpl_openai_core_v1')).toBe('openai_core_v1');
    expect(splitTemplateId('custom template')).toBe('custom_template');
  });

  it('parses csv and multiline lists', () => {
    expect(toCsvList('a, b,, c')).toEqual(['a', 'b', 'c']);
    expect(toLineList('^/v1/a$\n\n^/v1/b$')).toEqual(['^/v1/a$', '^/v1/b$']);
  });
});
