import {describe, expect, it} from 'vitest';

import {parseTemplateDiffSummaryLine} from './templateDiffPresentation';

describe('templateDiffPresentation', () => {
  it('parses +/- list style diff lines', () => {
    expect(parseTemplateDiffSummaryLine('Allowed hosts: +[api.openai.com] -[localhost]')).toEqual({
      kind: 'list',
      label: 'Allowed hosts',
      added: ['api.openai.com'],
      removed: ['localhost']
    });
  });

  it('parses changed from/to lines', () => {
    expect(parseTemplateDiffSummaryLine('Provider changed: openai -> anthropic')).toEqual({
      kind: 'change',
      label: 'Provider',
      before: 'openai',
      after: 'anthropic'
    });
  });

  it('parses added and removed list lines', () => {
    expect(parseTemplateDiffSummaryLine('Path groups added: responses_create, models_read')).toEqual({
      kind: 'list',
      label: 'Path groups',
      added: ['responses_create', 'models_read'],
      removed: []
    });
    expect(parseTemplateDiffSummaryLine('Path groups removed: legacy')).toEqual({
      kind: 'list',
      label: 'Path groups',
      added: [],
      removed: ['legacy']
    });
  });

  it('returns plain lines when no known format applies', () => {
    expect(parseTemplateDiffSummaryLine('No contract changes detected between these versions.')).toEqual({
      kind: 'plain',
      text: 'No contract changes detected between these versions.'
    });
  });
});
