import {describe, expect, it} from 'vitest';

import {buildNodeOptionsWithImport} from '../patch-child-process.js';

describe('buildNodeOptionsWithImport', () => {
  const importSpecifier = 'file:///tmp/preload.js';

  it('adds --import flag when NODE_OPTIONS is empty', () => {
    const result = buildNodeOptionsWithImport('', importSpecifier);
    expect(result).toBe(`--import=${importSpecifier}`);
  });

  it('appends --import flag to existing options', () => {
    const result = buildNodeOptionsWithImport('--trace-warnings', importSpecifier);
    expect(result).toContain('--trace-warnings');
    expect(result).toContain(`--import=${importSpecifier}`);
  });

  it('does not duplicate existing import flag', () => {
    const existing = `--trace-warnings --import=${importSpecifier}`;
    const result = buildNodeOptionsWithImport(existing, importSpecifier);
    expect(result).toBe(existing);
  });

  it('does not duplicate existing split --import token form', () => {
    const existing = `--trace-warnings --import ${importSpecifier}`;
    const result = buildNodeOptionsWithImport(existing, importSpecifier);
    expect(result).toBe(existing);
  });

  it('does not treat partial substring as an existing import specifier', () => {
    const existing = `--trace-warnings --conditions=${importSpecifier}`;
    const result = buildNodeOptionsWithImport(existing, importSpecifier);
    expect(result).toContain(`--conditions=${importSpecifier}`);
    expect(result).toContain(`--import=${importSpecifier}`);
  });
});
