import {describe, expect, it} from 'vitest';

import {packageName} from '../index';

describe('packageName', () => {
  it('exports the package name', () => {
    expect(packageName).toBe('shared');
  });
});
