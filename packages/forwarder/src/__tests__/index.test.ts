import {describe, expect, it} from 'vitest';

import {createForwarderDbDependencyBridge_INCOMPLETE, packageName} from '../index';

describe('packageName', () => {
  it('exports the package name', () => {
    expect(packageName).toBe('forwarder');
  });

  it('exports the db dependency bridge factory', () => {
    expect(typeof createForwarderDbDependencyBridge_INCOMPLETE).toBe('function');
  });
});
