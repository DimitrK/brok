import {describe, expect, it} from 'vitest';

import {BrokerAdminApiClient, useAdminStore} from '../index';

describe('public exports', () => {
  it('exports the API client and store', () => {
    expect(BrokerAdminApiClient).toBeTypeOf('function');
    expect(useAdminStore).toBeTypeOf('function');
  });
});
