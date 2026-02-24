import {describe, expect, it} from 'vitest';

import {mergeCursorPages} from './useCursorInfiniteQuery';

describe('useCursorInfiniteQuery', () => {
  it('merges pages in order when dedupe key is not provided', () => {
    const merged = mergeCursorPages({
      pages: [{items: [1, 2]}, {items: [3, 4]}],
      getItems: page => page.items
    });

    expect(merged).toEqual([1, 2, 3, 4]);
  });

  it('deduplicates by item key when provided', () => {
    const merged = mergeCursorPages({
      pages: [
        {items: [{id: 'a'}, {id: 'b'}]},
        {items: [{id: 'b'}, {id: 'c'}]}
      ],
      getItems: page => page.items,
      getItemKey: item => item.id
    });

    expect(merged.map(item => item.id)).toEqual(['a', 'b', 'c']);
  });
});
