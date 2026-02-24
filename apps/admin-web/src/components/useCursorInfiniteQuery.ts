import {useMemo} from 'react';
import {useInfiniteQuery, type QueryKey} from '@tanstack/react-query';

type MergeCursorPagesInput<TPage, TItem> = {
  pages: TPage[] | undefined;
  getItems: (page: TPage) => TItem[];
  getItemKey?: (item: TItem) => string;
};

export const mergeCursorPages = <TPage, TItem>(input: MergeCursorPagesInput<TPage, TItem>) => {
  const merged: TItem[] = [];

  if (!input.pages) {
    return merged;
  }

  if (!input.getItemKey) {
    for (const page of input.pages) {
      merged.push(...input.getItems(page));
    }
    return merged;
  }

  const seenKeys = new Set<string>();
  for (const page of input.pages) {
    for (const item of input.getItems(page)) {
      const itemKey = input.getItemKey(item);
      if (seenKeys.has(itemKey)) {
        continue;
      }
      seenKeys.add(itemKey);
      merged.push(item);
    }
  }

  return merged;
};

type UseCursorInfiniteQueryInput<TPage, TItem> = {
  queryKey: QueryKey;
  queryPage: (input: {cursor?: string; signal?: AbortSignal}) => Promise<TPage>;
  getItems: (page: TPage) => TItem[];
  getNextCursor: (page: TPage) => string | undefined;
  getItemKey?: (item: TItem) => string;
  enabled?: boolean;
};

export const useCursorInfiniteQuery = <TPage, TItem>(input: UseCursorInfiniteQueryInput<TPage, TItem>) => {
  const query = useInfiniteQuery({
    queryKey: input.queryKey,
    initialPageParam: undefined as string | undefined,
    queryFn: ({signal, pageParam}) => input.queryPage({cursor: pageParam, signal}),
    getNextPageParam: lastPage => input.getNextCursor(lastPage),
    ...(input.enabled === undefined ? {} : {enabled: input.enabled})
  });

  const items = useMemo(
    () =>
      mergeCursorPages({
        pages: query.data?.pages,
        getItems: input.getItems,
        ...(input.getItemKey ? {getItemKey: input.getItemKey} : {})
      }),
    [input.getItemKey, input.getItems, query.data?.pages]
  );

  return {
    ...query,
    items
  };
};
