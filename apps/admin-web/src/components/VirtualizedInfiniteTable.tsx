import React, {useEffect, useMemo, useRef, useState} from 'react';

import {buildVirtualRowWindow} from '../features/audit/auditEventListWindow';

export type VirtualizedInfiniteTableColumn<TItem> = {
  id: string;
  header: React.ReactNode;
  width?: string;
  renderCell: (item: TItem) => React.ReactNode;
};

type VirtualizedInfiniteTableProps<TItem> = {
  columns: VirtualizedInfiniteTableColumn<TItem>[];
  items: TItem[];
  rowKey: (item: TItem) => string;
  rowHeightPx: number;
  viewportRows: number;
  overscanRows: number;
  hasMore: boolean;
  isLoadingMore: boolean;
  onLoadMore: () => void;
  loadMoreThresholdRows: number;
  selectedRowKey?: string;
  onRowClick?: (item: TItem) => void;
  ariaLabel: string;
  emptyState: React.ReactNode;
};

export const VirtualizedInfiniteTable = <TItem,>(props: VirtualizedInfiniteTableProps<TItem>) => {
  const {
    columns,
    items,
    rowKey,
    rowHeightPx,
    viewportRows,
    overscanRows,
    hasMore,
    isLoadingMore,
    onLoadMore,
    loadMoreThresholdRows,
    selectedRowKey,
    onRowClick,
    ariaLabel,
    emptyState
  } = props;

  const [scrollTopPx, setScrollTopPx] = useState(0);
  const loadRequestedRef = useRef(false);

  const gridTemplateColumns = useMemo(
    () => columns.map(column => column.width ?? 'minmax(0, 1fr)').join(' '),
    [columns]
  );
  const virtualRowWindow = useMemo(
    () =>
      buildVirtualRowWindow({
        totalRows: items.length,
        rowHeightPx,
        viewportRows,
        scrollTopPx,
        overscanRows
      }),
    [items.length, overscanRows, rowHeightPx, scrollTopPx, viewportRows]
  );
  const visibleItems = useMemo(
    () => items.slice(virtualRowWindow.startRow, virtualRowWindow.endRowExclusive),
    [items, virtualRowWindow.endRowExclusive, virtualRowWindow.startRow]
  );
  const totalHeight = items.length * rowHeightPx;

  useEffect(() => {
    if (!isLoadingMore) {
      loadRequestedRef.current = false;
    }
  }, [isLoadingMore, items.length]);

  return (
    <div className="virtualized-table-shell" aria-label={ariaLabel}>
      <div className="virtualized-table-header" style={{gridTemplateColumns}} role="row">
        {columns.map(column => (
          <span key={column.id} role="columnheader">
            {column.header}
          </span>
        ))}
      </div>

      {items.length === 0 ? (
        <p className="helper-text virtualized-table-empty">{emptyState}</p>
      ) : (
        <div
          className="virtualized-table-viewport"
          style={{height: viewportRows * rowHeightPx}}
          onScroll={event => {
            const viewport = event.currentTarget;
            setScrollTopPx(viewport.scrollTop);

            if (
              hasMore &&
              !isLoadingMore &&
              !loadRequestedRef.current &&
              viewport.scrollTop + viewport.clientHeight >= viewport.scrollHeight - loadMoreThresholdRows * rowHeightPx
            ) {
              loadRequestedRef.current = true;
              onLoadMore();
            }
          }}
        >
          <div className="virtualized-table-spacer" style={{height: totalHeight}}>
            {visibleItems.map((item, index) => {
              const key = rowKey(item);
              const rowIndex = virtualRowWindow.startRow + index;
              const selected = key === selectedRowKey;
              const className = `virtualized-table-row${selected ? ' selected' : ''}`;
              const rowStyle = {
                top: rowIndex * rowHeightPx,
                height: rowHeightPx,
                gridTemplateColumns
              };

              return onRowClick ? (
                <button
                  key={key}
                  type="button"
                  className={className}
                  style={rowStyle}
                  onClick={() => onRowClick(item)}
                  aria-pressed={selected}
                >
                  {columns.map(column => (
                    <span key={column.id}>{column.renderCell(item)}</span>
                  ))}
                </button>
              ) : (
                <div key={key} className={className} style={rowStyle} role="row">
                  {columns.map(column => (
                    <span key={column.id}>{column.renderCell(item)}</span>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
