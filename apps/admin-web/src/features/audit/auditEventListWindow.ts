export const AUDIT_VIEWPORT_ROWS = 12;
export const AUDIT_ROW_HEIGHT_PX = 44;
export const AUDIT_OVERSCAN_ROWS = 3;
export const AUDIT_LOAD_MORE_THRESHOLD_ROWS = 3;

export type VirtualRowWindow = {
  startRow: number;
  endRowExclusive: number;
};

export const buildVirtualRowWindow = (input: {
  totalRows: number;
  rowHeightPx: number;
  viewportRows: number;
  scrollTopPx: number;
  overscanRows: number;
}): VirtualRowWindow => {
  if (input.totalRows <= 0) {
    return {
      startRow: 0,
      endRowExclusive: 0
    };
  }

  const safeRowHeight = Number.isFinite(input.rowHeightPx) ? Math.max(1, Math.floor(input.rowHeightPx)) : 1;
  const safeViewportRows = Number.isFinite(input.viewportRows) ? Math.max(1, Math.floor(input.viewportRows)) : 1;
  const safeOverscanRows = Number.isFinite(input.overscanRows) ? Math.max(0, Math.floor(input.overscanRows)) : 0;
  const safeScrollTop = Number.isFinite(input.scrollTopPx) ? Math.max(0, input.scrollTopPx) : 0;

  const startVisibleRow = Math.floor(safeScrollTop / safeRowHeight);
  const endVisibleRowExclusive = Math.min(input.totalRows, startVisibleRow + safeViewportRows);

  const startRow = Math.max(0, startVisibleRow - safeOverscanRows);
  const endRowExclusive = Math.min(input.totalRows, endVisibleRowExclusive + safeOverscanRows);

  return {
    startRow,
    endRowExclusive
  };
};
