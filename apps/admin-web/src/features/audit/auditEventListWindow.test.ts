import {describe, expect, it} from 'vitest';

import {
  AUDIT_LOAD_MORE_THRESHOLD_ROWS,
  AUDIT_ROW_HEIGHT_PX,
  AUDIT_VIEWPORT_ROWS,
  buildVirtualRowWindow
} from './auditEventListWindow';

describe('auditEventListWindow', () => {
  it('exports sane virtual list defaults', () => {
    expect(AUDIT_VIEWPORT_ROWS).toBeGreaterThan(0);
    expect(AUDIT_ROW_HEIGHT_PX).toBeGreaterThan(0);
    expect(AUDIT_LOAD_MORE_THRESHOLD_ROWS).toBeGreaterThan(0);
  });

  it('builds virtual row ranges with overscan and bounds', () => {
    expect(
      buildVirtualRowWindow({
        totalRows: 80,
        rowHeightPx: AUDIT_ROW_HEIGHT_PX,
        viewportRows: AUDIT_VIEWPORT_ROWS,
        scrollTopPx: 0,
        overscanRows: 3
      })
    ).toEqual({
      startRow: 0,
      endRowExclusive: 15
    });

    expect(
      buildVirtualRowWindow({
        totalRows: 80,
        rowHeightPx: AUDIT_ROW_HEIGHT_PX,
        viewportRows: AUDIT_VIEWPORT_ROWS,
        scrollTopPx: AUDIT_ROW_HEIGHT_PX * 10,
        overscanRows: 3
      })
    ).toEqual({
      startRow: 7,
      endRowExclusive: 25
    });
  });

  it('handles empty rows safely', () => {
    expect(
      buildVirtualRowWindow({
        totalRows: 0,
        rowHeightPx: AUDIT_ROW_HEIGHT_PX,
        viewportRows: AUDIT_VIEWPORT_ROWS,
        scrollTopPx: 120,
        overscanRows: 3
      })
    ).toEqual({
      startRow: 0,
      endRowExclusive: 0
    });
  });
});
