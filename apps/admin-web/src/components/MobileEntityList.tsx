import React, {useMemo, useState} from 'react';

import {AppIcon} from './AppIcon';
import {useOverlayDismiss} from './useOverlayDismiss';

type MobileEntitySummaryMeta = {
  label: string;
  value: React.ReactNode;
};

export type MobileEntitySummary = {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  meta?: MobileEntitySummaryMeta[];
  statusTone?: 'positive' | 'neutral';
};

type MobileEntityListRenderDetailControls = {
  close: () => void;
};

type MobileEntityListProps<TItem> = {
  items: TItem[];
  ariaLabel: string;
  emptyState: string;
  getItemKey: (item: TItem) => string;
  getSummary: (item: TItem) => MobileEntitySummary;
  renderDetail: (item: TItem, controls: MobileEntityListRenderDetailControls) => React.ReactNode;
  selectedItemKey?: string;
  onSelectedItemKeyChange?: (itemKey: string | undefined) => void;
};

export const MobileEntityList = <TItem,>({
  items,
  ariaLabel,
  emptyState,
  getItemKey,
  getSummary,
  renderDetail,
  selectedItemKey,
  onSelectedItemKeyChange
}: MobileEntityListProps<TItem>) => {
  const [internalSelectedItemKey, setInternalSelectedItemKey] = useState<string | undefined>();

  const resolvedSelectedItemKey = selectedItemKey ?? internalSelectedItemKey;

  const selectedItem = useMemo(
    () => items.find(item => getItemKey(item) === resolvedSelectedItemKey),
    [getItemKey, items, resolvedSelectedItemKey]
  );

  const setSelectedItemKey = (itemKey: string | undefined) => {
    if (typeof onSelectedItemKeyChange === 'function') {
      onSelectedItemKeyChange(itemKey);
      return;
    }
    setInternalSelectedItemKey(itemKey);
  };

  const selectedSummary = selectedItem ? getSummary(selectedItem) : undefined;
  const closeSelectedItem = () => setSelectedItemKey(undefined);
  const detailOverlay = useOverlayDismiss({
    isOpen: Boolean(selectedItem),
    onClose: closeSelectedItem,
    scope: `${ariaLabel}:mobile-detail`
  });

  return (
    <section className="mobile-entity-stack" aria-label={ariaLabel}>
      {items.length === 0 ? (
        <p className="helper-text">{emptyState}</p>
      ) : (
        <ul className="mobile-entity-list">
          {items.map(item => {
            const itemKey = getItemKey(item);
            const summary = getSummary(item);
            return (
              <li key={itemKey}>
                <button type="button" className="mobile-entity-list-item" onClick={() => setSelectedItemKey(itemKey)}>
                  <div className="mobile-entity-list-main">
                    <strong className="mobile-entity-title">
                      {summary.statusTone ? <span className={`state-dot ${summary.statusTone}`} aria-hidden /> : null}
                      <span>{summary.title}</span>
                    </strong>
                    {summary.subtitle ? <span className="mobile-entity-subtitle">{summary.subtitle}</span> : null}
                  </div>
                  {summary.meta?.length ? (
                    <dl className="mobile-entity-meta">
                      {summary.meta.map(meta => (
                        <React.Fragment key={meta.label}>
                          <dt>{meta.label}</dt>
                          <dd>{meta.value}</dd>
                        </React.Fragment>
                      ))}
                    </dl>
                  ) : null}
                  <span className="mobile-entity-chevron" aria-hidden>
                    <AppIcon name="chevron-right" />
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}

      {selectedItem ? (
        <section className="mobile-entity-detail-screen">
          <header className="mobile-entity-detail-header">
              <button
                type="button"
                className="mobile-entity-back"
                aria-label="Back to list"
                onClick={detailOverlay.requestClose}
              >
                <AppIcon name="arrow-left" />
              </button>
            <strong className="mobile-entity-detail-title">{selectedSummary?.title}</strong>
            <span className="mobile-entity-detail-spacer" aria-hidden />
          </header>
          <div className="mobile-entity-detail-content">
            {renderDetail(selectedItem, {close: detailOverlay.requestClose})}
          </div>
        </section>
      ) : null}
    </section>
  );
};
