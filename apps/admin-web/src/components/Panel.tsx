import React from 'react';
import type {PropsWithChildren, ReactNode} from 'react';

type PanelProps = PropsWithChildren<{
  title: string;
  subtitle?: string;
  action?: ReactNode;
}>;

export const Panel = ({title, subtitle, action, children}: PanelProps) => (
  <section className="panel">
    <header className="panel-header">
      <div>
        <h2>{title}</h2>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {action ? <div>{action}</div> : null}
    </header>
    <div className="panel-body">{children}</div>
  </section>
);
