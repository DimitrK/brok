import React from 'react';

export type AppIconName =
  | 'tenants'
  | 'users'
  | 'workloads'
  | 'templates'
  | 'integrations'
  | 'policies'
  | 'approvals'
  | 'audit'
  | 'manifest'
  | 'menu'
  | 'close'
  | 'plus'
  | 'chevron-right'
  | 'arrow-left';

type AppIconProps = {
  name: AppIconName;
  className?: string;
  title?: string;
};

const iconPathByName: Record<AppIconName, React.ReactNode> = {
  tenants: (
    <>
      <rect x="3" y="4" width="8" height="7" rx="1.5" />
      <rect x="13" y="4" width="8" height="5" rx="1.5" />
      <rect x="13" y="11" width="8" height="9" rx="1.5" />
      <rect x="3" y="13" width="8" height="7" rx="1.5" />
    </>
  ),
  users: (
    <>
      <circle cx="12" cy="8.5" r="3.25" />
      <path d="M5 19.5c1.9-3 4-4.5 7-4.5s5.1 1.5 7 4.5" />
    </>
  ),
  workloads: (
    <>
      <path d="M12 3 4 7.2v9.6L12 21l8-4.2V7.2L12 3Z" />
      <path d="M4 7.2 12 12l8-4.8M12 12v9" />
    </>
  ),
  templates: (
    <>
      <path d="M8 3.5h8.5L20 7v13a1.5 1.5 0 0 1-1.5 1.5H8A1.5 1.5 0 0 1 6.5 20V5A1.5 1.5 0 0 1 8 3.5Z" />
      <path d="M16.5 3.5V7H20M9.5 11h7M9.5 14h7M9.5 17h5" />
    </>
  ),
  integrations: (
    <>
      <path d="M9 8.8 6.3 11.5a3 3 0 1 0 4.2 4.2l2.7-2.7" />
      <path d="m15 15.2 2.7-2.7a3 3 0 0 0-4.2-4.2l-2.7 2.7" />
      <path d="m9.8 14.2 4.4-4.4" />
    </>
  ),
  policies: (
    <>
      <path d="M12 3.5c2.5 2 5.5 3 8.5 3v5.4c0 4.8-2.9 7.8-8.5 9.6-5.6-1.8-8.5-4.8-8.5-9.6V6.5c3 0 6-1 8.5-3Z" />
      <path d="m8.6 12.2 2.2 2.2 4.5-4.5" />
    </>
  ),
  approvals: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m8.8 12.1 2.3 2.3 4.2-4.2" />
    </>
  ),
  audit: (
    <>
      <path d="M4 18.5h16M6.5 15.5V9m5.5 6.5V6.5m5.5 9V11" />
    </>
  ),
  manifest: (
    <>
      <circle cx="8.5" cy="12" r="2.5" />
      <path d="m10.3 13.8 3.9 3.9 2-2-3.9-3.9M15.1 12.9l3.2-3.2a2.1 2.1 0 1 0-3-3l-3.2 3.2" />
    </>
  ),
  menu: (
    <>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </>
  ),
  close: (
    <>
      <path d="m6 6 12 12M18 6 6 18" />
    </>
  ),
  plus: (
    <>
      <path d="M12 5v14M5 12h14" />
    </>
  ),
  'chevron-right': (
    <>
      <path d="m9 6 6 6-6 6" />
    </>
  ),
  'arrow-left': (
    <>
      <path d="m15.5 12H7.5M11 8.5 7.5 12l3.5 3.5" />
    </>
  )
};

export const AppIcon = ({name, className, title}: AppIconProps) => (
  <svg
    className={className}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden={title ? undefined : true}
    role={title ? 'img' : undefined}
  >
    {title ? <title>{title}</title> : null}
    {iconPathByName[name]}
  </svg>
);
