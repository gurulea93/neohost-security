const paths = {
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" />
    </>
  ),
  shield: (
    <path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z" />
  ),
  server: (
    <>
      <rect x="4" y="4" width="16" height="5" rx="1.5" />
      <rect x="4" y="11" width="16" height="5" rx="1.5" />
      <circle cx="8" cy="6.5" r="1" fill="currentColor" stroke="none" />
      <circle cx="8" cy="13.5" r="1" fill="currentColor" stroke="none" />
    </>
  ),
  history: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  link: (
    <>
      <path d="M10 14a4 4 0 0 1 0-5.7l1.3-1.3a4 4 0 0 1 5.7 5.7l-1 1" />
      <path d="M14 10a4 4 0 0 1 0 5.7l-1.3 1.3a4 4 0 0 1-5.7-5.7l1-1" />
    </>
  ),
  logout: (
    <>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <path d="M16 17l5-5-5-5M21 12H9" />
    </>
  ),
  ban: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M7 7l10 10" />
    </>
  ),
  users: (
    <>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2 20c0-3.3 3.1-6 7-6s7 2.7 7 6" />
      <circle cx="17" cy="9" r="2.5" />
      <path d="M22 20c0-2.2-2-4-5-4.5" />
    </>
  ),
  activity: (
    <path d="M4 16l4-6 4 3 8-10" />
  ),
  download: (
    <>
      <path d="M12 3v12" />
      <path d="M7 10l5 5 5-5" />
      <path d="M5 21h14" />
    </>
  ),
  pause: (
    <>
      <rect x="7" y="5" width="4" height="14" rx="1" fill="currentColor" stroke="none" />
      <rect x="13" y="5" width="4" height="14" rx="1" fill="currentColor" stroke="none" />
    </>
  ),
  play: (
    <path d="M8 5l12 7-12 7V5z" fill="currentColor" stroke="none" />
  ),
  close: (
    <>
      <path d="M6 6l12 12M18 6L6 18" />
    </>
  ),
  check: (
  <>
    <path d="M5 13l4 4L19 7" />
  </>
  ),
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l9-9M20 3l1 1-2 2" />
    </>
  ),
  trash: (
    <>
      <path d="M4 7h16M9 7V5h6v2M10 11v5M14 11v5M6 7l1 12h10l1-12" />
    </>
  ),
  edit: (
    <>
      <path d="M4 20h4l10.5-10.5a2.1 2.1 0 0 0-3-3L5 17v3z" />
      <path d="M13.5 6.5l3 3" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </>
  ),
  plus: (
    <>
      <path d="M12 5v14M5 12h14" />
    </>
  ),
  refresh: (
    <>
      <path d="M4 12a8 8 0 0 1 13.5-5.7" />
      <path d="M20 7v5h-5M20 12a8 8 0 0 1-13.5 5.7" />
      <path d="M4 17v-5h5" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3-3" />
    </>
  ),
  arrowDown: (
    <>
      <path d="M12 5v10" />
      <path d="M8 11l4 4 4-4" />
    </>
  ),
  arrowUp: (
    <>
      <path d="M12 19V9" />
      <path d="M8 13l4-4 4 4" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </>
  ),
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </>
  ),
  moon: (
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
  ),
};

export default function Icon({ name, size = 20, className = "", strokeWidth = 1.75 }) {
  const content = paths[name];
  if (!content) return null;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {content}
    </svg>
  );
}

export function IconBox({ name, color = "blue", size = 22 }) {
  return (
    <div className={`icon-box icon-box-${color}`}>
      <Icon name={name} size={size} />
    </div>
  );
}
