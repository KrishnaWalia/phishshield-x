const PATHS = {
  dashboard: "M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z",
  link: "M10 13a5 5 0 007.07 0l3-3a5 5 0 00-7.07-7.07l-1 1M14 11a5 5 0 00-7.07 0l-3 3a5 5 0 007.07 7.07l1-1",
  message: "M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z",
  history: "M12 8v4l3 2M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  arena: "M12 21a9 9 0 100-18 9 9 0 000 18zM12 16a4 4 0 100-8 4 4 0 000 8zM12 12h.01",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4",
  menu: "M4 7h16M4 12h16M4 17h16",
  close: "M6 6l12 12M18 6L6 18",
  flag: "M5 21V4M5 4h11l-2 4 2 4H5",
  check: "M5 12l5 5 9-10",
  alert: "M12 9v4M12 17h.01M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, className = "h-5 w-5" }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={PATHS[name]} />
    </svg>
  );
}
