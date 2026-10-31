"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { getHealth } from "@/lib/api";
import { Icon, type IconName } from "./Icon";

const NAV: { href: string; label: string; icon: IconName }[] = [
  { href: "/", label: "Dashboard", icon: "dashboard" },
  { href: "/scanner/url", label: "URL scanner", icon: "link" },
  { href: "/scanner/message", label: "Message scanner", icon: "message" },
  { href: "/history", label: "Scan history", icon: "history" },
  { href: "/arena", label: "Scam Arena", icon: "arena" },
];

type Status = "checking" | "online" | "offline";

function useBackendStatus(): Status {
  const [status, setStatus] = useState<Status>("checking");
  useEffect(() => {
    let alive = true;
    const check = () =>
      getHealth().then(
        () => alive && setStatus("online"),
        () => alive && setStatus("offline")
      );
    check();
    const id = setInterval(check, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);
  return status;
}

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <nav className="flex flex-col gap-1">
      {NAV.map((item) => {
        const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            aria-current={active ? "page" : undefined}
            className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
              active ? "bg-ink-600 text-white shadow-[inset_2px_0_0_#4cc9f0]" : "text-slate-400 hover:bg-ink-700 hover:text-slate-100"
            }`}
          >
            <Icon name={item.icon} className="h-[18px] w-[18px]" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2.5">
      <span className="grid h-9 w-9 place-items-center rounded-lg bg-signal/15 text-signal">
        <Icon name="shield" className="h-5 w-5" />
      </span>
      <span className="font-display text-lg leading-none text-white">
        PhishShield <span className="text-signal">X</span>
      </span>
    </Link>
  );
}

function StatusPill() {
  const status = useBackendStatus();
  const map = {
    checking: { dot: "bg-slate-500", text: "Checking backend" },
    online: { dot: "bg-emerald-400", text: "Backend online" },
    offline: { dot: "bg-red-400", text: "Backend offline" },
  }[status];
  return (
    <div className="flex items-center gap-2 rounded-lg border border-line bg-ink-900 px-3 py-2 text-xs text-slate-400" role="status">
      <span className={`h-2 w-2 rounded-full ${map.dot}`} />
      {map.text}
    </div>
  );
}

export function Sidebar() {
  const [open, setOpen] = useState(false);
  return (
    <>
      {/* Desktop */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 flex-col justify-between border-r border-line bg-ink-900/95 p-5 lg:flex">
        <div className="space-y-8">
          <Brand />
          <NavList />
        </div>
        <StatusPill />
      </aside>

      {/* Mobile */}
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-line bg-ink-900/95 px-4 py-3 backdrop-blur lg:hidden">
        <Brand />
        <button className="btn-ghost !px-2.5 !py-2" onClick={() => setOpen(true)} aria-label="Open navigation">
          <Icon name="menu" />
        </button>
      </header>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
          <div className="absolute inset-y-0 left-0 flex w-72 flex-col justify-between border-r border-line bg-ink-900 p-5">
            <div className="space-y-8">
              <div className="flex items-center justify-between">
                <Brand />
                <button className="text-slate-400" onClick={() => setOpen(false)} aria-label="Close navigation">
                  <Icon name="close" />
                </button>
              </div>
              <NavList onNavigate={() => setOpen(false)} />
            </div>
            <StatusPill />
          </div>
        </div>
      )}
    </>
  );
}
