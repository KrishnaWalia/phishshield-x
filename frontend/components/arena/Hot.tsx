"use client";

import { createContext, useContext, type ReactNode } from "react";
import type { Indicator } from "@/lib/arena";

interface ArenaState {
  flagged: Set<string>;
  revealed: boolean;
  indicators: Record<string, Indicator>;
  toggle: (id: string) => void;
}

export const ArenaContext = createContext<ArenaState | null>(null);

const STATE_STYLES = {
  idle: "hover:outline-dashed hover:outline-2 hover:outline-offset-2 hover:outline-sky-500",
  flag: "outline outline-2 outline-offset-2 outline-amber-500 bg-amber-300/25",
  hit: "outline outline-2 outline-offset-2 outline-emerald-600 bg-emerald-300/25",
  miss: "outline-dashed outline-2 outline-offset-2 outline-red-600 bg-red-300/25",
  wrong: "outline outline-2 outline-offset-2 outline-red-600 bg-red-300/25",
} as const;

const BADGES = {
  flag: { text: "Flagged", cls: "bg-amber-500 text-white" },
  hit: { text: "Correct", cls: "bg-emerald-600 text-white" },
  miss: { text: "Missed", cls: "bg-red-600 text-white" },
  wrong: { text: "Not a red flag", cls: "bg-red-600 text-white" },
} as const;

/** A clickable region of a fictional page. The player flags it if they think it's a red flag. */
export function Hot({ id, children, className = "", as: Tag = "div" }: { id: string; children: ReactNode; className?: string; as?: "div" | "span" }) {
  const ctx = useContext(ArenaContext);
  if (!ctx) return <>{children}</>;

  const on = ctx.flagged.has(id);
  const suspicious = ctx.indicators[id]?.suspicious ?? false;
  let state: keyof typeof STATE_STYLES = "idle";
  if (ctx.revealed) {
    if (suspicious) state = on ? "hit" : "miss";
    else if (on) state = "wrong";
  } else if (on) state = "flag";

  const badge = state !== "idle" ? BADGES[state] : null;
  return (
    <Tag
      role="button"
      tabIndex={0}
      aria-pressed={on}
      aria-label={`Mark as red flag: ${ctx.indicators[id]?.label ?? id}`}
      onClick={() => !ctx.revealed && ctx.toggle(id)}
      onKeyDown={(e: React.KeyboardEvent) => {
        if ((e.key === "Enter" || e.key === " ") && !ctx.revealed) {
          e.preventDefault();
          ctx.toggle(id);
        }
      }}
      className={`relative cursor-pointer rounded-sm transition ${STATE_STYLES[state]} ${className}`}
    >
      {children}
      {badge && <span className={`pointer-events-none absolute -top-2.5 right-0 z-10 whitespace-nowrap rounded px-1.5 py-0.5 text-[10px] font-semibold leading-none ${badge.cls}`}>{badge.text}</span>}
    </Tag>
  );
}
