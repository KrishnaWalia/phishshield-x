"use client";

import { useEffect, useState } from "react";
import type { RiskLevel } from "@/lib/api";
import { riskStyle } from "@/lib/risk";

/** Displays a backend-provided score. The ring only visualises the number it is given. */
export function ScoreGauge({ score, level, size = 168 }: { score: number; level: RiskLevel | string; size?: number }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(score));
    return () => cancelAnimationFrame(id);
  }, [score]);

  const { hex, label } = riskStyle(level);
  const r = 52;
  const c = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, shown));

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`Risk score ${score} out of 100, ${label}`}>
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#12203a" strokeWidth="9" />
        {/* tick marks at the backend's threshold boundaries: 20 / 40 / 60 / 80 */}
        {[20, 40, 60, 80].map((t) => {
          const a = (t / 100) * 2 * Math.PI;
          return (
            <line key={t} x1={60 + (r - 7) * Math.cos(a)} y1={60 + (r - 7) * Math.sin(a)} x2={60 + (r + 7) * Math.cos(a)} y2={60 + (r + 7) * Math.sin(a)} stroke="#060b16" strokeWidth="2" />
          );
        })}
        <circle
          cx="60" cy="60" r={r} fill="none" stroke={hex} strokeWidth="9" strokeLinecap="butt"
          strokeDasharray={c} strokeDashoffset={c * (1 - clamped / 100)}
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(.2,.8,.2,1)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display leading-none text-white" style={{ fontSize: size * 0.3 }}>{score}</span>
        <span className="mt-1 text-xs text-slate-400" style={{ color: hex }}>{label}</span>
      </div>
    </div>
  );
}
