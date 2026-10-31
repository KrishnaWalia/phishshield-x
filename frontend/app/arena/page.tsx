"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { SCENARIOS, loadBestScores } from "@/lib/arena";
import { PageHeader } from "@/components/ui";

export default function ArenaIndexPage() {
  const [best, setBest] = useState<Record<string, { score: number; max: number }>>({});
  useEffect(() => setBest(loadBestScores()), []);

  return (
    <>
      <PageHeader
        title="Scam Arena"
        description="Practice spotting scams on fictional pages. Nothing here collects data or moves money. After each round, see how your picks compare with PhishShield's own detection."
      />
      <div className="grid gap-5 md:grid-cols-3">
        {SCENARIOS.map((s) => {
          const b = best[s.slug];
          return (
            <Link key={s.slug} href={`/arena/${s.slug}`} className="panel group flex flex-col justify-between gap-6 p-5 transition hover:border-signal/60">
              <div className="space-y-2">
                <span className="text-xs text-slate-500">{s.difficulty}</span>
                <h2 className="text-xl">{s.title}</h2>
                <p className="text-sm leading-relaxed text-slate-400">{s.tagline}</p>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-500">{b ? `Best challenge score ${b.score} / ${b.max}` : "Not attempted"}</span>
                <span className="text-signal group-hover:underline">Start</span>
              </div>
            </Link>
          );
        })}
      </div>
    </>
  );
}
