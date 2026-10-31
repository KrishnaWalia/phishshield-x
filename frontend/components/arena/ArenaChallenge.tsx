"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { scanUrl, type ScanResponse } from "@/lib/api";
import { POINTS_CORRECT, POINTS_FALSE_FLAG, gradeAnswers, saveBestScore, type Scenario } from "@/lib/arena";
import { SEVERITY_RANK } from "@/lib/risk";
import { ScoreGauge } from "@/components/ScoreGauge";
import { ErrorBanner, RiskBadge, SeverityBadge, Spinner } from "@/components/ui";
import { ArenaContext } from "./Hot";
import { SCENARIO_PAGES } from "./ScenarioPages";

export function ArenaChallenge({ scenario }: { scenario: Scenario }) {
  const [flagged, setFlagged] = useState<Set<string>>(new Set());
  const [revealed, setRevealed] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [scanError, setScanError] = useState<unknown>(null);

  const indicators = useMemo(() => Object.fromEntries(scenario.indicators.map((i) => [i.id, i])), [scenario]);
  const grade = useMemo(() => gradeAnswers(scenario, flagged), [scenario, flagged]);
  const Page = SCENARIO_PAGES[scenario.slug];

  function toggle(id: string) {
    setFlagged((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  async function runScan() {
    setScanning(true);
    setScanError(null);
    try {
      // Same endpoint as the URL scanner, tagged source "arena". The backend analyses the text; it does not open the URL.
      setScan(await scanUrl({ ...scenario.scan, source: "arena" }));
    } catch (e) {
      setScanError(e);
    } finally {
      setScanning(false);
    }
  }

  function submit() {
    setRevealed(true);
    saveBestScore(scenario.slug, grade.score, grade.max);
    runScan();
  }

  function reset() {
    setFlagged(new Set());
    setRevealed(false);
    setScan(null);
    setScanError(null);
  }

  return (
    <ArenaContext.Provider value={{ flagged, revealed, indicators, toggle }}>
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_400px]">
        <div><Page /></div>

        <aside className="space-y-5">
          {!revealed ? (
            <div className="panel space-y-4 p-5 xl:sticky xl:top-6">
              <h2 className="text-lg">Find the red flags</h2>
              <p className="text-sm leading-relaxed text-slate-400">
                Click or tap anything on the page that looks like a scam signal, including the address bar. Click again to undo.
                Some elements are perfectly normal, so flag carefully.
              </p>
              <p className="text-sm text-slate-300">
                Flagged so far: <span className="font-display text-xl text-white">{flagged.size}</span>
              </p>
              <p className="text-xs text-slate-500">
                Challenge scoring: +{POINTS_CORRECT} for each real red flag, −{POINTS_FALSE_FLAG} for each normal element you flag.
              </p>
              <button className="btn-primary w-full" onClick={submit} disabled={flagged.size === 0}>Submit my answers</button>
            </div>
          ) : (
            <>
              <section className="panel space-y-3 p-5">
                <h2 className="text-lg">Your challenge score</h2>
                <p className="font-display text-4xl text-white">{grade.score} <span className="text-xl text-slate-500">/ {grade.max}</span></p>
                <p className="text-xs text-slate-500">Learning score for practice only. It is separate from PhishShield&apos;s official risk score below.</p>
                <p className="text-sm text-slate-300">
                  Found {grade.correct.length} of {grade.correct.length + grade.missed.length} red flags
                  {grade.falseFlags.length > 0 && `, with ${grade.falseFlags.length} normal element${grade.falseFlags.length > 1 ? "s" : ""} wrongly flagged`}.
                </p>
                <div className="flex gap-2">
                  <button className="btn-primary" onClick={reset}>Try again</button>
                  <Link href="/arena" className="btn-ghost">All scenarios</Link>
                </div>
              </section>

              <section className="panel p-5">
                <h2 className="mb-3 text-lg">What was on the page</h2>
                <ul className="space-y-3">
                  {scenario.indicators.map((ind) => {
                    const on = flagged.has(ind.id);
                    const status = ind.suspicious ? (on ? "Found" : "Missed") : on ? "Not a red flag" : "Normal, correctly left alone";
                    const good = ind.suspicious ? on : !on;
                    return (
                      <li key={ind.id} className="rounded-lg border border-line bg-ink-900/70 p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium text-white">{ind.label}</span>
                          <span className={`rounded-md border px-2 py-0.5 text-xs ${good ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300" : "border-red-400/30 bg-red-400/10 text-red-300"}`}>{status}</span>
                        </div>
                        <p className="mt-1.5 text-sm leading-relaxed text-slate-400">{ind.explanation}</p>
                      </li>
                    );
                  })}
                </ul>
              </section>

              <section className="panel space-y-3 p-5">
                <h2 className="text-lg">PhishShield&apos;s detection</h2>
                <p className="text-xs text-slate-500">The backend analysed this fictional page&apos;s address and text. Compare its findings with your own.</p>
                {scanning && <Spinner label="Running backend scan" />}
                {!!scanError && <ErrorBanner error={scanError} onRetry={runScan} />}
                {scan && (
                  <>
                    <div className="flex items-center gap-4">
                      <ScoreGauge score={scan.risk_score} level={scan.risk_level} size={92} />
                      <div className="space-y-1.5">
                        <RiskBadge level={scan.risk_level} />
                        <p className="text-sm text-slate-300">{scan.summary}</p>
                      </div>
                    </div>
                    {scan.engines && !scan.engines.ai && <p className="text-xs text-amber-300/90">AI analysis was unavailable, so this result uses the rule engine and ML model only.</p>}
                    {scan.findings.length === 0 ? (
                      <p className="text-sm text-slate-400">The backend reported no findings for this page.</p>
                    ) : (
                      <ul className="space-y-2">
                        {[...scan.findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]).map((f) => (
                          <li key={f.id} className="rounded-lg border border-line bg-ink-900/70 p-3">
                            <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium text-white">{f.title}</span><SeverityBadge severity={f.severity} /></div>
                            {f.evidence && <p className="mt-1.5 break-words font-mono text-xs text-slate-400">{f.evidence}</p>}
                          </li>
                        ))}
                      </ul>
                    )}
                    <Link href={`/reports/${encodeURIComponent(scan.scan_id)}`} className="inline-block text-sm text-signal underline underline-offset-2">Open full report</Link>
                  </>
                )}
              </section>
            </>
          )}
        </aside>
      </div>
    </ArenaContext.Provider>
  );
}
