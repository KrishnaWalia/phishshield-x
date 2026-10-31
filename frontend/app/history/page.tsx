"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { listScans, type ScanSummary } from "@/lib/api";
import { RISK_ORDER, RISK_STYLES, formatDateTime } from "@/lib/risk";
import { sortRecent } from "@/lib/stats";
import { EmptyState, ErrorBanner, PageHeader, RiskBadge, Spinner } from "@/components/ui";

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [level, setLevel] = useState("ALL");
  const [type, setType] = useState("ALL");

  const load = useCallback(async () => {
    setError(null);
    try { setScans(sortRecent(await listScans())); } catch (e) { setScans(null); setError(e); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const types = useMemo(() => Array.from(new Set((scans ?? []).map((s) => s.target_type))), [scans]);
  const rows = useMemo(
    () => (scans ?? []).filter((s) => (level === "ALL" || s.risk_level === level) && (type === "ALL" || s.target_type === type)),
    [scans, level, type]
  );

  return (
    <>
      <PageHeader
        title="Scan history"
        description="Every scan saved by the backend, newest first. Open one for the full investigation report."
        action={<button className="btn-ghost" onClick={load}>Refresh</button>}
      />
      {!!error && <ErrorBanner error={error} onRetry={load} />}
      {!error && scans === null && <Spinner label="Loading history" />}

      {scans && (
        <section className="panel">
          {scans.length === 0 ? (
            <EmptyState title="No scans yet" body="Scans from the dashboard, the browser extension and Scam Arena show up here." href="/scanner/url" cta="Scan a URL" />
          ) : (
            <>
              <div className="flex flex-wrap gap-3 border-b border-line p-4">
                <select className="input !w-auto" value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Filter by risk level">
                  <option value="ALL">All risk levels</option>
                  {RISK_ORDER.map((l) => <option key={l} value={l}>{RISK_STYLES[l].label}</option>)}
                </select>
                <select className="input !w-auto" value={type} onChange={(e) => setType(e.target.value)} aria-label="Filter by scan type">
                  <option value="ALL">All scan types</option>
                  {types.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <span className="ml-auto self-center text-sm text-slate-500">{rows.length} of {scans.length}</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] text-left text-sm">
                  <thead className="text-slate-400">
                    <tr className="border-b border-line">
                      <th className="px-4 py-3 font-medium">Scan ID</th>
                      <th className="px-4 py-3 font-medium">Target</th>
                      <th className="px-4 py-3 font-medium">Type</th>
                      <th className="px-4 py-3 font-medium">Score</th>
                      <th className="px-4 py-3 font-medium">Level</th>
                      <th className="px-4 py-3 font-medium">Scanned</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {rows.map((s) => (
                      <tr key={s.scan_id} className="transition hover:bg-ink-700/40">
                        <td className="px-4 py-3 font-mono text-xs"><Link className="text-signal hover:underline" href={`/reports/${encodeURIComponent(s.scan_id)}`}>{s.scan_id}</Link></td>
                        <td className="max-w-[280px] truncate px-4 py-3 text-slate-200" title={s.target}>{s.target}</td>
                        <td className="px-4 py-3 text-slate-400">{s.target_type}</td>
                        <td className="px-4 py-3 font-display text-base text-white">{s.risk_score}</td>
                        <td className="px-4 py-3"><RiskBadge level={s.risk_level} /></td>
                        <td className="whitespace-nowrap px-4 py-3 text-slate-400">{formatDateTime(s.analyzed_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {rows.length === 0 && <p className="p-6 text-center text-sm text-slate-400">No scans match these filters.</p>}
              </div>
            </>
          )}
        </section>
      )}
    </>
  );
}
