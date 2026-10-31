"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getScan, listScans, type ScanResponse, type ScanSummary } from "@/lib/api";
import { countByLevel, countFindingsByCategory, sortRecent } from "@/lib/stats";
import { timeAgo } from "@/lib/risk";
import { RiskDistributionChart, ThreatCategoryChart } from "@/components/charts";
import { QuickScan } from "@/components/QuickScan";
import { EmptyState, ErrorBanner, PageHeader, RiskBadge, Spinner } from "@/components/ui";

/** Threat categories need findings; the list endpoint may omit them, so we fetch details for the newest scans. */
const DETAIL_LIMIT = 20;

function Stat({ label, value, hint, tone = "text-white" }: { label: string; value: string | number; hint?: string; tone?: string }) {
  return (
    <div className="panel p-5">
      <p className="text-sm text-slate-400">{label}</p>
      <p className={`mt-2 font-display text-4xl leading-none ${tone}`}>{value}</p>
      {hint && <p className="mt-2 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [details, setDetails] = useState<Pick<ScanResponse, "findings">[]>([]);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const sorted = sortRecent(await listScans());
      setScans(sorted);
      const recent = sorted.slice(0, DETAIL_LIMIT);
      const settled = await Promise.allSettled(
        recent.map((s) => (s.findings ? Promise.resolve(s as ScanResponse) : getScan(s.scan_id)))
      );
      setDetails(settled.flatMap((r) => (r.status === "fulfilled" ? [r.value] : [])));
    } catch (e) {
      setScans(null);
      setError(e);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const levels = useMemo(() => (scans ? countByLevel(scans) : []), [scans]);
  const categories = useMemo(() => countFindingsByCategory(details), [details]);
  const count = (l: string) => levels.find((x) => x.level === l)?.count ?? 0;
  const hasScans = !!scans && scans.length > 0;
  const hasFindings = categories.some((c) => c.count > 0);

  return (
    <>
      <PageHeader title="Threat overview" description="Live results from your PhishShield backend. Every number here comes from a saved scan." />

      {!!error && <div className="mb-6"><ErrorBanner error={error} onRetry={load} /></div>}
      {!error && scans === null && <Spinner label="Loading scans" />}

      {scans && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="Total scans" value={scans.length} />
            <Stat label="High risk" value={count("HIGH")} tone="text-orange-300" hint="Risk level HIGH" />
            <Stat label="Critical" value={count("CRITICAL")} tone="text-red-300" hint="Risk level CRITICAL" />
            <Stat label="Suspicious" value={count("SUSPICIOUS")} tone="text-amber-300" hint="Risk level SUSPICIOUS" />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <section className="panel p-5">
              <h2 className="mb-3 text-lg">Risk distribution</h2>
              {hasScans ? <RiskDistributionChart data={levels} /> : <EmptyState title="No scans yet" body="Scan a URL or message and the distribution will appear here." />}
            </section>
            <section className="panel p-5">
              <h2 className="text-lg">Threat categories</h2>
              <p className="mb-3 text-xs text-slate-500">Findings across your {Math.min(scans.length, DETAIL_LIMIT)} most recent scans.</p>
              {hasFindings ? <ThreatCategoryChart data={categories} /> : <EmptyState title="No findings yet" body="Categories appear once a scan reports findings." />}
            </section>
          </div>

          <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
            <section className="panel p-5">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-lg">Recent activity</h2>
                {hasScans && <Link href="/history" className="text-sm text-signal hover:underline">All scans</Link>}
              </div>
              {hasScans ? (
                <ul className="divide-y divide-line">
                  {scans.slice(0, 6).map((s) => (
                    <li key={s.scan_id}>
                      <Link href={`/reports/${encodeURIComponent(s.scan_id)}`} className="flex items-center gap-3 py-3 transition hover:bg-ink-700/40">
                        <span className="w-9 text-center font-display text-lg text-white">{s.risk_score}</span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm text-slate-200">{s.target}</span>
                          <span className="text-xs text-slate-500">{s.target_type} · {timeAgo(s.analyzed_at)}</span>
                        </span>
                        <RiskBadge level={s.risk_level} />
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="Nothing scanned yet" body="Use the quick scan or the browser extension to create your first scan." />
              )}
            </section>
            <QuickScan onScanned={load} />
          </div>
        </div>
      )}

      {/* Quick scan stays available when the backend list can't load */}
      {!!error && <div className="max-w-xl"><QuickScan onScanned={load} /></div>}
    </>
  );
}
