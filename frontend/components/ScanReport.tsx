import Link from "next/link";
import type { Finding, ScanResponse } from "@/lib/api";
import { CATEGORY_META, CATEGORY_ORDER, SEVERITY_RANK, SEVERITY_STYLES, formatDateTime } from "@/lib/risk";
import { ScoreGauge } from "./ScoreGauge";
import { RiskBadge, SeverityBadge } from "./ui";

function EngineChip({ label, on }: { label: string; on: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs ${on ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300" : "border-line bg-ink-900 text-slate-500"}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${on ? "bg-emerald-400" : "bg-slate-600"}`} />
      {label}: {on ? "ran" : "not used"}
    </span>
  );
}

function FindingCard({ f }: { f: Finding }) {
  const s = SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.low;
  return (
    <li className="flex gap-3 rounded-lg border border-line bg-ink-900/70 p-4">
      <span className={`mt-1 h-full min-h-[2.5rem] w-1 shrink-0 rounded-full ${s.bar}`} />
      <div className="min-w-0 flex-1 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-white">{f.title}</span>
          <SeverityBadge severity={f.severity} />
          <span className="ml-auto font-display text-sm text-slate-300">+{f.points} pts</span>
        </div>
        {f.evidence && <p className="break-words rounded-md bg-ink-950 px-3 py-2 font-mono text-xs text-slate-300">{f.evidence}</p>}
        <p className="text-sm leading-relaxed text-slate-400">{f.explanation}</p>
      </div>
    </li>
  );
}

/** Message insights are DERIVED from the backend's findings; the backend contract has no dedicated message fields. */
function MessageInsights({ findings }: { findings: Finding[] }) {
  const language = findings.filter((f) => f.category === "semantic" || f.category === "identity");
  const top = [...language].sort((a, b) => b.points - a.points)[0];
  const phrases = Array.from(new Set(language.map((f) => f.evidence).filter(Boolean)));

  return (
    <section className="panel space-y-5 p-5">
      <div>
        <h2 className="text-lg">Message analysis</h2>
        <p className="text-xs text-slate-500">Grouped from the backend&apos;s language and identity findings.</p>
      </div>
      <div>
        <p className="text-sm text-slate-400">Likely scam category</p>
        <p className="mt-1 font-display text-xl text-white">{top ? top.title : "No scam pattern identified"}</p>
      </div>
      <div>
        <p className="mb-2 text-sm text-slate-400">Social-engineering tactics detected</p>
        {language.length === 0 ? (
          <p className="text-sm text-slate-500">None reported.</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {language.map((f) => (
              <li key={f.id} className="rounded-md border border-line bg-ink-900 px-2.5 py-1 text-sm text-slate-200" title={f.explanation}>
                {f.title}
              </li>
            ))}
          </ul>
        )}
      </div>
      <div>
        <p className="mb-2 text-sm text-slate-400">Suspicious phrases</p>
        {phrases.length === 0 ? (
          <p className="text-sm text-slate-500">No specific phrases were reported.</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {phrases.map((p) => (
              <li key={p} className="rounded-md border border-red-400/30 bg-red-400/10 px-2.5 py-1 font-mono text-xs text-red-200">{p}</li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

export function ScanReport({ scan, showReportLink = false }: { scan: ScanResponse; showReportLink?: boolean }) {
  const findings = scan.findings ?? [];
  const isMessage = scan.target_type === "message";
  const engines = scan.engines;

  return (
    <div className="space-y-5">
      {/* Overall assessment */}
      <section className="panel flex flex-col gap-6 p-5 sm:flex-row sm:items-center sm:p-6">
        <ScoreGauge score={scan.risk_score} level={scan.risk_level} />
        <div className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <RiskBadge level={scan.risk_level} />
            <span className="text-sm text-slate-400">Risk score {scan.risk_score} / 100</span>
          </div>
          <p className="text-lg leading-snug text-white">{scan.summary}</p>
          <dl className="grid gap-x-6 gap-y-1 text-sm text-slate-400 sm:grid-cols-2">
            <div className="min-w-0">
              <dt className="inline">{isMessage ? "Subject: " : "Target: "}</dt>
              <dd className="inline break-all text-slate-200">{scan.target}</dd>
            </div>
            <div><dt className="inline">Scanned: </dt><dd className="inline text-slate-200">{formatDateTime(scan.analyzed_at)}</dd></div>
            <div><dt className="inline">Type: </dt><dd className="inline text-slate-200">{scan.target_type}</dd></div>
            <div><dt className="inline">Scan ID: </dt><dd className="inline font-mono text-xs text-slate-200">{scan.scan_id}</dd></div>
          </dl>
          {showReportLink && (
            <Link href={`/reports/${encodeURIComponent(scan.scan_id)}`} className="inline-block text-sm text-signal underline underline-offset-2 hover:text-sky-200">
              Open full investigation report
            </Link>
          )}
        </div>
      </section>

      {/* Recommended action + engines */}
      <section className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
        <div className="panel border-l-2 border-l-signal p-5">
          <h2 className="text-lg">Recommended action</h2>
          <p className="mt-2 text-slate-300">{scan.recommended_action}</p>
        </div>
        <div className="panel space-y-3 p-5">
          <h2 className="text-lg">Analysis engines</h2>
          <div className="flex flex-wrap gap-2">
            <EngineChip label="Rule engine" on={!!engines?.rules} />
            <EngineChip label="ML model" on={!!engines?.ml} />
            <EngineChip label="AI analysis" on={!!engines?.ai} />
          </div>
          {engines && !engines.ai && (
            <p className="text-xs leading-relaxed text-amber-300/90">
              AI analysis was unavailable for this scan. The score comes from the engines that did run, so semantic findings may be limited.
            </p>
          )}
        </div>
      </section>

      {isMessage && <MessageInsights findings={findings} />}

      {/* Category breakdown */}
      <section className="panel p-5">
        <h2 className="text-lg">Where the risk comes from</h2>
        <p className="mb-4 text-xs text-slate-500">Points reported by the backend per category, against each category&apos;s maximum.</p>
        <div className="space-y-3">
          {CATEGORY_ORDER.map((cat) => {
            const pts = findings.filter((f) => f.category === cat).reduce((n, f) => n + f.points, 0);
            const { label, cap, blurb } = CATEGORY_META[cat];
            return (
              <div key={cat}>
                <div className="mb-1 flex items-baseline justify-between text-sm">
                  <span className="text-slate-200">{label} <span className="hidden text-xs text-slate-500 sm:inline">{blurb}</span></span>
                  <span className="font-display text-slate-300">{Math.min(pts, cap)} / {cap}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-ink-700">
                  <div className="h-full rounded-full bg-signal transition-[width] duration-700" style={{ width: `${Math.min(100, (pts / cap) * 100)}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Findings by category */}
      <section className="space-y-4">
        <h2 className="text-lg">Findings and evidence</h2>
        {findings.length === 0 ? (
          <div className="panel p-5 text-sm text-slate-400">The backend reported no suspicious indicators for this scan.</div>
        ) : (
          CATEGORY_ORDER.map((cat) => {
            const items = findings.filter((f) => f.category === cat).sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
            if (items.length === 0) return null;
            return (
              <div key={cat} className="panel p-5">
                <h3 className="mb-3 text-base">{CATEGORY_META[cat].label} <span className="text-sm text-slate-500">({items.length})</span></h3>
                <ul className="space-y-3">{items.map((f) => <FindingCard key={f.id} f={f} />)}</ul>
              </div>
            );
          })
        )}
      </section>
    </div>
  );
}
