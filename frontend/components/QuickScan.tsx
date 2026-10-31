"use client";

import Link from "next/link";
import { useState } from "react";
import { scanMessage, scanUrl, type ScanResponse } from "@/lib/api";
import { validateMessageInput, validateUrlInput } from "@/lib/validate";
import { ScoreGauge } from "./ScoreGauge";
import { ErrorBanner, RiskBadge, Spinner } from "./ui";

export function QuickScan({ onScanned }: { onScanned?: () => void }) {
  const [mode, setMode] = useState<"url" | "message">("url");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [inputError, setInputError] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    const check = mode === "url" ? validateUrlInput(value) : validateMessageInput(value);
    if (!check.ok) return setInputError(check.error);
    setInputError(null);
    setLoading(true);
    try {
      const res = mode === "url" ? await scanUrl({ url: check.value }) : await scanMessage(check.value);
      setResult(res);
      setValue(""); // never keep submitted message text around
      onScanned?.();
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-lg">Quick scan</h2>
        <div className="flex rounded-lg border border-line bg-ink-900 p-0.5 text-sm" role="tablist">
          {(["url", "message"] as const).map((m) => (
            <button key={m} role="tab" aria-selected={mode === m} onClick={() => { setMode(m); setInputError(null); setValue(""); }}
              className={`rounded-md px-3 py-1 transition ${mode === m ? "bg-ink-600 text-white" : "text-slate-400 hover:text-slate-200"}`}>
              {m === "url" ? "URL" : "Message"}
            </button>
          ))}
        </div>
      </div>
      <form onSubmit={submit} className="space-y-3">
        {mode === "url" ? (
          <input className="input" value={value} onChange={(e) => setValue(e.target.value)} placeholder="https://example.com/login" aria-label="URL to scan" inputMode="url" />
        ) : (
          <textarea className="input min-h-[96px] resize-y" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Paste a suspicious SMS, email or chat message" aria-label="Message to scan" />
        )}
        {inputError && <p className="text-sm text-red-300">{inputError}</p>}
        <button className="btn-primary" disabled={loading}>{loading ? "Scanning…" : "Scan now"}</button>
      </form>
      <div className="mt-4 space-y-3">
        {loading && <Spinner label="Analysing" />}
        {!!error && <ErrorBanner error={error} />}
        {result && (
          <div className="flex items-center gap-4 rounded-lg border border-line bg-ink-900/70 p-4">
            <ScoreGauge score={result.risk_score} level={result.risk_level} size={84} />
            <div className="min-w-0 space-y-1.5">
              <RiskBadge level={result.risk_level} />
              <p className="text-sm text-slate-300">{result.summary}</p>
              <Link href={`/reports/${encodeURIComponent(result.scan_id)}`} className="text-sm text-signal underline underline-offset-2">View full report</Link>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
