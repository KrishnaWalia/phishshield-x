"use client";

import { useState } from "react";
import { scanMessage, type ScanResponse } from "@/lib/api";
import { MAX_MESSAGE_LENGTH, validateMessageInput } from "@/lib/validate";
import { ScanReport } from "@/components/ScanReport";
import { ErrorBanner, PageHeader, Spinner } from "@/components/ui";

export default function MessageScannerPage() {
  // Message text lives only in component state. It is never written to storage.
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [inputError, setInputError] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const check = validateMessageInput(text);
    if (!check.ok) { setInputError(check.error); return; }
    setInputError(null);
    setLoading(true);
    setResult(null);
    try {
      setResult(await scanMessage(check.value, "dashboard"));
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <PageHeader title="Message scanner" description="Paste an SMS, email or chat message to see which pressure tactics and suspicious phrases it uses." />
      <form onSubmit={submit} className="panel mb-6 space-y-3 p-5">
        <label htmlFor="msg" className="text-sm text-slate-300">Message text</label>
        <textarea id="msg" className="input min-h-[160px] resize-y" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the full message here" />
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className={`text-xs ${text.length > MAX_MESSAGE_LENGTH ? "text-red-300" : "text-slate-500"}`}>
            {text.length.toLocaleString()} / {MAX_MESSAGE_LENGTH.toLocaleString()} characters. Your text isn&apos;t saved in this browser.
          </p>
          <div className="flex gap-2">
            <button type="button" className="btn-ghost" onClick={() => { setText(""); setResult(null); setInputError(null); }}>Clear</button>
            <button className="btn-primary" disabled={loading}>{loading ? "Scanning…" : "Scan message"}</button>
          </div>
        </div>
        {inputError && <p className="text-sm text-red-300">{inputError}</p>}
      </form>
      {loading && <Spinner label="Analysing message" />}
      {!!error && <ErrorBanner error={error} />}
      {result && <ScanReport scan={result} showReportLink />}
    </>
  );
}
