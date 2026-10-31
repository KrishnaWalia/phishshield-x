"use client";

import { useState } from "react";
import { scanUrl, type ScanResponse } from "@/lib/api";
import { validateUrlInput } from "@/lib/validate";
import { ScanReport } from "@/components/ScanReport";
import { ErrorBanner, PageHeader, Spinner } from "@/components/ui";

export default function UrlScannerPage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [inputError, setInputError] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const check = validateUrlInput(url);
    if (!check.ok) { setInputError(check.error); return; }
    setInputError(null);
    setLoading(true);
    setResult(null);
    try {
      // The backend only analyses the string; it never opens the URL.
      setResult(await scanUrl({ url: check.value, page_title: "Manual URL scan", page_text: "", links: [], source: "dashboard" }));
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <PageHeader title="URL scanner" description="Check a link before you open it. The backend analyses the address itself; it never visits the site." />
      <form onSubmit={submit} className="panel mb-6 space-y-3 p-5">
        <label htmlFor="url" className="text-sm text-slate-300">Website address</label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <input id="url" className="input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/login" inputMode="url" autoComplete="off" />
          <button className="btn-primary sm:w-36" disabled={loading}>{loading ? "Scanning…" : "Scan URL"}</button>
        </div>
        {inputError && <p className="text-sm text-red-300">{inputError}</p>}
      </form>
      {loading && <Spinner label="Analysing URL" />}
      {!!error && <ErrorBanner error={error} />}
      {result && <ScanReport scan={result} showReportLink />}
    </>
  );
}
