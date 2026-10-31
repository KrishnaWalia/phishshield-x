"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ApiError, getScan, type ScanResponse } from "@/lib/api";
import { ScanReport } from "@/components/ScanReport";
import { ErrorBanner, PageHeader, Spinner } from "@/components/ui";

export default function ReportPage() {
  const params = useParams<{ scanId: string }>();
  const scanId = decodeURIComponent(params.scanId);
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    setError(null);
    setScan(null);
    try { setScan(await getScan(scanId)); } catch (e) { setError(e); }
  }, [scanId]);
  useEffect(() => { load(); }, [load]);

  const notFound = error instanceof ApiError && error.kind === "not_found";

  return (
    <>
      <PageHeader
        title="Investigation report"
        description={`Scan ${scanId}`}
        action={<Link href="/history" className="btn-ghost">Back to history</Link>}
      />
      {!scan && !error && <Spinner label="Loading report" />}
      {notFound ? (
        <div className="panel p-6">
          <p className="font-display text-lg text-white">No scan with that ID</p>
          <p className="mt-1 text-sm text-slate-400">&ldquo;{scanId}&rdquo; isn&apos;t in the backend&apos;s history. Check the ID, or pick a scan from the history list.</p>
          <Link href="/history" className="btn-primary mt-4">Open scan history</Link>
        </div>
      ) : (
        !!error && <ErrorBanner error={error} onRetry={load} />
      )}
      {scan && <ScanReport scan={scan} />}
    </>
  );
}
