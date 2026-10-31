import Link from "next/link";
import type { ReactNode } from "react";
import { API_BASE_URL, ApiError, type RiskLevel, type Severity } from "@/lib/api";
import { SEVERITY_STYLES, riskStyle } from "@/lib/risk";
import { Icon } from "./Icon";

export function PageHeader({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-2xl">
        <h1 className="text-2xl font-semibold sm:text-3xl">{title}</h1>
        {description && <p className="mt-1.5 text-sm leading-relaxed text-slate-400">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-slate-400" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-signal" />
      {label}
    </span>
  );
}

export function RiskBadge({ level }: { level: RiskLevel | string }) {
  const s = riskStyle(level);
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${s.text} ${s.bg} ${s.border}`}>
      {s.label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.low;
  return <span className={`rounded-md border px-2 py-0.5 text-xs font-medium capitalize ${s.text} ${s.bg} ${s.border}`}>{severity}</span>;
}

const ERROR_TITLES: Record<string, string> = {
  config: "API address not configured",
  network: "Can't reach the backend",
  timeout: "The backend timed out",
  validation: "The backend rejected this input",
  not_found: "Not found",
  server: "The backend reported an error",
  parse: "Unexpected backend response",
};

export function ErrorBanner({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const err = error instanceof ApiError ? error : null;
  const message = err ? err.message : error instanceof Error ? error.message : String(error);
  return (
    <div className="flex gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-sm" role="alert">
      <Icon name="alert" className="mt-0.5 h-5 w-5 shrink-0 text-red-300" />
      <div className="space-y-1.5">
        <p className="font-medium text-red-200">{err ? ERROR_TITLES[err.kind] : "Something went wrong"}</p>
        <p className="text-red-100/80">{message}</p>
        {err?.kind === "network" && (
          <p className="text-red-100/60">
            Start the FastAPI backend (expected at {API_BASE_URL || "the configured API base URL"}) and make sure it allows
            CORS requests from this page&apos;s origin.
          </p>
        )}
        {onRetry && (
          <button onClick={onRetry} className="mt-1 text-red-200 underline underline-offset-2 hover:text-white">
            Try again
          </button>
        )}
      </div>
    </div>
  );
}

export function EmptyState({ title, body, href, cta }: { title: string; body: string; href?: string; cta?: string }) {
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-10 text-center">
      <p className="font-display text-lg text-white">{title}</p>
      <p className="max-w-sm text-sm text-slate-400">{body}</p>
      {href && cta && (
        <Link href={href} className="btn-primary mt-3">
          {cta}
        </Link>
      )}
    </div>
  );
}
