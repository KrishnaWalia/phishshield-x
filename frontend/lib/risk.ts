import type { FindingCategory, RiskLevel, Severity } from "./api";

/** Presentation only. Scores and levels always come from the backend. */
export const RISK_STYLES: Record<RiskLevel, { hex: string; text: string; bg: string; border: string; label: string }> = {
  LOW: { hex: "#34d399", text: "text-emerald-300", bg: "bg-emerald-400/10", border: "border-emerald-400/30", label: "Low" },
  MODERATE: { hex: "#a3e635", text: "text-lime-300", bg: "bg-lime-400/10", border: "border-lime-400/30", label: "Moderate" },
  SUSPICIOUS: { hex: "#fbbf24", text: "text-amber-300", bg: "bg-amber-400/10", border: "border-amber-400/30", label: "Suspicious" },
  HIGH: { hex: "#fb923c", text: "text-orange-300", bg: "bg-orange-400/10", border: "border-orange-400/30", label: "High" },
  CRITICAL: { hex: "#f87171", text: "text-red-300", bg: "bg-red-400/10", border: "border-red-400/30", label: "Critical" },
};

export const RISK_ORDER: RiskLevel[] = ["LOW", "MODERATE", "SUSPICIOUS", "HIGH", "CRITICAL"];

export const SEVERITY_STYLES: Record<Severity, { text: string; bg: string; border: string; bar: string }> = {
  low: { text: "text-sky-300", bg: "bg-sky-400/10", border: "border-sky-400/30", bar: "bg-sky-400" },
  medium: { text: "text-amber-300", bg: "bg-amber-400/10", border: "border-amber-400/30", bar: "bg-amber-400" },
  high: { text: "text-orange-300", bg: "bg-orange-400/10", border: "border-orange-400/30", bar: "bg-orange-400" },
  critical: { text: "text-red-300", bg: "bg-red-400/10", border: "border-red-400/30", bar: "bg-red-400" },
};

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Category caps are defined by the backend scoring contract; used only to size display bars. */
export const CATEGORY_META: Record<FindingCategory, { label: string; cap: number; blurb: string }> = {
  url: { label: "URL structure", cap: 25, blurb: "Domain, path and address patterns" },
  identity: { label: "Brand identity", cap: 20, blurb: "Impersonation of known brands" },
  semantic: { label: "Language & intent", cap: 25, blurb: "Social-engineering wording" },
  behavior: { label: "Page behaviour", cap: 20, blurb: "Forms, redirects, scripts" },
  reputation: { label: "Reputation", cap: 10, blurb: "Known-bad signals" },
};

export const CATEGORY_ORDER: FindingCategory[] = ["url", "identity", "semantic", "behavior", "reputation"];

export function riskStyle(level: string) {
  return RISK_STYLES[level as RiskLevel] ?? RISK_STYLES.LOW;
}

export function formatDateTime(iso: string | undefined): string {
  if (!iso) return "Unknown time";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function timeAgo(iso: string | undefined): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
