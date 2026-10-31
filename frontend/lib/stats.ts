import type { FindingCategory, RiskLevel, ScanResponse, ScanSummary } from "./api";
import { CATEGORY_ORDER, RISK_ORDER } from "./risk";

/** Counting helpers over real backend data. No scoring happens here. */
export function sortRecent<T extends { analyzed_at?: string }>(scans: T[]): T[] {
  return [...scans].sort((a, b) => Date.parse(b.analyzed_at ?? "") - Date.parse(a.analyzed_at ?? "") || 0);
}

export function countByLevel(scans: ScanSummary[]): { level: RiskLevel; count: number }[] {
  return RISK_ORDER.map((level) => ({ level, count: scans.filter((s) => s.risk_level === level).length }));
}

export function countFindingsByCategory(scans: Pick<ScanResponse, "findings">[]): { category: FindingCategory; count: number }[] {
  const counts: Record<FindingCategory, number> = { url: 0, identity: 0, semantic: 0, behavior: 0, reputation: 0 };
  for (const s of scans) for (const f of s.findings ?? []) if (f.category in counts) counts[f.category] += 1;
  return CATEGORY_ORDER.map((category) => ({ category, count: counts[category] }));
}
