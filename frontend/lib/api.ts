/**
 * Shared PhishShield X API client.
 * ALL backend requests in the frontend go through this file.
 * Interfaces mirror the shared API contract (exact snake_case names).
 */

// ---------- Contract types ----------
export type Source = "extension" | "dashboard" | "arena";
export type FindingCategory = "url" | "identity" | "semantic" | "behavior" | "reputation";
export type Severity = "low" | "medium" | "high" | "critical";
export type RiskLevel = "LOW" | "MODERATE" | "SUSPICIOUS" | "HIGH" | "CRITICAL";

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  points: number;
  title: string;
  evidence: string;
  explanation: string;
}

export interface EngineStatus {
  rules: boolean;
  ml: boolean;
  ai: boolean;
}

export interface ScanResponse {
  scan_id: string;
  /** Contract example is "url"; message scans are expected to use "message". */
  target_type: string;
  target: string;
  risk_score: number;
  risk_level: RiskLevel;
  summary: string;
  findings: Finding[];
  recommended_action: string;
  analyzed_at: string;
  engines: EngineStatus;
}

/** History rows: the list endpoint's exact shape is not fixed by the contract, so extra fields are optional. */
export type ScanSummary = Pick<
  ScanResponse,
  "scan_id" | "target_type" | "target" | "risk_score" | "risk_level" | "analyzed_at"
> &
  Partial<ScanResponse>;

export interface UrlScanRequest {
  url: string;
  page_title: string;
  page_text: string;
  links: string[];
  source: Source;
}

export interface MessageScanRequest {
  text: string;
  source: Source;
}

// ---------- Errors ----------
export type ApiErrorKind =
  | "config"
  | "network"
  | "timeout"
  | "validation"
  | "not_found"
  | "server"
  | "parse";

export class ApiError extends Error {
  kind: ApiErrorKind;
  status?: number;
  constructor(kind: ApiErrorKind, message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

// ---------- Core request helper ----------
export const API_BASE_URL = process.env.NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL?.trim().replace(/\/+$/, "") || "";
const TIMEOUT_MS = 20_000;

function detailToText(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // FastAPI/Pydantic validation errors: [{ loc, msg }]
    return detail
      .map((d) => (d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : ""))
      .filter(Boolean)
      .join("; ") || null;
  }
  return null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!API_BASE_URL) {
    throw new ApiError(
      "config",
      "NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL is not set. Add it to frontend/.env.local and restart the dev server."
    );
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    let res: Response;
    try {
      res = await fetch(`${API_BASE_URL}${path}`, {
        ...init,
        signal: controller.signal,
        cache: "no-store",
        headers: {
          Accept: "application/json",
          ...(init?.body ? { "Content-Type": "application/json" } : {}),
        },
      });
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") {
        throw new ApiError("timeout", "The backend took too long to respond. Try again in a moment.");
      }
      throw new ApiError("network", `Could not reach the PhishShield backend at ${API_BASE_URL}.`);
    }

    let body: unknown = null;
    const text = await res.text();
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        if (res.ok) throw new ApiError("parse", "The backend returned a response that is not valid JSON.");
      }
    }

    if (!res.ok) {
      const detail = detailToText(body);
      if (res.status === 404) throw new ApiError("not_found", detail ?? "Not found.", 404);
      if (res.status === 400 || res.status === 422) {
        throw new ApiError("validation", detail ?? "The backend rejected this input.", res.status);
      }
      throw new ApiError("server", detail ?? `The backend returned an error (HTTP ${res.status}).`, res.status);
    }
    return body as T;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- Endpoints ----------
export function getHealth(): Promise<unknown> {
  return request("/health");
}

export function scanUrl(input: {
  url: string;
  page_title?: string;
  page_text?: string;
  links?: string[];
  source?: Source;
}): Promise<ScanResponse> {
  const body: UrlScanRequest = {
    url: input.url,
    page_title: input.page_title ?? "Manual URL scan",
    page_text: input.page_text ?? "",
    links: input.links ?? [],
    source: input.source ?? "dashboard",
  };
  return request<ScanResponse>("/api/v1/scan/url", { method: "POST", body: JSON.stringify(body) });
}

export function scanMessage(text: string, source: Source = "dashboard"): Promise<ScanResponse> {
  const body: MessageScanRequest = { text, source };
  return request<ScanResponse>("/api/v1/scan/message", { method: "POST", body: JSON.stringify(body) });
}

/** Accepts a bare array or a wrapper object ({scans|items|results|data: [...]}). */
function normalizeScanList(raw: unknown): ScanSummary[] {
  let list: unknown = raw;
  if (!Array.isArray(raw) && raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    list = obj.scans ?? obj.items ?? obj.results ?? obj.data ?? [];
  }
  if (!Array.isArray(list)) {
    throw new ApiError("parse", "Unexpected response format from GET /api/v1/scans.");
  }
  return list.filter(
    (s): s is ScanSummary => !!s && typeof s === "object" && typeof (s as ScanSummary).scan_id === "string"
  );
}

export async function listScans(): Promise<ScanSummary[]> {
  return normalizeScanList(await request<unknown>("/api/v1/scans"));
}

export function getScan(scanId: string): Promise<ScanResponse> {
  return request<ScanResponse>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
}
