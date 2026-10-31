// Shared config + helpers (ES module). All environment-specific values live HERE.
export const CONFIG = {
  // Maps to PHISHSHIELD_EXTENSION_API_BASE_URL (extensions have no .env). If you change
  // this, also change host_permissions in manifest.json.
  API_BASE_URL: 'http://127.0.0.1:8000',

  // PROVISIONAL: confirm all of these with Member 3 (frontend / Scam Arena).
  DASHBOARD_URL: 'http://localhost:3000',
  REPORT_PATH: '/reports/{scan_id}',
  ARENA_PATH: '/arena',
  // Arena scenarios live at /arena/<slug> (simulated browser frame inside the dashboard).
  DEMO_THREATS: [{ origin: 'http://localhost:3000', pathPrefix: '/arena/' }],
  // slug -> the FICTIONAL URL shown in that scenario (mirrors frontend/lib/arena.ts). The backend
  // scans this instead of localhost. If Member 3 changes a scenario URL, update it here.
  ARENA_SCENARIOS: {
    'banking-kyc': 'https://novatrust-kyc-verify.account-secure.top/update',
    'upi-reward': 'http://quickpay-cashback-claim.win/rewards',
    'fake-job': 'https://brightpath-careers-hiring.work-apply.click/apply',
  },

  INTERRUPT_LEVELS: ['HIGH', 'CRITICAL'], // full-page warning, demo threats ONLY
  REQUEST_TIMEOUT_MS: 10000,
  CACHE_TTL_MS: 5 * 60 * 1000,
  MAX_TEXT_CHARS: 5000,
  MAX_LINKS: 30, // backend contract: links max 30 items (more => HTTP 422)
};

export const LEVELS = {
  LOW: { label: 'Low risk', color: '#22c55e', badge: 'OK' },
  MODERATE: { label: 'Moderate', color: '#3b82f6', badge: 'MOD' },
  SUSPICIOUS: { label: 'Suspicious', color: '#eab308', badge: 'SUS' },
  HIGH: { label: 'High risk', color: '#f97316', badge: 'HIGH' },
  CRITICAL: { label: 'Critical', color: '#ef4444', badge: 'CRIT' },
};

export function isScannable(url) {
  try { const u = new URL(url); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
}
export function cleanUrl(url) { const u = new URL(url); u.hash = ''; return u.toString(); }
export function isDemoThreat(url) {
  try {
    const u = new URL(url);
    return CONFIG.DEMO_THREATS.some((d) => u.origin === d.origin && u.pathname.startsWith(d.pathPrefix));
  } catch { return false; }
}
export function scenarioUrl(url) {
  if (!isDemoThreat(url)) return null;
  return CONFIG.ARENA_SCENARIOS[new URL(url).pathname.split('/').filter(Boolean)[1]] || null;
}
export function isOwnDashboard(url) {
  try { return new URL(url).origin === new URL(CONFIG.DASHBOARD_URL).origin && !isDemoThreat(url); }
  catch { return false; }
}
export const reportUrl = (id) => CONFIG.DASHBOARD_URL + CONFIG.REPORT_PATH.replace('{scan_id}', encodeURIComponent(id));
export const arenaUrl = () => CONFIG.DASHBOARD_URL + CONFIG.ARENA_PATH;

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
// Validates the backend response. Never recalculates score/level; only sanitizes shape.
export function normalizeResult(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('not an object');
  const level = String(raw.risk_level || '').toUpperCase();
  if (!LEVELS[level]) throw new Error('bad risk_level');
  const score = Number(raw.risk_score);
  if (!Number.isFinite(score)) throw new Error('bad risk_score');
  const str = (v, d = '') => (typeof v === 'string' ? v : d);
  const findings = (Array.isArray(raw.findings) ? raw.findings : [])
    .filter((f) => f && typeof f === 'object')
    .map((f) => ({
      id: str(f.id), category: str(f.category),
      severity: SEVERITIES.includes(f.severity) ? f.severity : 'low',
      points: Number.isFinite(Number(f.points)) ? Number(f.points) : 0,
      title: str(f.title, 'Untitled finding'), evidence: str(f.evidence), explanation: str(f.explanation),
    }));
  return {
    scan_id: str(raw.scan_id), target_type: str(raw.target_type), target: str(raw.target),
    risk_score: Math.max(0, Math.min(100, Math.round(score))), risk_level: level,
    summary: str(raw.summary), findings, recommended_action: str(raw.recommended_action),
    analyzed_at: str(raw.analyzed_at),
    engines: raw.engines && typeof raw.engines === 'object' ? raw.engines : {},
  };
}
