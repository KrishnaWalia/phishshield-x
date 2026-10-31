import { CONFIG, LEVELS, isScannable, isDemoThreat, isOwnDashboard, cleanUrl, normalizeResult, reportUrl } from './config.js';

class ScanError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const S = chrome.storage.session; // cleared when the browser closes: no persistent browsing history
const inflight = new Map();

async function api(path, init = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CONFIG.REQUEST_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(CONFIG.API_BASE_URL + path, { ...init, signal: ctrl.signal, headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    throw e.name === 'AbortError'
      ? new ScanError('timeout', 'The backend took too long to respond.')
      : new ScanError('offline', 'Could not reach the PhishShield X backend.');
  } finally { clearTimeout(timer); }
  if (res.status === 429) throw new ScanError('rate_limited', 'Too many scan requests. Wait a moment and retry.');
  if (res.status >= 500) throw new ScanError('server_error', `The backend reported an error (HTTP ${res.status}).`);
  if (!res.ok) throw new ScanError('bad_request', `The backend rejected the request (HTTP ${res.status}).`);
  try { return await res.json(); }
  catch { throw new ScanError('invalid_response', 'The backend returned an unreadable response.'); }
}
async function post(path, body) {
  const raw = await api(path, { method: 'POST', body: JSON.stringify(body) });
  try { return normalizeResult(raw); }
  catch { throw new ScanError('invalid_response', 'The backend response was missing required fields.'); }
}

const setState = (tabId, s) => S.set({ [`state:${tabId}`]: { ...s, at: Date.now() } });
const badge = (tabId, text, color) =>
  Promise.all([chrome.action.setBadgeText({ tabId, text }), chrome.action.setBadgeBackgroundColor({ tabId, color })]).catch(() => {});
const errInfo = (e) => ({ code: e.code || 'unknown', message: e.code ? e.message : 'The scan failed unexpectedly.' });

async function extractPage(tabId, url) {
  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
    const r = await chrome.tabs.sendMessage(tabId, { type: 'PSX_EXTRACT', maxText: CONFIG.MAX_TEXT_CHARS, maxLinks: CONFIG.MAX_LINKS });
    if (r && r.url === url) return { ...r, limited: false };
  } catch { /* no permission / page not ready: fall back to URL-only */ }
  return { page_title: '', page_text: '', links: [], limited: true };
}

async function doScan(tabId, url) {
  const page = await extractPage(tabId, url);
  const result = await post('/api/v1/scan/url', {
    url, page_title: page.page_title, page_text: page.page_text, links: page.links, source: 'extension',
  });
  return { result, limited: page.limited };
}

async function runScan(tabId, rawUrl, { force = false } = {}) {
  if (!isScannable(rawUrl)) { await setState(tabId, { status: 'unsupported', url: rawUrl }); return; }
  const url = cleanUrl(rawUrl);
  if (!force) {
    const c = (await S.get(`scan:${url}`))[`scan:${url}`];
    if (c && Date.now() - c.at < CONFIG.CACHE_TTL_MS) { await applyResult(tabId, url, c.result, c.limited); return; }
  }
  await setState(tabId, { status: 'scanning', url });
  let p = inflight.get(url); // duplicate-request prevention
  if (!p) { p = doScan(tabId, url).finally(() => inflight.delete(url)); inflight.set(url, p); }
  try {
    const { result, limited } = await p;
    await S.set({ [`scan:${url}`]: { result, limited, at: Date.now() } });
    await applyResult(tabId, url, result, limited);
  } catch (e) {
    await setState(tabId, { status: 'error', url, error: errInfo(e) }); // never labelled safe or malicious
    await badge(tabId, '!', '#64748b');
  }
}

async function applyResult(tabId, url, result, limited) {
  const level = result.risk_level;
  await setState(tabId, { status: 'done', url, result, limited });
  await badge(tabId, LEVELS[level].badge, LEVELS[level].color);

  // Hard interruption ONLY for controlled Scam Arena demo URLs, and only with an escape hatch.
  if (isDemoThreat(url) && CONFIG.INTERRUPT_LEVELS.includes(level)) {
    const k = `allow:${url}`;
    if (!(await S.get(k))[k]) {
      await chrome.tabs.update(tabId, { url: chrome.runtime.getURL('warning.html') + '?u=' + encodeURIComponent(url) });
      return;
    }
  }
  if (['SUSPICIOUS', 'HIGH', 'CRITICAL'].includes(level) && !limited) {
    try {
      await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
      await chrome.tabs.sendMessage(tabId, {
        type: 'PSX_BANNER', level, color: LEVELS[level].color, label: LEVELS[level].label,
        score: result.risk_score, summary: result.summary, action: result.recommended_action,
        report: result.scan_id ? reportUrl(result.scan_id) : '',
      });
    } catch { /* banner is best-effort */ }
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== 'complete' || !tab.url || !isScannable(tab.url) || isOwnDashboard(tab.url)) return;
  let granted = false;
  try { granted = await chrome.permissions.contains({ origins: [new URL(tab.url).origin + '/*'] }); } catch {}
  if (!granted) { await setState(tabId, { status: 'not_scanned', url: tab.url }); await badge(tabId, '', '#000000'); return; }
  runScan(tabId, tab.url);
});
chrome.tabs.onRemoved.addListener((tabId) => S.remove(`state:${tabId}`));

chrome.runtime.onMessage.addListener((m, sender, send) => {
  if (sender.id !== chrome.runtime.id) return;
  (async () => {
    if (m.type === 'SCAN') { await runScan(m.tabId, m.url, { force: true }); send({ ok: true }); }
    else if (m.type === 'HEALTH') {
      try { const h = await api('/health'); send({ ok: !!h && h.status === 'ok' }); }
      catch (e) { send({ ok: false, code: e.code }); }
    }
  })();
  return true;
});

// Message scan: ONLY on explicit user action (right-click selected text).
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'psx-scan-selection', title: 'Scan selected text with PhishShield X', contexts: ['selection'] });
});
chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== 'psx-scan-selection') return;
  const text = (info.selectionText || '').trim().slice(0, 5000);
  if (!text) return;
  let entry;
  try { entry = { result: await post('/api/v1/scan/message', { text, source: 'extension' }) }; }
  catch (e) { entry = { error: errInfo(e) }; }
  await S.set({ 'msg:last': entry });
  chrome.tabs.create({ url: chrome.runtime.getURL('warning.html') + '?kind=message' });
});
