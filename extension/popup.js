import { LEVELS, isScannable, cleanUrl, reportUrl } from './config.js';

const root = document.getElementById('root');
let tab;

const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v; else if (k === 'onclick') n.onclick = v; else if (k === 'style') n.style.cssText = v; else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n; // all text via text nodes: backend strings are never parsed as HTML
};

const ERR = {
  offline: ['Backend unavailable', 'Could not reach the PhishShield X backend. This site has NOT been assessed: it is not confirmed safe or dangerous.'],
  timeout: ['Scan timed out', 'The backend took too long to respond. This site has NOT been assessed.'],
  rate_limited: ['Rate limited', 'Too many scans in a short time. Wait a moment, then retry.'],
  server_error: ['Backend error', 'The backend hit an internal error. This site has NOT been assessed.'],
  bad_request: ['Scan failed', 'The backend rejected this scan request.'],
  invalid_response: ['Scan failed', 'The backend returned an invalid response, so no result is shown.'],
  unknown: ['Scan failed', 'The scan could not be completed.'],
};

const scan = () => chrome.runtime.sendMessage({ type: 'SCAN', tabId: tab.id, url: tab.url });
const scanBtn = (label, primary) => el('button', { class: 'btn' + (primary ? ' primary' : ''), onclick: scan }, label);

async function autoBtn() {
  const granted = await chrome.permissions.contains({ origins: ['http://*/*', 'https://*/*'] });
  if (granted) return null;
  return el('button', {
    class: 'btn', onclick: async () => {
      if (await chrome.permissions.request({ origins: ['http://*/*', 'https://*/*'] })) scan();
    },
  }, 'Enable automatic scanning on all sites');
}

async function render(s) {
  root.replaceChildren();
  if (!tab || !tab.url || !isScannable(tab.url)) {
    root.append(el('div', { class: 'card' }, el('h2', {}, 'Page not supported'),
      el('p', {}, 'PhishShield X scans regular http(s) websites, not browser-internal pages.')));
    return;
  }
  root.append(el('div', { class: 'domain' }, new URL(tab.url).hostname));
  if (!s || s.url !== cleanUrl(tab.url) || s.status === 'not_scanned' || s.status === 'unsupported') s = { status: 'not_scanned' };

  if (s.status === 'not_scanned') {
    root.append(el('div', { class: 'card' }, el('h2', {}, 'Not scanned'),
      el('p', {}, 'This page has not been scanned yet. Scanning sends the URL, title, visible text and links (never form inputs) to your PhishShield X backend.')),
      scanBtn('Scan this page', true));
    const a = await autoBtn(); if (a) root.append(a);
  } else if (s.status === 'scanning') {
    root.append(el('div', { class: 'card' }, el('h2', {}, el('span', { class: 'spin' }), 'Scanning…'), el('p', {}, 'Waiting for the backend assessment.')));
  } else if (s.status === 'error') {
    const [title, msg] = ERR[s.error?.code] || ERR.unknown;
    const health = el('p', { class: 'note' });
    root.append(el('div', { class: 'card' }, el('h2', {}, title), el('p', {}, msg), health), scanBtn('Retry', true));
    if (['offline', 'timeout', 'server_error'].includes(s.error?.code)) {
      chrome.runtime.sendMessage({ type: 'HEALTH' }).then((r) => { health.textContent = r?.ok ? 'Health check: backend is reachable.' : 'Health check: backend is not responding.'; });
    }
  } else if (s.status === 'done') {
    const r = s.result, L = LEVELS[r.risk_level];
    const top = [...r.findings].sort((a, b) => b.points - a.points).slice(0, 3);
    root.append(el('div', { class: 'card' },
      el('div', { class: 'score' },
        el('div', { class: 'num', style: `color:${L.color}` }, r.risk_score),
        el('div', {}, el('span', { class: 'pill', style: `background:${L.color}` }, r.risk_level), el('p', { style: 'margin-top:6px' }, r.summary))),
      el('p', { class: 'note' }, `${r.findings.length} finding${r.findings.length === 1 ? '' : 's'}`),
      top.length ? el('ul', { class: 'findings' }, top.map((f) =>
        el('li', {}, el('span', { class: `sev sev-${f.severity}` }), f.title, f.explanation ? el('small', {}, f.explanation) : null))) : null,
      r.recommended_action ? el('p', { class: 'note' }, r.recommended_action) : null,
      s.limited ? el('p', { class: 'note' }, 'Limited scan: only the URL was analyzed (page content was not accessible).') : null));
    if (r.scan_id) root.append(el('a', { class: 'btn primary', href: reportUrl(r.scan_id), target: '_blank', rel: 'noopener' }, 'View detailed report'));
    root.append(scanBtn('Rescan'));
  }
}

(async function init() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const k = `state:${tab?.id}`;
  render((await chrome.storage.session.get(k))[k]);
  chrome.storage.onChanged.addListener((c, area) => { if (area === 'session' && c[k]) render(c[k].newValue); });
})();
