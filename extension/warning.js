import { LEVELS, isScannable, isDemoThreat, reportUrl, arenaUrl } from './config.js';

const root = document.getElementById('root');
const q = new URLSearchParams(location.search);
const S = chrome.storage.session;
const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v; else if (k === 'onclick') n.onclick = v; else if (k === 'style') n.style.cssText = v; else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
};

function findingsList(r, n) {
  const top = [...r.findings].sort((a, b) => b.points - a.points).slice(0, n);
  return top.length ? el('ul', { class: 'findings' }, top.map((f) => el('li', {},
    el('span', { class: `sev sev-${f.severity}` }), el('b', {}, f.title),
    f.evidence ? el('small', {}, 'Evidence: ' + f.evidence) : null,
    f.explanation ? el('small', {}, f.explanation) : null))) : null;
}
const header = (r, title) => {
  const L = LEVELS[r.risk_level];
  return [el('span', { class: 'pill', style: `background:${L.color}` }, `${r.risk_level} · ${r.risk_score}/100`),
    el('h1', {}, title), el('p', {}, r.summary || 'The backend flagged indicators on this content.')];
};

async function pageWarning() {
  const url = q.get('u') || '';
  const valid = isScannable(url) && isDemoThreat(url);
  const hit = valid ? (await S.get(`scan:${url}`))[`scan:${url}`] : null;
  const r = hit?.result;
  const card = el('div', { class: 'card wcard', style: `--c:${r ? LEVELS[r.risk_level].color : '#ef4444'}` });
  if (r) {
    card.append(...header(r, `This site looks risky: ${new URL(url).hostname}`),
      el('p', { class: 'note' }, 'This is a controlled Scam Arena training simulation.'),
      findingsList(r, 5),
      r.recommended_action ? el('p', {}, el('b', {}, 'Recommended: '), r.recommended_action) : null);
  } else {
    card.append(el('h1', {}, 'Warning details unavailable'), el('p', {}, 'The scan result expired or the link is invalid. Return to safety or rescan from the extension popup.'));
  }
  root.append(card,
    el('button', { class: 'btn primary', onclick: () => chrome.tabs.update({ url: arenaUrl() }) }, 'Return to Scam Arena'));
  if (r?.scan_id) root.append(el('a', { class: 'btn', href: reportUrl(r.scan_id), target: '_blank', rel: 'noopener' }, 'View detailed report'));
  if (valid) root.append(el('button', {
    class: 'link', onclick: async () => { await S.set({ [`allow:${url}`]: true }); chrome.tabs.update({ url }); },
  }, 'I understand this is a simulation: continue anyway'));
}

async function messageResult() {
  const e = (await S.get('msg:last'))['msg:last'];
  if (!e || e.error) {
    root.append(el('div', { class: 'card wcard', style: '--c:#64748b' }, el('h1', {}, 'Message scan failed'),
      el('p', {}, e?.error?.message || 'No result is available. The message has NOT been assessed.')));
  } else {
    const r = e.result;
    root.append(el('div', { class: 'card wcard', style: `--c:${LEVELS[r.risk_level].color}` },
      ...header(r, 'Message scan result'), findingsList(r, 6),
      r.recommended_action ? el('p', {}, el('b', {}, 'Recommended: '), r.recommended_action) : null));
    if (r.scan_id) root.append(el('a', { class: 'btn', href: reportUrl(r.scan_id), target: '_blank', rel: 'noopener' }, 'View detailed report'));
  }
  root.append(el('button', { class: 'btn', onclick: () => window.close() }, 'Close'));
}

q.get('kind') === 'message' ? messageResult() : pageWarning();
