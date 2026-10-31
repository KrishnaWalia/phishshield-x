// Injected on demand by the background worker. Extracts ONLY non-sensitive visible text + links.
(() => {
  if (window.__psxLoaded) return;
  window.__psxLoaded = true;

  // Never read these (private conversations). URL-only scan instead.
  const PRIVATE = new Set(['web.whatsapp.com', 'mail.google.com', 'outlook.live.com', 'outlook.office.com',
    'web.telegram.org', 'www.messenger.com', 'discord.com']);
  const SKIP = 'script,style,noscript,template,input,textarea,select,option,iframe,svg,[hidden],[aria-hidden="true"],[contenteditable]';

  function visibleText(max) {
    const out = []; let len = 0;
    const w = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        const p = n.parentElement;
        if (!p || p.closest(SKIP) || (p.checkVisibility && !p.checkVisibility())) return NodeFilter.FILTER_REJECT;
        return n.nodeValue.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      },
    });
    while (len < max && w.nextNode()) {
      const t = w.currentNode.nodeValue.replace(/\s+/g, ' ').trim();
      out.push(t); len += t.length + 1;
    }
    return out.join(' ').slice(0, max);
  }
  function links(max) {
    const s = new Set();
    for (const a of document.querySelectorAll('a[href]')) {
      try {
        const u = new URL(a.href);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
        u.hash = '';
        if (u.toString().length <= 500) s.add(u.toString());
      } catch {}
      if (s.size >= max) break;
    }
    return [...s];
  }

  function banner(m) {
    document.getElementById('psx-host')?.remove();
    const host = document.createElement('div');
    host.id = 'psx-host';
    host.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647';
    const root = host.attachShadow({ mode: 'closed' });
    const st = document.createElement('style');
    st.textContent = `.b{font:13px/1.4 system-ui,sans-serif;background:#0b1020;color:#e2e8f0;border-bottom:3px solid ${m.color};padding:10px 14px;display:flex;gap:12px;align-items:center;box-shadow:0 2px 12px #0009}.t{flex:1}.t b{color:${m.color}}button{font:inherit;background:#1b2742;color:#e2e8f0;border:1px solid #243049;border-radius:6px;padding:5px 10px;cursor:pointer}button:hover{background:#243049}`;
    const bar = document.createElement('div'); bar.className = 'b';
    const t = document.createElement('div'); t.className = 't';
    const b = document.createElement('b'); b.textContent = `PhishShield X: ${m.label} (${m.score}/100). `;
    t.append(b, document.createTextNode([m.summary, m.action].filter(Boolean).join(' ')));
    bar.append(t);
    const btn = (label, fn) => { const x = document.createElement('button'); x.textContent = label; x.onclick = fn; bar.append(x); };
    if (m.report) btn('View report', () => window.open(m.report, '_blank', 'noopener'));
    if (m.level === 'HIGH' || m.level === 'CRITICAL') btn('Leave site', () => location.replace('about:blank'));
    btn('Dismiss', () => host.remove());
    root.append(st, bar);
    document.documentElement.append(host);
  }

  chrome.runtime.onMessage.addListener((m, sender) => {
    if (sender.id !== chrome.runtime.id) return;
    if (m.type === 'PSX_EXTRACT') {
      const u = new URL(location.href); u.hash = '';
      const priv = PRIVATE.has(location.hostname);
      return Promise.resolve({
        url: u.toString(), page_title: (document.title || '').slice(0, 200),
        page_text: priv ? '' : visibleText(m.maxText), links: priv ? [] : links(m.maxLinks),
      });
    }
    if (m.type === 'PSX_BANNER') banner(m);
  });
})();
