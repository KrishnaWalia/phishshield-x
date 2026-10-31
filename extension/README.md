# PhishShield X — Browser Extension (Member 2)

Chrome MV3, vanilla JS. Branch: `feature/browser-extension`. Owns `extension/` only.
The backend is the sole authority for `risk_score`/`risk_level`; the extension only displays them.

## Install (local)
1. Start the backend: `http://127.0.0.1:8000` (check `GET /health` returns `{"status":"ok"}`).
2. Chrome → `chrome://extensions` → Developer mode → **Load unpacked** → select `extension/`.
3. Open any http(s) page → click the PhishShield X icon → **Scan this page**.
4. Optional: popup → **Enable automatic scanning on all sites** (optional host permission, user-granted).

## Configuration (`config.js`)
`API_BASE_URL` (= `PHISHSHIELD_EXTENSION_API_BASE_URL`; also update `host_permissions` in `manifest.json` when changed).
PROVISIONAL, awaiting Member 3: `DASHBOARD_URL`, `REPORT_PATH`, `ARENA_PATH`, `DEMO_THREATS`.

## Behavior
- LOW/MODERATE: popup + badge only, no interruption.
- SUSPICIOUS/HIGH/CRITICAL: dismissible in-page banner (needs host access to the site).
- Full-page `warning.html` (with "Return to Scam Arena" and "continue anyway"): HIGH/CRITICAL on `DEMO_THREATS` URLs only.
- Right-click selected text → "Scan selected text with PhishShield X" (only explicit message scan path).
- Backend down/timeout/429/5xx/invalid JSON → explicit "not assessed" state + Retry. Never shown as safe or malicious.
- No `declarativeNetRequest` rules: nothing is blocked at the network layer, so a backend outage cannot leave the browser stuck.

## Privacy
Sent: URL (no hash), title (200 chars), visible text (5000 chars), up to 50 links. Skipped: inputs, textareas, selects, contenteditable, hidden elements; text/links skipped entirely on WhatsApp Web, Gmail, Outlook, Telegram Web, Messenger, Discord. Links may contain query strings. Scan cache lives in `storage.session` (cleared on browser close).

## Needs from teammates
- Member 3: final Arena demo origins/paths, report route (`/scans/{scan_id}`?), arena route, and how Arena detects the return.
- Member 1: confirm `docs/api-contract.md` matches the master prompt; max `page_text`/`links` sizes; whether `/health` and scan endpoints allow requests from the extension.

## Test checklist
Benign site (LOW) · suspicious URL · 3 Arena scenarios · backend stopped · timeout (point `API_BASE_URL` at a black-hole IP) · malformed JSON · `chrome://extensions` (unsupported) · permission not granted (URL-only note) · password/OTP fields not in request (inspect backend logs / DevTools Network on the service worker).
