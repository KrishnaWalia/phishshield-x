# PhishShield X

**An AI-powered browser security companion that detects phishing threats, explains why they are dangerous, and teaches people to recognise social engineering.**

Built for **GRAVITON 2026**, Problem Statement #2: *PhishShield AI*.

> PhishShield X reports risk indicators with evidence. It does **not** guarantee protection against phishing, and its scores are hackathon design choices, not measured probabilities of maliciousness.

---

## Table of contents

1. [What it does](#what-it-does)
2. [Architecture](#architecture)
3. [Tech stack](#tech-stack)
4. [Repository structure](#repository-structure)
5. [Quick start (local)](#quick-start-local)
6. [Environment variables](#environment-variables)
7. [API reference](#api-reference)
8. [Detection and scoring](#detection-and-scoring)
9. [Browser extension](#browser-extension)
10. [Scam Arena](#scam-arena)
11. [Privacy and security](#privacy-and-security)
12. [Testing](#testing)
13. [Deployment](#deployment)
14. [Troubleshooting](#troubleshooting)
15. [Known limitations](#known-limitations)
16. [Team and ownership](#team-and-ownership)

---

## What it does

| Component | Purpose |
|---|---|
| **Browser extension** | Scans the page you are on, shows a risk score and the reasons behind it, and warns you before you interact with a dangerous site. |
| **Security dashboard** | Scan any URL or pasted message, browse scan history, and open detailed evidence reports. |
| **Scam Arena** | Three interactive, fictional phishing scenarios (fake bank KYC, fake UPI reward, fake job offer) that train users to spot scams. |
| **Backend engine** | The single authority for risk scoring: rules, a small ML classifier, and optional Groq AI, with every scan stored in Neon PostgreSQL. |

Core principle: **the backend is the only place a risk score is calculated.** The extension and the dashboard display what the backend returns.

---

## Architecture

```
                 ┌───────────────────────┐
                 │   Chrome extension    │  page URL, title, visible text, links
                 │   (Manifest V3)       │ ─────────────────┐
                 └───────────────────────┘                  │
                                                            ▼
┌───────────────────────┐   REST (JSON)   ┌──────────────────────────────────┐
│  Next.js dashboard    │ ──────────────► │  FastAPI backend                 │
│  + Scam Arena         │ ◄────────────── │   rules → ML → Groq (optional)   │
└───────────────────────┘                 │   risk engine (caps + thresholds)│
                                          └───────────────┬──────────────────┘
                                                          │ SQLAlchemy 2.0 / Psycopg 3
                                                          ▼
                                                 Neon PostgreSQL
```

- The extension and dashboard **never connect to the database directly**.
- The Groq API key lives **only on the backend**.
- If Groq or the ML model is unavailable, scoring still works from rules.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy 2.0, Psycopg 3, Alembic |
| Database | Neon PostgreSQL |
| Detection | Rule-based analyzers, scikit-learn (TF-IDF + Logistic Regression), `tldextract` |
| Optional AI | Groq API (structured JSON, validated with Pydantic) |
| Frontend | Next.js 14, React 18, TypeScript, Tailwind CSS, Recharts |
| Extension | Chrome Manifest V3, vanilla JavaScript, HTML, CSS |

---

## Repository structure

```
phishshield-x/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI entrypoint, CORS
│   │   ├── core/              # settings, sanitisation
│   │   ├── database/          # connection, session, models
│   │   ├── detection/         # url_analyzer, message_analyzer, risk_engine
│   │   ├── routes/            # /health, /api/v1/scan/*, /api/v1/scans/*
│   │   ├── schemas/           # Pydantic request/response models
│   │   └── services/          # ML classifier, Groq analyzer, scan orchestration
│   ├── alembic/               # migrations
│   ├── data/                  # ML training samples
│   ├── tests/                 # pytest suite
│   ├── requirements.txt
│   └── .env.example
├── extension/
│   ├── manifest.json
│   ├── config.js              # API/dashboard URLs, Arena mapping, limits
│   ├── background.js          # service worker: scans, caching, warnings
│   ├── content.js             # page text/link extraction, in-page banner
│   ├── popup.html / popup.js
│   ├── warning.html / warning.js
│   └── styles.css
├── frontend/
│   ├── app/                   # dashboard, scanners, history, reports, arena
│   ├── components/
│   ├── lib/                   # API client, Arena scenario data
│   └── public/
├── docs/
│   └── api-contract.md        # shared API contract
├── .gitignore
└── README.md
```

---

## Quick start (local)

### Prerequisites

- Python 3.12 (the pinned `scikit-learn==1.9.1` is verified on 3.12)
- Node.js 18+ and npm
- A free [Neon](https://neon.tech) PostgreSQL project
- Optional: a free [Groq](https://console.groq.com) API key for AI analysis
- Desktop Chrome, Edge or Brave for the extension

### 1. Backend

```bash
cd backend
python -m venv .venv
# Windows:   .venv\Scripts\activate
# Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
```

Edit `backend/.env` (see [Environment variables](#environment-variables)), then:

```bash
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Check it: <http://127.0.0.1:8000/health> returns `{"status":"ok"}`. Interactive docs: <http://127.0.0.1:8000/docs>.

### 2. Frontend

```bash
cd frontend
npm install
cp .env.example .env.local  # Windows: copy .env.example .env.local
npm run dev
```

Open <http://localhost:3000>. Use exactly `localhost:3000` or `127.0.0.1:3000`; those are the origins the backend allows by default.

### 3. Browser extension

1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Click the PhishShield X icon, then **Enable automatic scanning on all sites** (optional, one-time).
5. After editing any extension file, click the reload icon on its card.

### 4. Verify the full flow

1. Dashboard → **URL scanner**: scan a URL and open the report.
2. Dashboard → **Scan history**: the scan appears (proves Neon persistence).
3. Extension popup on any website → **Scan this page**.
4. Dashboard → **Scam Arena**: open a scenario and watch the extension warn.

---

## Environment variables

### Backend (`backend/.env`)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Neon **pooled** connection string (`postgresql+psycopg://...`), used for normal queries. |
| `DIRECT_URL` | Neon **direct** connection string, used by Alembic migrations. |
| `PHISHSHIELD_GROQ_API_KEY` | Groq API key. Backend only. Never commit it. |
| `PHISHSHIELD_GROQ_MODEL` | A model available on your Groq account, e.g. `openai/gpt-oss-120b`. The default in `.env.example` may not be available on every account, so check your Groq console. |
| `PHISHSHIELD_AI_ENABLED` | `true` / `false`. Set `false` to run on rules and ML only. |
| `PHISHSHIELD_HOST`, `PHISHSHIELD_PORT`, `PHISHSHIELD_DEBUG` | Server settings. |
| `CORS_ORIGINS` | Optional. JSON list of allowed origins, e.g. `["https://your-app.vercel.app","http://localhost:3000"]`. |

### Frontend (`frontend/.env.local`)

| Variable | Purpose |
|---|---|
| `NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL` | Backend address, e.g. `http://127.0.0.1:8000`. |

### Extension (`extension/config.js`)

Browser extensions have no `.env`, so configuration lives in `config.js`:

| Setting | Purpose |
|---|---|
| `API_BASE_URL` | Backend address (equivalent of `PHISHSHIELD_EXTENSION_API_BASE_URL`). Also list it in `host_permissions` in `manifest.json`. |
| `DASHBOARD_URL`, `REPORT_PATH`, `ARENA_PATH` | Where report and Arena links point. |
| `DEMO_THREATS` | Origins and path prefixes of Scam Arena pages that get the full-page warning. |
| `ARENA_SCENARIOS` | Maps each Arena slug to its fictional URL, so the backend scans that instead of `localhost`. |
| `REQUEST_TIMEOUT_MS`, `CACHE_TTL_MS`, `MAX_TEXT_CHARS`, `MAX_LINKS` | Timeouts, caching and payload limits. |

Never commit real secrets. `.env` files are git-ignored.

---

## API reference

The shared contract is in `docs/api-contract.md`. All property names use `snake_case`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns `{"status":"ok"}`. |
| `POST` | `/api/v1/scan/url` | Scan a URL (optionally with page title, text and links). |
| `POST` | `/api/v1/scan/message` | Scan a pasted message. |
| `GET` | `/api/v1/scans?limit=20&offset=0` | Scan history (`limit` 1–100). |
| `GET` | `/api/v1/scans/{scan_id}` | Full report for one scan. |

### Request: URL scan

```json
{
  "url": "https://example.com",
  "page_title": "Example website",
  "page_text": "Visible text extracted from the page",
  "links": ["https://example.com/login"],
  "source": "extension"
}
```

Limits: `page_title` ≤ 500 characters, `page_text` ≤ 6000 characters, `links` ≤ **30** items. Sending more than 30 links returns a validation error.

### Request: message scan

```json
{ "text": "Your account will be suspended. Verify your KYC immediately.", "source": "dashboard" }
```

`source` is one of `extension`, `dashboard`, `arena`.

### Response (both scan types)

```json
{
  "scan_id": "psx_123456",
  "target_type": "url",
  "target": "https://example.com",
  "risk_score": 87,
  "risk_level": "CRITICAL",
  "summary": "Multiple phishing indicators detected.",
  "findings": [
    {
      "id": "url_001",
      "category": "url",
      "severity": "high",
      "points": 20,
      "title": "Suspicious domain structure",
      "evidence": "Observed URL evidence",
      "explanation": "The domain contains suspicious characteristics."
    }
  ],
  "recommended_action": "Avoid interacting with this website.",
  "analyzed_at": "2026-10-31T10:30:00Z",
  "engines": { "rules": true, "ml": true, "ai": true }
}
```

- Finding `category`: `url`, `identity`, `semantic`, `behavior`, `reputation`
- Finding `severity`: `low`, `medium`, `high`, `critical`
- `engines.ai` is `false` when Groq is disabled or unavailable; scoring still completes.

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan/message \
  -H "Content-Type: application/json" \
  -d '{"text":"Verify your KYC now or your account will be blocked","source":"dashboard"}'
```

---

## Detection and scoring

Three layers feed one scoring engine:

1. **Rules.** URL analysis (IP hosts, subdomain depth, brand-like domains, risky TLDs, punycode, unusual paths, HTTP vs HTTPS as context only) and message analysis (urgency, fake KYC, OTP/PIN requests, reverse-UPI scams, cashback rewards, job registration fees, suspicious links).
2. **Machine learning.** TF-IDF + Logistic Regression trained from `backend/data/training_samples.json`. The model is trained automatically on first start if no saved model exists.
3. **Groq AI (optional).** Produces structured, validated findings and explanations. It can never change the final score, and findings with unsupported structure are rejected.

### Risk engine

The backend validates and de-duplicates findings, enforces per-category caps, sums the points, and assigns the level.

| Category | Max points |
|---|---:|
| URL | 25 |
| Identity | 20 |
| Semantic | 25 |
| Behavior | 20 |
| Reputation | 10 |
| **Total** | **100** |

| Score | Risk level |
|---|---|
| 0–19 | LOW |
| 20–39 | MODERATE |
| 40–59 | SUSPICIOUS |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

These caps and thresholds are initial design choices. They have **not** been statistically validated.

The backend never fetches submitted URLs, which avoids server-side request forgery and downloading untrusted content.

---

## Browser extension

Chrome Manifest V3, no framework, no build step.

### What it does

- Reads the current page's URL, title, visible text and links, and sends them to the backend.
- Shows the backend's `risk_score`, `risk_level`, summary and findings in the popup, with a coloured badge on the toolbar icon.
- Shows a dismissible in-page banner for SUSPICIOUS, HIGH and CRITICAL results.
- On **Scam Arena** pages only, shows a full-page warning for HIGH/CRITICAL results with a safe way back to the Arena.
- Offers **right-click → Scan selected text with PhishShield X** for explicit message scanning.
- Handles backend offline, timeout, HTTP 429/5xx, malformed responses and unsupported pages. A failed scan is never displayed as "safe" or "malicious".

### Risk-level behaviour

| Level | Behaviour |
|---|---|
| LOW | Safe status, no interruption |
| MODERATE | Popup caution only |
| SUSPICIOUS | Caution banner with indicators |
| HIGH | Prominent banner, recommends leaving |
| CRITICAL | Strong banner; full-page warning on Arena demo pages |

### Permissions

- `activeTab`, `scripting`, `storage`, `contextMenus`.
- Host access only to the backend and local dashboard by default.
- All-sites scanning is an **optional permission** the user grants from the popup.
- No `declarativeNetRequest` rules are used, so nothing is blocked at the network layer and a backend outage cannot lock the browser.

### What it collects, and what it never does

Sent: URL (no `#fragment`), title (200 chars), visible text (up to 5000 chars), and up to 30 links.

Never collected: password, OTP, card or PIN fields, any form input, textareas, selects, editable or hidden content. On WhatsApp Web, Gmail, Outlook, Telegram Web, Messenger and Discord, only the URL is sent. The extension does not submit forms or start transactions.

Scan results are cached for 5 minutes in `chrome.storage.session`, which is cleared when the browser closes.

### Installing for other people

The Chrome Web Store charges a registration fee and reviews take time, so this project is shared as an unpacked extension: download the zip, unzip it, then **Load unpacked** in Developer mode. Chrome cannot load a zip directly and cannot install from a website with one click. If the backend and dashboard are hosted, set the hosted addresses in `config.js` and `manifest.json` first.

---

## Scam Arena

Three fictional training scenarios, shown in a simulated browser frame inside the dashboard at `/arena/<slug>`:

| Slug | Scenario |
|---|---|
| `banking-kyc` | Fake bank KYC update with account-suspension pressure |
| `upi-reward` | Fake cashback reward that asks for a payment |
| `fake-job` | Fake job offer with a registration fee |

Players read the page, flag suspicious indicators, make decisions, and get scored with explanations and learning points. All brands and domains are fictional, nothing is collected, and no payment is ever made. Because the Arena runs inside the dashboard, the extension maps each slug to its fictional URL (`ARENA_SCENARIOS` in `extension/config.js`); update the map if a scenario URL changes.

---

## Privacy and security

- Passwords, OTPs, UPI PINs, card details and other credentials are never collected or stored.
- Raw page content and raw messages are not stored; scans save only a safe target descriptor, score, findings and evidence.
- Secrets (database URLs, Groq key) live only in the backend environment. `.env` is git-ignored.
- Inputs are validated with Pydantic and size-limited; CORS is restricted to configured origins.
- Neon is accessed only by the backend.
- Scanned page text is sent to the backend you configure. Do not scan pages containing private information when using a shared or hosted backend.

---

## Testing

### Backend

```bash
cd backend
pip install pytest   # if not already installed
PHISHSHIELD_AI_ENABLED=false pytest -q      # Windows: set PHISHSHIELD_AI_ENABLED=false first
```

The suite covers the URL analyzer, message analyzer, risk engine, AI analyzer fallbacks, API endpoints and end-to-end scenarios, using an in-memory SQLite database (no Neon needed).

### Frontend

```bash
cd frontend
npm run build
```

### Extension manual checklist

- Benign site → LOW, no warning
- Suspicious URL → warning and findings
- Each Arena scenario → warning, working report link, "Return to Scam Arena"
- Backend stopped → "Backend unavailable" and Retry, never "safe"
- `chrome://extensions` → "Page not supported"
- Right-click selected text → message result tab
- Type a fake password in a field, scan, and confirm it is **not** in the request (service worker → Network tab)

### Guidance on test data

Use fictional or obviously fake domains. Never visit real phishing sites to test.

---

## Deployment

Local use is the primary supported path. Free-tier hosting is possible:

| Part | Suggested host | Notes |
|---|---|---|
| Database | Neon | Free tier pauses when idle; the first request after a pause can be slow. |
| Backend | Render (free web service) | Root `backend`, build `pip install -r requirements.txt`, start `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Set `PYTHON_VERSION` to a version your pinned dependencies support. Free instances sleep after inactivity and take roughly a minute to wake. |
| Frontend | Vercel | Root `frontend`; set `NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL`. |

After deploying: add the frontend origin to the backend `CORS_ORIGINS`, then update `API_BASE_URL`, `DASHBOARD_URL`, the `DEMO_THREATS` origin and `host_permissions` in the extension. Free tiers have rate and usage limits, so do not assume unlimited capacity.

---

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Popup says **Backend unavailable** | Backend is not running on the address in `config.js`. Open `/health` in a browser tab; reload the extension after edits. |
| Every extension scan fails | The request exceeded API limits, e.g. more than 30 links. Keep `MAX_LINKS` ≤ 30. |
| `engines.ai` is always `false` | Groq key or model is wrong/unavailable, or the response was cut off. Check `PHISHSHIELD_GROQ_MODEL` against your Groq console and read the backend log. Scans still work without AI. |
| Arena warning never appears | `DEMO_THREATS` origin does not match the dashboard address, or the backend scored below HIGH. |
| Popup says **Limited scan** | The site's origin was not granted host access. Click **Enable automatic scanning on all sites**. |
| `alembic upgrade head` fails | Check `DIRECT_URL`; the Neon database may be waking up, so retry. |
| Dashboard shows a network/CORS error | The frontend origin is missing from `CORS_ORIGINS`, or `NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL` is wrong. |
| A message scan returns "unexpected error" | Read the backend terminal for the logged traceback; try with `PHISHSHIELD_AI_ENABLED=false` to isolate the AI layer. |

---

## Known limitations

- **No measured accuracy.** The ML model is trained on a very small seed dataset (30 samples) and no formal evaluation has been run. Do not quote detection rates.
- **Heuristic rules.** Pattern-based message rules can miss paraphrased scams and occasionally flag legitimate messages. Single-signal scams often score MODERATE rather than SUSPICIOUS.
- **Single-page apps.** The extension scans on page load; URL changes without a reload may not trigger a new scan.
- **Unpacked extension.** Installation requires Developer mode and desktop Chrome, Edge or Brave.
- **Extension scope.** It cannot intercept payments or inspect banking apps, and does not interfere with real banking sites.
- **Free-tier services.** Neon, Groq and any free host can pause, rate-limit or change terms without notice.
- **English-centric.** Detection patterns focus on English with some Indian-English phrasing; coverage of other languages is limited.

---

## Team and ownership

| Member | Module | Directory | Branch |
|---|---|---|---|
| Member 1 | Backend, detection engine, AI, database | `backend/`, `docs/api-contract.md` | `feature/backend-engine` |
| Member 2 | Browser extension | `extension/` | `feature/browser-extension` |
| Member 3 | Dashboard and Scam Arena | `frontend/` | `feature/frontend-arena` |

Cross-module rule: `docs/api-contract.md` is the single source of truth. Propose changes to the owner, update the contract, then update every affected module. Never commit `.env` files or API keys.
