# PHISHSHIELD X – MASTER BACKEND & AI THREAT INTELLIGENCE

> **GRAVITON 2026 Hackathon | Problem Statement #2: PhishShield AI**  
> **Lead:** Member 1 – Backend, AI Intelligence & Database Lead  
> **Modules Integrated:** Chrome Extension (Member 2) & Next.js Dashboard / Scam Arena (Member 3)

---

## 1. PROJECT OVERVIEW

**PhishShield X** is an AI-powered phishing detection and adaptive scam intelligence platform. The backend is the **sole authoritative intelligence and risk-scoring engine** for the platform. Neither the browser extension nor the dashboard calculates risk scores independently.

### Key Capabilities:
- **URL Anatomy & Structural Inspection:** Identifies IP-based hosts, excessive subdomains, brand impersonation, high-abuse TLDs, punycode/IDN homograph attacks, and insecure protocol contexts.
- **Social-Engineering & Scam Detection:** Rules-based and lexical pattern matching for Fake KYC, urgent account suspension, OTP/PIN theft, reverse UPI scams, and fraudulent job offers.
- **Machine Learning Classification:** Lightweight Scikit-learn TF-IDF + Logistic Regression trained on representative phishing and legitimate communications.
- **Groq AI Integration (Optional & Resilient):** Semantic reasoning and structured explanation generation via LLaMA 3.3. Failure or rate-limiting of Groq never crashes the system.
- **Authoritative Central Risk Scoring Engine:** Mathematical point allocation bound by strict category caps (`url: 25`, `identity: 20`, `semantic: 25`, `behavior: 20`, `reputation: 10`) producing explainable scores (0–100) and risk classifications (`LOW`, `MODERATE`, `SUSPICIOUS`, `HIGH`, `CRITICAL`).
- **Persistent Storage in Neon PostgreSQL:** Authoritative scan history and granular evidence stored in Neon using SQLAlchemy 2.0, Psycopg 3, and Alembic migrations.

---

## 2. REPOSITORY & FILE OWNERSHIP

```
Graviton/
│
├── backend/                  <-- [Member 1 Exclusive Ownership]
│   ├── app/
│   │   ├── main.py           # FastAPI application entrypoint & CORS
│   │   ├── core/             # Settings (Pydantic), security & sanitization
│   │   ├── database/         # Neon PostgreSQL connection, session, models
│   │   ├── detection/        # URL analyzer, message analyzer, risk engine
│   │   ├── routes/           # /health, /api/v1/scan/*, /api/v1/scans/*
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   └── services/         # ML classifier, Groq AI, scan orchestrator
│   ├── alembic/              # Alembic migrations (uses DIRECT_URL)
│   ├── data/                 # Training dataset samples
│   ├── models/               # Saved ML model artifact (.joblib)
│   ├── tests/                # Automated pytest suite (20 core scenarios)
│   ├── alembic.ini           # Alembic configuration
│   ├── requirements.txt      # Python dependencies
│   └── .env.example          # Safe environment template
│
├── docs/
│   └── api-contract.md       <-- Authoritative API Specification for Members 2 & 3
│
├── .gitignore
└── README.md
```

> **Rules of Engagement:**
> - Member 1 owns `backend/`, `docs/api-contract.md`, `.gitignore`, and `README.md`.
> - Member 2 owns `extension/`.
> - Member 3 owns `frontend/`.

---

## 3. PREREQUISITES & INSTALLATION

### 3.1 Prerequisites
- **Python 3.11+** installed.
- **Git** installed.
- Free-tier **Neon PostgreSQL** project (`phishshield-x`).

### 3.2 Installation Steps (Windows / macOS / Linux)

1. **Clone the repository and switch to the backend feature branch:**
   ```bash
   git checkout feature/backend-engine
   ```

2. **Navigate to the backend directory:**
   ```bash
   cd backend
   ```

3. **Create and activate a Python virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

4. **Install all dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 4. ENVIRONMENT CONFIGURATION

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Edit `backend/.env` with your Neon PostgreSQL and Groq credentials:

```env
# Database Connection Strings (Neon PostgreSQL)
# Pooled connection string for application queries
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST-pooler.REGION.aws.neon.tech/phishshield?sslmode=require

# Direct connection string for Alembic schema migrations
DIRECT_URL=postgresql+psycopg://USER:PASSWORD@HOST.REGION.aws.neon.tech/phishshield?sslmode=require

# Groq AI Service (Optional - system falls back to local detection if empty)
PHISHSHIELD_GROQ_API_KEY=gsk_your_groq_api_key_here
PHISHSHIELD_GROQ_MODEL=llama-3.3-70b-versatile
PHISHSHIELD_AI_ENABLED=true

# Server Configuration
PHISHSHIELD_HOST=127.0.0.1
PHISHSHIELD_PORT=8000
PHISHSHIELD_DEBUG=false
```

---

## 5. DATABASE MIGRATIONS (ALEMBIC)

Alembic manages all schema changes in Neon PostgreSQL and connects via `DIRECT_URL`.

1. **Apply all migrations to Neon PostgreSQL:**
   ```bash
   alembic upgrade head
   ```

2. **To generate a new migration after model changes (if needed):**
   ```bash
   alembic revision --autogenerate -m "describe changes"
   ```

---

## 6. RUNNING THE BACKEND LOCALLY

Start the FastAPI development server with live reloading:
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Verification Endpoints:
- **Health Check:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Interactive Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 7. RUNNING AUTOMATED TESTS

The test suite validates URL detection, message scams, ML classification, Groq resilience, deterministic scoring caps, and all 20 required hackathon scenarios:

```bash
pytest -v tests/
```

To run with coverage reporting:
```bash
pytest --cov=app tests/
```

---

## 8. INTEGRATION GUIDE FOR TEAM MEMBERS

### For Member 2 (Chrome Extension):
- Backend base URL: `http://127.0.0.1:8000`
- Call `POST /api/v1/scan/url` with:
  ```json
  {
    "url": "https://suspicious-site.xyz/login",
    "page_title": "Page Title",
    "page_text": "Extracted visible text",
    "links": ["https://..."],
    "source": "extension"
  }
  ```
- Trigger caution/danger banner when `risk_level` is `SUSPICIOUS`, `HIGH`, or `CRITICAL`.
- Consult [`docs/api-contract.md`](file:///c:/Users/HP/OneDrive/2ND%20YEAR/Graviton/docs/api-contract.md) for full field definitions.

### For Member 3 (Next.js Dashboard & Scam Arena):
- Set `.env.local`: `NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL=http://127.0.0.1:8000`
- Query scan history: `GET /api/v1/scans?limit=20&offset=0`
- Query single report: `GET /api/v1/scans/{scan_id}`
- Interactive Message Scanner: `POST /api/v1/scan/message` with `source: "dashboard"`
- Consult [`docs/api-contract.md`](file:///c:/Users/HP/OneDrive/2ND%20YEAR/Graviton/docs/api-contract.md) for sample responses.
