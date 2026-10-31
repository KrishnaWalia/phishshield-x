# PHISHSHIELD X – AUTHORITATIVE API CONTRACT & INTEGRATION SPECIFICATION

**Author:** Member 1 (Backend Engineering Lead)  
**Target Audience:** Member 2 (Chrome Extension Developer) & Member 3 (Next.js Dashboard & Scam Arena Developer)  
**Version:** 1.0.0  
**Base URL:** `http://127.0.0.1:8000`

---

## 1. ARCHITECTURAL OVERVIEW & RULES

1. **Single Source of Truth:**
   The backend is the **sole authoritative intelligence and risk-scoring engine**.
   Neither the Chrome Extension nor the Next.js Dashboard should independently calculate, modify, or override the `risk_score` or `risk_level`.
2. **Persistence:**
   All scans and explainable findings are automatically persisted in **Neon PostgreSQL** under the `scans` and `scan_findings` tables.
   Clients must NOT connect directly to Neon PostgreSQL; all interactions occur through the REST endpoints below.
3. **Data Privacy & Security:**
   - The backend NEVER stores raw passwords, OTPs, PINs, card numbers, or full message bodies.
   - Any sensitive tokens are scrubbed using zero-trust sanitization before analysis.
   - Do NOT transmit sensitive form credentials to the backend.
4. **Resilient AI & Degradation:**
   Groq AI is an optional enhancement layer. If Groq is disabled, times out, or is rate-limited, the local rule-based heuristic and ML detection engines continue operating without disruption (`"engines": { "ai": false }`).

---

## 2. STANDARD SCORING & CLASSIFICATION SYSTEM

### 2.1 Category Scoring Caps (Maximum 100 Total)

| Finding Category | Description | Point Cap |
|:---|:---|:---:|
| `url` | Structural, lexical, domain, and protocol anomalies | **25 pts** |
| `identity` | Brand impersonation and typosquatting | **20 pts** |
| `semantic` | Social engineering, urgency, and threats | **25 pts** |
| `behavior` | Credential harvesting, reverse UPI, and redirects | **20 pts** |
| `reputation` | Domain randomness and suspicious TLDs | **10 pts** |
| **Total Maximum** | Aggregate across all categories | **100 pts** |

### 2.2 Authoritative Risk Level Thresholds

| Risk Score (0–100) | Risk Level | Meaning & Client Action |
|:---:|:---:|:---|
| **0 – 19** | `LOW` | Benign / Safe. Green indicator. |
| **20 – 39** | `MODERATE` | Minor anomalies observed. Informational warning / Blue. |
| **40 – 59** | `SUSPICIOUS` | Multiple suspicious signals. Caution warning / Yellow. |
| **60 – 79** | `HIGH` | Strong phishing indicators. Danger warning / Orange. |
| **80 – 100** | `CRITICAL` | Severe threat. Immediate blocking recommendation / Red. |

---

## 3. SHARED ENUM CONSTANTS

Use these exact string values across all modules (case-sensitive):

- **`source`:**
  - `"extension"`
  - `"dashboard"`
  - `"arena"`
- **`target_type`:**
  - `"url"`
  - `"message"`
- **`risk_level`:**
  - `"LOW"`
  - `"MODERATE"`
  - `"SUSPICIOUS"`
  - `"HIGH"`
  - `"CRITICAL"`
- **`finding.category`:**
  - `"url"`
  - `"identity"`
  - `"semantic"`
  - `"behavior"`
  - `"reputation"`
- **`finding.severity`:**
  - `"low"`
  - `"medium"`
  - `"high"`
  - `"critical"`

---

## 4. ENDPOINT SPECIFICATIONS

### 4.1 Health Check

Verifies server liveness.

- **Route:** `GET /health`
- **Method:** `GET`
- **Headers:** None required

#### Success Response (`200 OK`)
```json
{
  "status": "ok"
}
```

---

### 4.2 Scan URL

Evaluates a target URL, domain structure, optional page title, visible text, and anchor links.

- **Route:** `POST /api/v1/scan/url`
- **Method:** `POST`
- **Headers:** `Content-Type: application/json`

#### Request Payload
```json
{
  "url": "https://sbi-verify-kyc-update.xyz/login",
  "page_title": "State Bank of India - Verify KYC",
  "page_text": "Your bank account will be blocked within 24 hours. Complete KYC immediately to avoid suspension.",
  "links": [
    "https://sbi-verify-kyc-update.xyz/login",
    "https://sbi-verify-kyc-update.xyz/submit-otp"
  ],
  "source": "extension"
}
```

#### Constraints & Validation
- `url` *(string, required)*: Valid URL starting with `http://` or `https://` (max 2048 characters).
- `page_title` *(string, optional)*: Max 500 characters.
- `page_text` *(string, optional)*: Max 6000 characters.
- `links` *(array of strings, optional)*: Max 30 items.
- `source` *(string, required)*: Must be `"extension"`, `"dashboard"`, or `"arena"`.

#### Success Response (`200 OK`)
```json
{
  "scan_id": "psx_48b291a0c71e",
  "target_type": "url",
  "target": "https://sbi-verify-kyc-update.xyz/login",
  "risk_score": 88,
  "risk_level": "CRITICAL",
  "summary": "CRITICAL THREAT: Severe phishing indicators detected. Key risk: Brand impersonation detected (SBI).",
  "findings": [
    {
      "id": "identity_001",
      "category": "identity",
      "severity": "critical",
      "points": 20,
      "title": "Brand impersonation detected (SBI)",
      "evidence": "Brand 'sbi' appears in registered domain 'sbi-verify-kyc-update.xyz' which is not official",
      "explanation": "The URL references the brand 'Sbi' while hosted on an unauthorized domain. This is a primary indicator of a credential-harvesting phishing site."
    },
    {
      "id": "url_001",
      "category": "url",
      "severity": "medium",
      "points": 12,
      "title": "High-risk TLD detected",
      "evidence": "Domain uses high-abuse top-level domain '.xyz'",
      "explanation": "The '.xyz' extension is frequently abused in automated disposable phishing campaigns due to negligible registration costs."
    },
    {
      "id": "semantic_001",
      "category": "semantic",
      "severity": "high",
      "points": 18,
      "title": "Fake KYC urgency in page text",
      "evidence": "Observed in visible page text: '...verify your kyc immediately...'",
      "explanation": "Phishing pages employ acute psychological urgency to pressure users into surrendering credentials."
    },
    {
      "id": "behavior_001",
      "category": "behavior",
      "severity": "high",
      "points": 15,
      "title": "Multiple auth/financial action keywords in path",
      "evidence": "Detected keywords: login, kyc",
      "explanation": "The URL path contains multiple high-value targets such as login, KYC, and verification, typical of phishing lures designed to steal account credentials."
    }
  ],
  "recommended_action": "DO NOT interact with this website. Do not enter credentials, OTPs, or payment details. Close the browser tab immediately.",
  "analyzed_at": "2026-10-31T12:00:00.000000+00:00",
  "engines": {
    "rules": true,
    "ml": true,
    "ai": true
  }
}
```

---

### 4.3 Scan Message

Evaluates an SMS, WhatsApp message, email excerpt, or job offer for social-engineering triggers.

- **Route:** `POST /api/v1/scan/message`
- **Method:** `POST`
- **Headers:** `Content-Type: application/json`

#### Request Payload
```json
{
  "text": "Congratulations! You have won Rs 5000 cashback. Enter your UPI PIN to claim money into your account.",
  "source": "dashboard"
}
```

#### Constraints & Validation
- `text` *(string, required)*: Non-blank message body (1 to 10,000 characters).
- `source` *(string, required)*: Must be `"extension"`, `"dashboard"`, or `"arena"`.

#### Success Response (`200 OK`)
```json
{
  "scan_id": "psx_9f20e481b372",
  "target_type": "message",
  "target": "Message: Congratulations! You have won Rs 5000 cashback... (105 chars)",
  "risk_score": 60,
  "risk_level": "HIGH",
  "summary": "HIGH RISK: Detected 3 suspicious indicator(s) including 2 severe signals.",
  "findings": [
    {
      "id": "msg_001",
      "category": "behavior",
      "severity": "critical",
      "points": 20,
      "title": "Reverse UPI Scam (PIN Required to Receive)",
      "evidence": "Matched trigger 'enter your upi pin to claim': ...Congratulations! You have won Rs 5000 cashback. Enter your UPI PIN to claim money into your accou...",
      "explanation": "Under the UPI protocol, entering a PIN is ONLY required to deduct money from your account, NEVER to receive funds. This is a predatory fraud."
    },
    {
      "id": "msg_002",
      "category": "semantic",
      "severity": "medium",
      "points": 15,
      "title": "Unsolicited Reward or Cashback Lure",
      "evidence": "Matched trigger 'cashback of Rs': ...Congratulations! You have won Rs 5000 cashback. Enter your UPI PIN to claim money into your accou...",
      "explanation": "Promises of unearned cash rewards or prizes are used to entice victims into initiating payment requests or surrendering personal details."
    }
  ],
  "recommended_action": "Do not click any embedded links or follow payment instructions. Contact the institution via verified official numbers.",
  "analyzed_at": "2026-10-31T12:00:00.000000+00:00",
  "engines": {
    "rules": true,
    "ml": true,
    "ai": false
  }
}
```

---

### 4.4 Scan History

Returns previously analyzed scans from Neon PostgreSQL with pagination.

- **Route:** `GET /api/v1/scans`
- **Method:** `GET`
- **Query Parameters:**
  - `limit` *(integer, optional, default: 20, min: 1, max: 100)*
  - `offset` *(integer, optional, default: 0, min: 0)*

#### Success Response (`200 OK`)
```json
{
  "total": 42,
  "limit": 20,
  "offset": 0,
  "scans": [
    {
      "scan_id": "psx_48b291a0c71e",
      "target_type": "url",
      "target": "https://sbi-verify-kyc-update.xyz/login",
      "risk_score": 88,
      "risk_level": "CRITICAL",
      "summary": "CRITICAL THREAT: Severe phishing indicators detected. Key risk: Brand impersonation detected (SBI).",
      "recommended_action": "DO NOT interact with this website. Do not enter credentials, OTPs, or payment details. Close the browser tab immediately.",
      "source": "extension",
      "analyzed_at": "2026-10-31T12:00:00.000000+00:00",
      "findings_count": 4
    }
  ]
}
```

---

### 4.5 Individual Scan Details

Retrieves the complete report and all granular findings for a given public `scan_id`.

- **Route:** `GET /api/v1/scans/{scan_id}`
- **Method:** `GET`
- **Path Parameter:** `scan_id` (e.g. `psx_48b291a0c71e`)

#### Success Response (`200 OK`)
Returns the standard `ScanResponse` JSON identical to Section 4.2 / 4.3.

#### Not Found Response (`404 Not Found`)
```json
{
  "detail": "Scan with ID 'psx_nonexistent_999' was not found."
}
```

---

## 5. STANDARD ERROR RESPONSES

### Validation Error (`422 Unprocessable Entity`)
Returned when payload fails validation (e.g. invalid URL scheme, missing fields, excessive length, invalid source enum).
```json
{
  "error": "Validation Error",
  "message": "The submitted payload failed validation constraints.",
  "details": [
    "body -> url: URL must start with http:// or https://",
    "body -> source: Input should be 'extension', 'dashboard' or 'arena'"
  ]
}
```

### Bad Request (`400 Bad Request`)
```json
{
  "detail": "Invalid URL scheme 'ftp'. Only http and https schemes are permitted."
}
```

### Internal Server Error (`500 Internal Server Error`)
```json
{
  "error": "Internal Server Error",
  "message": "An unexpected error occurred while processing the request."
}
```

---

## 6. CLIENT INTEGRATION GUIDE

### For Member 2 (Chrome Extension):
1. **Background Service Worker:**
   ```javascript
   const BACKEND_URL = "http://127.0.0.1:8000";

   async function scanCurrentUrl(url, pageTitle, pageText, links) {
     const response = await fetch(`${BACKEND_URL}/api/v1/scan/url`, {
       method: "POST",
       headers: { "Content-Type": "application/json" },
       body: JSON.stringify({
         url: url,
         page_title: pageTitle || null,
         page_text: (pageText || "").slice(0, 5000),
         links: (links || []).slice(0, 30),
         source: "extension"
       })
     });
     return await response.json();
   }
   ```
2. **Warning Banner Trigger:**
   - If `risk_level === "CRITICAL"` or `risk_level === "HIGH"`, trigger warning banner / overlay.
   - Display `summary`, `recommended_action`, and provide a link to the dashboard: `http://localhost:3000/report/${scan_id}`.

### For Member 3 (Next.js Dashboard & Scam Arena):
1. **Environment Configuration (`frontend/.env.local`):**
   ```env
   NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL=http://127.0.0.1:8000
   ```
2. **Dashboard Fetching:**
   - Scan URL: `POST ${NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL}/api/v1/scan/url` with `source: "dashboard"`
   - Scan Message: `POST ${NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL}/api/v1/scan/message` with `source: "dashboard"`
   - History List: `GET ${NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL}/api/v1/scans?limit=20&offset=0`
   - Single Report: `GET ${NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL}/api/v1/scans/${scanId}`
