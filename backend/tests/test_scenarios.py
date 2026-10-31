"""PhishShield X - 20 Core Required Hackathon Test Scenarios

Directly validates all 20 required scenarios outlined in Section 14:
1. Legitimate website
2. Suspicious website
3. Fake banking KYC message
4. Fake UPI reward message
5. Fake job offer
6. Benign payment-related message
7. Empty input
8. Invalid URL
9. Invalid source
10. Excessive page text
11. Excessive link count
12. AI API unavailable
13. Invalid AI JSON
14. Duplicate findings
15. Category scoring caps
16. Total score cap
17. Correct risk classification
18. Database connection failure
19. Scan persistence
20. Scan history retrieval
"""

from unittest.mock import MagicMock
from app.detection.url_analyzer import analyze_url
from app.detection.message_analyzer import analyze_message_rules
from app.detection.risk_engine import (
    calculate_risk_assessment,
    compute_risk_level,
    deduplicate_findings,
    CATEGORY_CAPS,
)
from app.schemas.findings import ScanFindingResponse
from app.services.ai_analyzer import GroqAIService
from app.services.scan_service import ScanService
from app.schemas.scan import MessageScanRequest, ScanSource


# 1. Legitimate website
def test_scenario_01_legitimate_website(client):
    resp = client.post(
        "/api/v1/scan/url",
        json={"url": "https://www.google.com", "source": "dashboard"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_level"] == "LOW"
    assert resp.json()["risk_score"] < 20


# 2. Suspicious website
def test_scenario_02_suspicious_website(client):
    resp = client.post(
        "/api/v1/scan/url",
        json={
            "url": "http://192.168.1.1/paypal.com/verify-kyc-account.xyz",
            "source": "extension",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] >= 40
    assert data["risk_level"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]


# 3. Fake banking KYC message
def test_scenario_03_fake_banking_kyc_message(client):
    resp = client.post(
        "/api/v1/scan/message",
        json={
            "text": "Dear customer, your SBI account will be blocked today. Complete KYC immediately at http://sbi-update.net",
            "source": "dashboard",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert any("KYC" in f["title"] for f in data["findings"])
    assert data["risk_score"] >= 40


# 4. Fake UPI reward message
def test_scenario_04_fake_upi_reward_message(client):
    resp = client.post(
        "/api/v1/scan/message",
        json={
            "text": "Congratulations! You have won Rs 5000 cashback. Enter your UPI PIN to receive money in bank account.",
            "source": "arena",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert any("UPI" in f["title"] or "Reward" in f["title"] for f in data["findings"])


# 5. Fake job offer
def test_scenario_05_fake_job_offer(client):
    resp = client.post(
        "/api/v1/scan/message",
        json={
            "text": "Earn Rs 5000 daily with part time work from home. Just like YouTube videos. Registration fee Rs 499 only.",
            "source": "dashboard",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert any("Job" in f["title"] for f in data["findings"])


# 6. Benign payment-related message
def test_scenario_06_benign_payment_message(client):
    resp = client.post(
        "/api/v1/scan/message",
        json={
            "text": "Your monthly electricity bill of Rs 1,420 for consumer 59281 was paid successfully. HDFC Bank.",
            "source": "dashboard",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] < 20


# 7. Empty input
def test_scenario_07_empty_input(client):
    resp = client.post("/api/v1/scan/message", json={"text": "   ", "source": "dashboard"})
    assert resp.status_code == 422


# 8. Invalid URL
def test_scenario_08_invalid_url(client):
    resp = client.post("/api/v1/scan/url", json={"url": "ftp://not-allowed.com", "source": "extension"})
    assert resp.status_code == 422


# 9. Invalid source
def test_scenario_09_invalid_source(client):
    resp = client.post("/api/v1/scan/message", json={"text": "Hello", "source": "unauthorized_origin"})
    assert resp.status_code == 422


# 10. Excessive page text
def test_scenario_10_excessive_page_text(client):
    resp = client.post(
        "/api/v1/scan/url",
        json={"url": "https://example.com", "page_text": "X" * 6005, "source": "extension"},
    )
    assert resp.status_code == 422


# 11. Excessive link count
def test_scenario_11_excessive_link_count(client):
    resp = client.post(
        "/api/v1/scan/url",
        json={
            "url": "https://example.com",
            "links": [f"https://example.com/{i}" for i in range(31)],
            "source": "extension",
        },
    )
    assert resp.status_code == 422


# 12. AI API unavailable
def test_scenario_12_ai_api_unavailable():
    service = GroqAIService()
    service.enabled = False
    service.api_key = None
    success, findings = service.analyze_content("Urgent KYC notice")
    assert success is False
    assert findings == []


# 13. Invalid AI JSON
def test_scenario_13_invalid_ai_json():
    service = GroqAIService()
    service.enabled = True
    service.api_key = "test_key"
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "{ malformed json..."
    mock_client.chat.completions.create.return_value.choices = [mock_choice]
    service._client = mock_client
    success, findings = service.analyze_content("Urgent KYC notice")
    assert success is False
    assert findings == []


# 14. Duplicate findings
def test_scenario_14_duplicate_findings():
    f1 = ScanFindingResponse(
        id="1", category="url", severity="high", points=15, title="Suspicious domain", evidence="ev", explanation="ex"
    )
    f2 = ScanFindingResponse(
        id="2", category="url", severity="medium", points=10, title="Suspicious domain", evidence="ev", explanation="ex"
    )
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    assert deduped[0].points == 15


# 15. Category scoring caps
def test_scenario_15_category_scoring_caps():
    # URL cap is 25
    findings = [
        ScanFindingResponse(
            id=f"u_{i}", category="url", severity="high", points=20, title=f"URL Issue {i}", evidence="ev", explanation="ex"
        )
        for i in range(3)
    ]
    score, level, _, _, _ = calculate_risk_assessment(findings, "url")
    assert score == CATEGORY_CAPS["url"]
    assert score == 25


# 16. Total score cap
def test_scenario_16_total_score_cap():
    findings = []
    for cat in ["url", "identity", "semantic", "behavior", "reputation"]:
        findings.append(
            ScanFindingResponse(
                id=f"c_{cat}", category=cat, severity="critical", points=50, title=f"Signal {cat}", evidence="ev", explanation="ex"
            )
        )
    score, _, _, _, _ = calculate_risk_assessment(findings, "message")
    assert score == 100


# 17. Correct risk classification
def test_scenario_17_correct_risk_classification():
    assert compute_risk_level(15) == "LOW"
    assert compute_risk_level(25) == "MODERATE"
    assert compute_risk_level(50) == "SUSPICIOUS"
    assert compute_risk_level(70) == "HIGH"
    assert compute_risk_level(95) == "CRITICAL"


# 18. Database connection failure
def test_scenario_18_database_connection_failure():
    """Even if database write fails, scanning service returns the valid scan result."""
    mock_bad_db = MagicMock()
    mock_bad_db.commit.side_effect = Exception("DB connection dropped")

    req = MessageScanRequest(
        text="Your account will be suspended. Verify your KYC immediately.",
        source=ScanSource.DASHBOARD,
    )
    # Must not raise an unhandled crash
    result = ScanService.scan_message(req, db=mock_bad_db)
    assert result.scan_id.startswith("psx_")
    assert result.risk_score >= 35


# 19. Scan persistence
def test_scenario_19_scan_persistence(client, db_session):
    resp = client.post(
        "/api/v1/scan/message",
        json={"text": "Complete KYC or account blocked.", "source": "dashboard"},
    )
    assert resp.status_code == 200
    scan_id = resp.json()["scan_id"]
    from app.database.models import Scan
    from sqlalchemy import select
    saved = db_session.scalar(select(Scan).where(Scan.scan_id == scan_id))
    assert saved is not None
    assert saved.scan_id == scan_id


# 20. Scan history retrieval
def test_scenario_20_scan_history_retrieval(client):
    # Perform scan
    client.post(
        "/api/v1/scan/url",
        json={"url": "https://sbi-fake-kyc.xyz/login", "source": "extension"},
    )
    # Query history
    resp = client.get("/api/v1/scans?limit=5&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert len(data["scans"]) >= 1
