"""Tests for FastAPI endpoints: /health, /api/v1/scan/url, /api/v1/scan/message, /api/v1/scans."""

def test_health_endpoint(client):
    """GET /health must return status ok."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_scan_url_valid(client):
    """POST /api/v1/scan/url with legitimate URL."""
    payload = {
        "url": "https://www.google.com",
        "page_title": "Google Search",
        "page_text": "Search the world's information, including webpages, images, videos and more.",
        "links": ["https://www.google.com/imghp"],
        "source": "dashboard",
    }
    resp = client.post("/api/v1/scan/url", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_type"] == "url"
    assert "google.com" in data["target"]
    assert data["risk_score"] < 20
    assert data["risk_level"] == "LOW"
    assert "scan_id" in data
    assert "engines" in data


def test_scan_message_valid(client):
    """POST /api/v1/scan/message with scam message."""
    payload = {
        "text": "Your SBI account will be blocked today. Complete KYC immediately at http://sbi-kyc.net",
        "source": "dashboard",
    }
    resp = client.post("/api/v1/scan/message", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_type"] == "message"
    assert data["risk_score"] >= 40
    assert data["risk_level"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]
    assert len(data["findings"]) > 0


def test_empty_message_input(client):
    """Empty message should return 422 Unprocessable Entity."""
    resp = client.post("/api/v1/scan/message", json={"text": "", "source": "dashboard"})
    assert resp.status_code == 422


def test_invalid_url_scheme(client):
    """Disallowed schemes like javascript: or ftp: must return 422 validation error."""
    resp = client.post(
        "/api/v1/scan/url",
        json={"url": "javascript:alert(1)", "source": "extension"},
    )
    assert resp.status_code == 422


def test_invalid_source(client):
    """Source other than extension, dashboard, arena must return 422."""
    resp = client.post(
        "/api/v1/scan/message",
        json={"text": "Hello world", "source": "invalid_source"},
    )
    assert resp.status_code == 422


def test_excessive_page_text(client):
    """page_text exceeding 6000 chars must return 422."""
    resp = client.post(
        "/api/v1/scan/url",
        json={
            "url": "https://example.com",
            "page_text": "A" * 6001,
            "source": "extension",
        },
    )
    assert resp.status_code == 422


def test_excessive_links_count(client):
    """links array exceeding 30 items must return 422."""
    resp = client.post(
        "/api/v1/scan/url",
        json={
            "url": "https://example.com",
            "links": [f"https://example.com/{i}" for i in range(35)],
            "source": "extension",
        },
    )
    assert resp.status_code == 422


def test_scan_history_and_detail(client):
    """Ensure scans are persisted and retrievable via /api/v1/scans and /api/v1/scans/{scan_id}."""
    # 1. Perform scan
    scan_resp = client.post(
        "/api/v1/scan/message",
        json={
            "text": "Your account will be suspended. Verify your KYC immediately.",
            "source": "dashboard",
        },
    )
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    # 2. Retrieve history list
    hist_resp = client.get("/api/v1/scans?limit=10&offset=0")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["total"] >= 1
    assert any(s["scan_id"] == scan_id for s in hist_data["scans"])

    # 3. Retrieve individual scan detail
    detail_resp = client.get(f"/api/v1/scans/{scan_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["scan_id"] == scan_id
    assert len(detail_data["findings"]) > 0

    # 4. Non-existent scan should return 404
    missing_resp = client.get("/api/v1/scans/psx_nonexistent_999")
    assert missing_resp.status_code == 404
