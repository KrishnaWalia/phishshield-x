"""PhishShield X - Scan Schemas

Defines request and response schemas conforming strictly to the shared API contract:
- POST /api/v1/scan/url
- POST /api/v1/scan/message
- GET /api/v1/scans
- GET /api/v1/scans/{scan_id}
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from app.schemas.findings import ScanFindingResponse


class ScanSource(str, Enum):
    """Allowed source origins."""
    EXTENSION = "extension"
    DASHBOARD = "dashboard"
    ARENA = "arena"


class TargetType(str, Enum):
    """Target types."""
    URL = "url"
    MESSAGE = "message"


class RiskLevel(str, Enum):
    """Strict risk level classifications."""
    LOW = "LOW"
    MODERATE = "MODERATE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EngineStatus(BaseModel):
    """Status flags for detection engines executed during the scan."""
    rules: bool = Field(True, description="Rule-based heuristic engine status")
    ml: bool = Field(True, description="Scikit-learn classification engine status")
    ai: bool = Field(False, description="Groq AI semantic engine status")


class UrlScanRequest(BaseModel):
    """Request payload for URL scanning endpoint."""
    url: str = Field(..., description="Target URL to analyze (http or https)")
    page_title: Optional[str] = Field(None, max_length=500, description="Extracted HTML title")
    page_text: Optional[str] = Field(
        None,
        max_length=6000,
        description="Visible text extracted from page (max 6000 characters)",
    )
    links: Optional[List[str]] = Field(
        default_factory=list,
        max_length=30,
        description="List of anchor links found on the page (max 30 links)",
    )
    source: ScanSource = Field(
        default=ScanSource.EXTENSION,
        description="Origin source: extension, dashboard, arena",
    )

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("URL cannot be empty.")
        stripped = v.strip()
        lower = stripped.lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        if len(stripped) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters.")
        return stripped

    @field_validator("links")
    @classmethod
    def validate_links_count(cls, v: Optional[List[str]]) -> List[str]:
        if v is None:
            return []
        if len(v) > 30:
            raise ValueError("Exceeded maximum of 30 links per scan.")
        return v

    @field_validator("page_text")
    @classmethod
    def validate_page_text_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 6000:
            raise ValueError("page_text exceeds maximum length of 6000 characters.")
        return v


class MessageScanRequest(BaseModel):
    """Request payload for Message scanning endpoint."""
    text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Message content (SMS, WhatsApp, Email, etc.)",
    )
    source: ScanSource = Field(
        default=ScanSource.DASHBOARD,
        description="Origin source: extension, dashboard, arena",
    )

    @field_validator("text")
    @classmethod
    def validate_text_not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Message text cannot be empty or solely whitespace.")
        return v.strip()


class ScanResponse(BaseModel):
    """Authoritative standard scan response returned for both URL and message scans."""
    scan_id: str = Field(..., description="Unique public scan identifier (e.g. psx_123456)")
    target_type: str = Field(..., description="Target type: 'url' or 'message'")
    target: str = Field(..., description="Sanitized URL or safe message descriptor")
    risk_score: int = Field(..., ge=0, le=100, description="Authoritative risk score (0-100)")
    risk_level: str = Field(..., description="Risk level: LOW, MODERATE, SUSPICIOUS, HIGH, CRITICAL")
    summary: str = Field(..., description="Executive threat summary")
    findings: List[ScanFindingResponse] = Field(
        default_factory=list,
        description="Granular findings supporting the score",
    )
    recommended_action: str = Field(..., description="Actionable user safety guidance")
    analyzed_at: str = Field(..., description="ISO 8601 formatted timestamp")
    engines: EngineStatus = Field(..., description="Engines utilized in analysis")

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
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
                        "explanation": "The domain contains suspicious characteristics.",
                    }
                ],
                "recommended_action": "Avoid interacting with this website.",
                "analyzed_at": "2026-10-31T10:30:00Z",
                "engines": {
                    "rules": True,
                    "ml": True,
                    "ai": True,
                },
            }
        },
    }


class ScanHistoryItem(BaseModel):
    """Summary item for scan history list."""
    scan_id: str
    target_type: str
    target: str
    risk_score: int
    risk_level: str
    summary: str
    recommended_action: str
    source: str
    analyzed_at: str
    findings_count: int

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    """Paginated scan history response."""
    total: int = Field(..., description="Total number of scans in database")
    limit: int = Field(..., description="Requested limit")
    offset: int = Field(..., description="Requested offset")
    scans: List[ScanHistoryItem] = Field(default_factory=list, description="Scans list")
