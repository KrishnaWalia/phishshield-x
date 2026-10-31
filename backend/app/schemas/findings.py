"""PhishShield X - Scan Finding Schemas

Pydantic schemas for detection findings and risk contributors.
"""

from enum import Enum
from pydantic import BaseModel, Field


class FindingCategory(str, Enum):
    """Allowed finding categories with fixed risk point caps:
    - url: 25 pts max
    - identity: 20 pts max
    - semantic: 25 pts max
    - behavior: 20 pts max
    - reputation: 10 pts max
    Total: 100 pts max.
    """
    URL = "url"
    IDENTITY = "identity"
    SEMANTIC = "semantic"
    BEHAVIOR = "behavior"
    REPUTATION = "reputation"


class FindingSeverity(str, Enum):
    """Allowed finding severity classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanFindingResponse(BaseModel):
    """Granular evidence-backed detection finding."""
    id: str = Field(..., description="Unique finding identifier (e.g. url_001, sem_002)")
    category: str = Field(..., description="Category: url, identity, semantic, behavior, reputation")
    severity: str = Field(..., description="Severity: low, medium, high, critical")
    points: int = Field(..., ge=0, le=100, description="Contributed risk points")
    title: str = Field(..., description="Short finding title")
    evidence: str = Field(..., description="Observed evidence from target URL, links, or text")
    explanation: str = Field(..., description="User-friendly explanation of why this is suspicious")

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "url_001",
                "category": "url",
                "severity": "high",
                "points": 20,
                "title": "Suspicious domain structure",
                "evidence": "Domain contains deceptive keywords and excessive subdomains",
                "explanation": "The domain attempts to mislead users into believing it is an official portal.",
            }
        },
    }
