"""PhishShield X Detection Package"""

from app.detection.url_analyzer import analyze_url
from app.detection.message_analyzer import analyze_message_rules
from app.detection.risk_engine import (
    calculate_risk_assessment,
    compute_risk_level,
    deduplicate_findings,
    CATEGORY_CAPS,
)

__all__ = [
    "analyze_url",
    "analyze_message_rules",
    "calculate_risk_assessment",
    "compute_risk_level",
    "deduplicate_findings",
    "CATEGORY_CAPS",
]
