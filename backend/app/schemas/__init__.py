"""PhishShield X Schemas Package"""

from app.schemas.findings import FindingCategory, FindingSeverity, ScanFindingResponse
from app.schemas.scan import (
    ScanSource,
    TargetType,
    RiskLevel,
    EngineStatus,
    UrlScanRequest,
    MessageScanRequest,
    ScanResponse,
    ScanHistoryItem,
    ScanHistoryResponse,
)

__all__ = [
    "FindingCategory",
    "FindingSeverity",
    "ScanFindingResponse",
    "ScanSource",
    "TargetType",
    "RiskLevel",
    "EngineStatus",
    "UrlScanRequest",
    "MessageScanRequest",
    "ScanResponse",
    "ScanHistoryItem",
    "ScanHistoryResponse",
]
