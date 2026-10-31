"""PhishShield X - Scan History Endpoints

GET /api/v1/scans
GET /api/v1/scans/{scan_id}
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.schemas.scan import ScanResponse, ScanHistoryResponse
from app.services.scan_service import ScanService
from app.database.session import get_db

router = APIRouter(prefix="/api/v1/scans", tags=["Scan History"])


@router.get(
    "",
    response_model=ScanHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Scan History",
)
def get_scan_history(
    limit: int = Query(default=20, ge=1, le=100, description="Number of scans to return"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated scan history stored in Neon PostgreSQL."""
    try:
        return ScanService.get_history(db=db, limit=limit, offset=offset)
    except Exception as exc:
        # Fallback to session cache even if database dependency connection drops
        return ScanService.get_history(db=None, limit=limit, offset=offset)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Detailed Scan Report by Scan ID",
)
def get_scan_detail(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve full scan report and evidence findings for a given public scan_id."""
    try:
        scan = ScanService.get_scan_by_id(db=db, scan_id=scan_id)
    except Exception:
        scan = ScanService.get_scan_by_id(db=None, scan_id=scan_id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' was not found.",
        )
    return scan
