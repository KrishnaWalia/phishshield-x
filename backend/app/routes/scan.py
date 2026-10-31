"""PhishShield X - Scan Endpoints

POST /api/v1/scan/url
POST /api/v1/scan/message
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.schemas.scan import (
    UrlScanRequest,
    MessageScanRequest,
    ScanResponse,
)
from app.services.scan_service import ScanService
from app.database.session import get_db

logger = logging.getLogger("phishshield.routes.scan")
router = APIRouter(prefix="/api/v1/scan", tags=["Scanning"])


@router.post(
    "/url",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan URL for Phishing and Deceptive Structure",
)
def scan_url_endpoint(
    request: UrlScanRequest,
    db: Session = Depends(get_db),
):
    """Analyze a suspicious URL, associated metadata, and anchor links.
    
    Returns an authoritative risk score (0-100), risk level, and granular findings.
    """
    try:
        return ScanService.scan_url(request, db=db)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        logger.exception(f"Error in scan_url_endpoint: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during URL threat analysis: {exc}",
        )


@router.post(
    "/message",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan Message for Social Engineering and Fraud Lures",
)
def scan_message_endpoint(
    request: MessageScanRequest,
    db: Session = Depends(get_db),
):
    """Analyze a suspicious message (SMS, WhatsApp, Email, Job Offer, KYC demand).
    
    Returns an authoritative risk score (0-100), risk level, and granular findings.
    """
    try:
        return ScanService.scan_message(request, db=db)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during message threat analysis.",
        )
