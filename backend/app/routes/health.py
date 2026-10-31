"""PhishShield X - Health Check Route

GET /health
"""

from fastapi import APIRouter
from app.database.connection import verify_database_connection

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Health check endpoint conforming to agreed API contract."""
    return {"status": "ok"}
