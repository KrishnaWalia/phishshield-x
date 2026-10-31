"""PhishShield X Routes Package"""

from app.routes.health import router as health_router
from app.routes.scan import router as scan_router
from app.routes.history import router as history_router

__all__ = ["health_router", "scan_router", "history_router"]
