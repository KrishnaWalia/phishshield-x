"""PhishShield X - Master Backend Application

The central intelligence layer and authoritative risk-scoring service for PhishShield X.
Integrates with Member 2 (Chrome Extension) and Member 3 (Next.js Dashboard & Scam Arena).
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.routes.health import router as health_router
from app.routes.scan import router as scan_router
from app.routes.history import router as history_router
from app.services.ml_service import ml_service
from app.database.connection import verify_database_connection

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.PHISHSHIELD_DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishshield.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize services and verify database connectivity."""
    logger.info("Initializing PhishShield X Intelligence Backend...")
    
    # 1. Verify ML Service readiness
    if ml_service.is_available:
        logger.info("ML Detection Service is active and ready.")
    else:
        logger.warning("ML Detection Service unavailable; rule-based engine will handle classification.")

    # 2. Check Database connection (Non-blocking verification)
    db_connected = verify_database_connection()
    if db_connected:
        logger.info("Successfully verified connection to Neon PostgreSQL database.")
    else:
        logger.warning(
            "Neon PostgreSQL database connection verification failed or DB is sleeping. "
            "App will attempt connection upon request."
        )

    yield

    logger.info("Shutting down PhishShield X Backend.")


# Initialize FastAPI application
app = FastAPI(
    title="PhishShield X Intelligence Backend API",
    description=(
        "The authoritative AI-powered cybersecurity intelligence engine for PhishShield X. "
        "Performs URL anatomy evaluation, scam/phishing message classification, and explainable risk scoring."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for Next.js Dashboard and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^chrome-extension://[a-z]{32}$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Global Exception Handler for validation errors (clean response without stack trace)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        loc = " -> ".join([str(x) for x in err.get("loc", [])])
        msg = err.get("msg", "Validation error")
        errors.append(f"{loc}: {msg}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "The submitted payload failed validation constraints.",
            "details": errors,
        },
    )


# Global Exception Handler for unhandled errors
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception during request {request.method} {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred while processing the request.",
        },
    )


# Register Routers
app.include_router(health_router)
app.include_router(scan_router)
app.include_router(history_router)
