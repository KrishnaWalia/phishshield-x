"""PhishShield X - Database Session Management

Provides FastAPI dependency injection for database sessions.
Ensures sessions are cleanly closed, preventing connection leaks.
"""

import logging
from typing import Generator
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status

from app.database.connection import SessionLocal

logger = logging.getLogger("phishshield.session")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a clean database session per request."""
    db: Session = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as exc:
        logger.error(f"Database session encountered an error: {exc}")
        db.rollback()
        raise
    finally:
        db.close()
