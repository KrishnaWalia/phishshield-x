"""PhishShield X - Database Connection Configuration

Configures SQLAlchemy 2.0 engine for Neon PostgreSQL.
Uses connection pooling optimized for Neon serverless architecture:
- pool_size=5, max_overflow=5
- pool_pre_ping=True (drops dead connections before executing queries)
- pool_recycle=300 (proactively refreshes connections before timeouts)
"""

import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings

logger = logging.getLogger("phishshield.database")

# Connection arguments for psycopg
connect_args = {"connect_timeout": 3} if "sqlite" not in settings.sqlalchemy_database_url else {}

# Create SQLAlchemy Engine using normalized Neon connection string
try:
    engine = create_engine(
        settings.sqlalchemy_database_url,
        pool_size=5,
        max_overflow=5,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_timeout=5,
        connect_args=connect_args,
        echo=settings.PHISHSHIELD_DEBUG,
    )
    logger.info("SQLAlchemy engine initialized for Neon PostgreSQL.")
except Exception as e:
    logger.error(f"Failed to initialize SQLAlchemy engine: {e}")
    raise

# Session factory for synchronous sessions
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def verify_database_connection() -> bool:
    """Verifies that the database is reachable and active.
    
    Returns True if connection succeeded, False otherwise.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(f"Database connection verification failed: {exc}")
        return False
