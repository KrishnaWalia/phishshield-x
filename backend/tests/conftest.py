"""PhishShield X - Test Configuration & Fixtures

Configures isolated in-memory test database for test runs to guarantee
zero destructive actions against the hackathon Neon database.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from unittest.mock import patch
from app.database.base import Base
from app.database.session import get_db
from app.main import app

@pytest.fixture(autouse=True)
def mock_db_verification():
    """Mock database verification during tests to avoid TCP timeouts to unconfigured local servers."""
    with patch("app.main.verify_database_connection", return_value=True):
        yield

# Isolated in-memory SQLite database specifically for test isolation
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session():
    """Create fresh in-memory database tables for each test function."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session: Session):
    """Provide FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
