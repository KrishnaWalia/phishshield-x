"""PhishShield X - SQLAlchemy 2.0 Database Models

Models:
1. Scan: Authoritative record of each analyzed URL or message.
2. ScanFinding: Granular, evidence-based detection findings tied to a scan.
3. ArenaSession (Optional): Scam Arena training sessions.
4. ArenaAnswer (Optional): User responses in Scam Arena.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    String,
    Integer,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    Boolean,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_uuid() -> str:
    """Generate string UUID4."""
    return str(uuid.uuid4())


class Scan(Base):
    """Authoritative scan record stored in Neon PostgreSQL."""

    __tablename__ = "scans"

    # Internal primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
        index=True,
    )

    # Public unique scan identifier returned in API (e.g. psx_a1b2c3d4)
    scan_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    # Target type: 'url' or 'message'
    target_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )

    # Sanitized URL or safe message descriptor (Never stores raw secrets/passwords)
    target: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Final authoritative risk score (0-100)
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    # Risk classification: LOW, MODERATE, SUSPICIOUS, HIGH, CRITICAL
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    # Human-readable summary
    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Actionable guidance
    recommended_action: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Status of detection engines: {"rules": bool, "ml": bool, "ai": bool}
    engines: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    # Source of request: 'extension', 'dashboard', 'arena'
    source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="dashboard",
    )

    # Timezone-aware timestamp
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # 1:N relationship with individual findings
    findings: Mapped[List["ScanFinding"]] = relationship(
        "ScanFinding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="desc(ScanFinding.points)",
    )


class ScanFinding(Base):
    """Individual explainable finding with evidence and category score."""

    __tablename__ = "scan_findings"

    # Unique finding identifier
    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=generate_uuid,
    )

    # Foreign key referencing scans.scan_id
    scan_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("scans.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Category: 'url', 'identity', 'semantic', 'behavior', 'reputation'
    category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    # Severity: 'low', 'medium', 'high', 'critical'
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )

    # Contributed risk points
    points: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # Finding title
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Concrete observed evidence
    evidence: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Human-friendly explanation
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Relationship back to scan
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="findings",
    )


# Optional Models for Scam Arena (schema readiness)
class ArenaSession(Base):
    """Optional Scam Arena training session."""

    __tablename__ = "arena_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    scenario_id: Mapped[str] = mapped_column(String(64), nullable=False)
    participant_score: Mapped[int] = mapped_column(Integer, default=0)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    answers: Mapped[List["ArenaAnswer"]] = relationship(
        "ArenaAnswer",
        back_populates="session",
        cascade="all, delete-orphan",
    )


class ArenaAnswer(Base):
    """Optional user response in Scam Arena."""

    __tablename__ = "arena_answers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    session_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("arena_sessions.session_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    question_id: Mapped[str] = mapped_column(String(64), nullable=False)
    selected_answer: Mapped[str] = mapped_column(String(255), nullable=False)
    is_correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    points_awarded: Mapped[int] = mapped_column(Integer, default=0)

    session: Mapped["ArenaSession"] = relationship("ArenaSession", back_populates="answers")
