"""initial schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-31 10:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create 'scans' table
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("engines", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False, server_default="dashboard"),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_scans_id", "scans", ["id"], unique=False)
    op.create_index("ix_scans_scan_id", "scans", ["scan_id"], unique=True)
    op.create_index("ix_scans_target_type", "scans", ["target_type"], unique=False)
    op.create_index("ix_scans_risk_level", "scans", ["risk_level"], unique=False)
    op.create_index("ix_scans_analyzed_at", "scans", ["analyzed_at"], unique=False)

    # 2. Create 'scan_findings' table
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("points", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_findings_scan_id", "scan_findings", ["scan_id"], unique=False)
    op.create_index("ix_scan_findings_category", "scan_findings", ["category"], unique=False)
    op.create_index("ix_scan_findings_severity", "scan_findings", ["severity"], unique=False)

    # 3. Optional 'arena_sessions' table
    op.create_table(
        "arena_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("scenario_id", sa.String(length=64), nullable=False),
        sa.Column("participant_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id"),
    )
    op.create_index("ix_arena_sessions_session_id", "arena_sessions", ["session_id"], unique=True)

    # 4. Optional 'arena_answers' table
    op.create_table(
        "arena_answers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("question_id", sa.String(length=64), nullable=False),
        sa.Column("selected_answer", sa.String(length=255), nullable=False),
        sa.Column("is_correct", sa.Boolean(), nullable=False),
        sa.Column("points_awarded", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["session_id"], ["arena_sessions.session_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_arena_answers_session_id", "arena_answers", ["session_id"], unique=False)


def downgrade() -> None:
    op.drop_table("arena_answers")
    op.drop_table("arena_sessions")
    op.drop_table("scan_findings")
    op.drop_table("scans")
