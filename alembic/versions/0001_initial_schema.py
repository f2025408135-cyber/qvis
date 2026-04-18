"""initial_schema: create threat_events and correlation_events tables.

This initial migration matches the DDL that was previously embedded in
``backend/storage/database.py`` verbatim, ensuring zero-diff for existing
SQLite databases that were created by the old ``init_db()`` path.

Revision ID: 0001_initial
Revises: None
Create Date: 2026-04-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create threat_events and correlation_events tables with indexes."""

    # ── threat_events ────────────────────────────────────────────────────
    op.create_table(
        "threat_events",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("technique_id", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.Column("backend_id", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("detected_at", sa.Text(), nullable=False),
        sa.Column("visual_effect", sa.Text(), nullable=False, server_default=""),
        sa.Column("visual_intensity", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("remediation", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("resolved_at", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index("idx_threats_detected_at", "threat_events", ["detected_at"])
    op.create_index("idx_threats_severity", "threat_events", ["severity"])
    op.create_index("idx_threats_technique_id", "threat_events", ["technique_id"])
    op.create_index("idx_threats_backend_id", "threat_events", ["backend_id"])
    op.create_index("idx_threats_resolved_at", "threat_events", ["resolved_at"])

    # ── correlation_events ───────────────────────────────────────────────
    op.create_table(
        "correlation_events",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("pattern_name", sa.Text(), nullable=False),
        sa.Column("techniques", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("backends", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("detected_at", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index("idx_corr_detected_at", "correlation_events", ["detected_at"])


def downgrade() -> None:
    """Drop correlation_events and threat_events tables."""
    op.drop_index("idx_corr_detected_at", table_name="correlation_events")
    op.drop_table("correlation_events")

    op.drop_index("idx_threats_resolved_at", table_name="threat_events")
    op.drop_index("idx_threats_backend_id", table_name="threat_events")
    op.drop_index("idx_threats_technique_id", table_name="threat_events")
    op.drop_index("idx_threats_severity", table_name="threat_events")
    op.drop_index("idx_threats_detected_at", table_name="threat_events")
    op.drop_table("threat_events")
