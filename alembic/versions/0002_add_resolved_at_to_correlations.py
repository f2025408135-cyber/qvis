"""add_resolved_at_to_correlations: add resolved_at column to correlation_events.

Allows resolved correlations to be tracked and later used by the data
retention policy for selective cleanup.

Revision ID: 0002_add_resolved_at
Revises: 0001_initial
Create Date: 2026-04-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0002_add_resolved_at"
down_revision: Union[str, Sequence[str], None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add resolved_at column and index to correlation_events."""
    op.add_column(
        "correlation_events",
        sa.Column("resolved_at", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_corr_resolved_at",
        "correlation_events",
        ["resolved_at"],
    )


def downgrade() -> None:
    """Remove resolved_at column and index from correlation_events."""
    op.drop_index("idx_corr_resolved_at", table_name="correlation_events")
    op.drop_column("correlation_events", "resolved_at")
