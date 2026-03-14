"""radar live desc index

Revision ID: 20260314_02
Revises: 20260314_01
Create Date: 2026-03-14 00:10:00.000000
"""

from alembic import op

revision = "20260314_02"
down_revision = "20260314_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE INDEX IF NOT EXISTS idx_scam_events_time_desc ON scam_events(created_at DESC)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_scam_events_time_desc")
