"""cyber_card v2 — add factors, insights, actions, updated_at to cyber_card_scores

Revision ID: 20260326_01
Revises: 20260322_01
Create Date: 2026-03-26

Adds four columns that the real-time scoring engine writes:
  factors   JSONB  — per-component score breakdown
  insights  JSONB  — human-readable findings list
  actions   JSONB  — suggested next-steps list
  updated_at TIMESTAMPTZ — used for the 5-minute stale-check cache
"""
from alembic import op

revision = "20260326_01"
down_revision = "20260322_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE cyber_card_scores
            ADD COLUMN IF NOT EXISTS factors    JSONB,
            ADD COLUMN IF NOT EXISTS insights   JSONB,
            ADD COLUMN IF NOT EXISTS actions    JSONB,
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now()
        """
    )
    # Back-fill updated_at for any rows that pre-date this migration
    op.execute(
        """
        UPDATE cyber_card_scores
        SET updated_at = COALESCE(created_at, now())
        WHERE updated_at IS NULL
        """
    )
    # Index used by the stale-check in fetch_cyber_card()
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_cyber_card_scores_user_updated
        ON cyber_card_scores (user_id, updated_at DESC NULLS LAST)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cyber_card_scores_user_updated")
    op.execute("ALTER TABLE cyber_card_scores DROP COLUMN IF EXISTS updated_at")
    op.execute("ALTER TABLE cyber_card_scores DROP COLUMN IF EXISTS actions")
    op.execute("ALTER TABLE cyber_card_scores DROP COLUMN IF EXISTS insights")
    op.execute("ALTER TABLE cyber_card_scores DROP COLUMN IF EXISTS factors")
