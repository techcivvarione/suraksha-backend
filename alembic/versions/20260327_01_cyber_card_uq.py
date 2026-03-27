"""cyber_card — add unique constraint on (user_id, score_month)

Revision ID: 20260327_01
Revises: 20260326_01
Create Date: 2026-03-27

The ON CONFLICT (user_id, score_month) clause in _compute_and_upsert requires
a unique constraint to exist.  Without it every upsert silently fails, so the
card is never written and eligible users always see "Analysing your scans".
"""
from alembic import op

revision     = "20260327_01"
down_revision = "20260326_01"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # Remove duplicate rows first (keep highest score per user/month)
    op.execute(
        """
        DELETE FROM cyber_card_scores a
        USING cyber_card_scores b
        WHERE a.id <> b.id
          AND a.user_id     = b.user_id
          AND a.score_month = b.score_month
          AND a.score < b.score
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_cyber_card_scores_user_month
        ON cyber_card_scores (user_id, score_month)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_cyber_card_scores_user_month")
