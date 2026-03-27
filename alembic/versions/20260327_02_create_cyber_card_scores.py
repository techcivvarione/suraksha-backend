"""Create cyber_card_scores table with all columns (safe if already exists)

Revision ID: 20260327_02
Revises: 20260327_01
Create Date: 2026-03-27

The cyber_card_scores table was never explicitly created via Alembic.
This migration creates it with ALL required columns (V2-ready from the start)
plus the unique constraint needed by the ON CONFLICT clause.

Uses IF NOT EXISTS everywhere so re-running is safe.
"""
from alembic import op

revision     = "20260327_02"
down_revision = "20260327_01"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── Create table with all columns (no-op if it already exists) ────────────
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cyber_card_scores (
            id           UUID        NOT NULL DEFAULT gen_random_uuid(),
            user_id      UUID        NOT NULL,
            score        INTEGER     NOT NULL DEFAULT 0,
            max_score    INTEGER     NOT NULL DEFAULT 1000,
            risk_level   VARCHAR(50),
            signals      JSONB                DEFAULT '{}',
            factors      JSONB,
            insights     JSONB,
            actions      JSONB,
            score_month  TIMESTAMPTZ NOT NULL,
            updated_at   TIMESTAMPTZ          DEFAULT now(),
            created_at   TIMESTAMPTZ          DEFAULT now(),
            CONSTRAINT pk_cyber_card_scores PRIMARY KEY (id)
        )
        """
    )

    # ── Add V2 columns in case the table already existed without them ─────────
    op.execute(
        """
        ALTER TABLE cyber_card_scores
            ADD COLUMN IF NOT EXISTS factors    JSONB,
            ADD COLUMN IF NOT EXISTS insights   JSONB,
            ADD COLUMN IF NOT EXISTS actions    JSONB,
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now()
        """
    )

    # ── Unique constraint (required for ON CONFLICT upsert) ───────────────────
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_cyber_card_scores_user_month
        ON cyber_card_scores (user_id, score_month)
        """
    )

    # ── Performance index on user_id + updated_at (stale-check query) ─────────
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_cyber_card_scores_user_updated
        ON cyber_card_scores (user_id, updated_at DESC NULLS LAST)
        """
    )

    # ── Back-fill updated_at for any rows created before this migration ────────
    op.execute(
        """
        UPDATE cyber_card_scores
        SET updated_at = COALESCE(created_at, now())
        WHERE updated_at IS NULL
        """
    )


def downgrade() -> None:
    # Only drop the indexes — keep the table data safe on downgrade
    op.execute("DROP INDEX IF EXISTS ix_cyber_card_scores_user_updated")
    op.execute("DROP INDEX IF EXISTS uq_cyber_card_scores_user_month")
