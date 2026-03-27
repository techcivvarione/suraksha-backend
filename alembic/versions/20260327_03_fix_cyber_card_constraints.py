"""Fix cyber_card_scores — drop legacy CHECK constraints, widen risk_level column

Revision ID: 20260327_03
Revises: 20260327_02
Create Date: 2026-03-27

Production symptom:
  psycopg2.errors.CheckViolation — new row for relation "cyber_card_scores"

Root cause:
  The table was originally created (outside Alembic) with legacy CHECK constraints
  such as:
    CHECK (score >= 0 AND score <= 999)   ← rejects score = 1000
    CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH'))  ← rejects 'MOSTLY_SAFE' etc.
    CHECK (max_score <= 999)              ← rejects max_score = 1000

  These constraints predate the V2 scoring system (0–1000 scale, named levels).

Fix:
  1. Dynamically drop ALL check constraints from cyber_card_scores via pg_constraint.
  2. Widen risk_level to TEXT (no length restriction).
  3. Add correct V2 constraints that allow 0–1000 and any non-empty string.
"""
from alembic import op

revision      = "20260327_03"
down_revision = "20260327_02"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── Step 1: Drop every CHECK constraint on the table ─────────────────────
    # We enumerate them via pg_constraint so the migration works regardless of
    # what the original constraint names were.
    op.execute(
        """
        DO $$
        DECLARE
            r RECORD;
        BEGIN
            FOR r IN (
                SELECT conname
                FROM pg_constraint
                WHERE conrelid = 'cyber_card_scores'::regclass
                  AND contype  = 'c'
            ) LOOP
                EXECUTE format(
                    'ALTER TABLE cyber_card_scores DROP CONSTRAINT IF EXISTS %I',
                    r.conname
                );
            END LOOP;
        END $$
        """
    )

    # ── Step 2: Widen risk_level from VARCHAR(50) → TEXT ─────────────────────
    # VARCHAR(50) is fine, but eliminates any chance of length rejection.
    op.execute(
        """
        ALTER TABLE cyber_card_scores
            ALTER COLUMN risk_level TYPE TEXT
        """
    )

    # ── Step 3: Add correct V2 constraints ───────────────────────────────────
    op.execute(
        """
        ALTER TABLE cyber_card_scores
            ADD CONSTRAINT ck_cyber_score_range
                CHECK (score >= 0 AND score <= 1000),
            ADD CONSTRAINT ck_cyber_max_score
                CHECK (max_score > 0 AND max_score <= 1000)
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE cyber_card_scores DROP CONSTRAINT IF EXISTS ck_cyber_max_score")
    op.execute("ALTER TABLE cyber_card_scores DROP CONSTRAINT IF EXISTS ck_cyber_score_range")
    op.execute("ALTER TABLE cyber_card_scores ALTER COLUMN risk_level TYPE VARCHAR(50)")
