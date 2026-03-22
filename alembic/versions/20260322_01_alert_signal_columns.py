"""add scan_type, risk_level, extra_signals to alert_events

Revision ID: 20260322_01
Revises: 20260321_01_supabase_user_id
Create Date: 2026-03-22 00:00:00.000000

STEP 6: Store richer context at alert-creation time so that
/alerts/debug/latest and /alerts/family-feed can return meaningful
data without re-joining scan_history.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260322_01"
down_revision = "20260321_01_supabase_user_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE alert_events
            ADD COLUMN IF NOT EXISTS scan_type     VARCHAR(20) NULL,
            ADD COLUMN IF NOT EXISTS risk_level    VARCHAR(10) NULL,
            ADD COLUMN IF NOT EXISTS extra_signals JSONB       NULL
        """
    )

    # Back-fill risk_level from risk_score for existing rows
    op.execute(
        """
        UPDATE alert_events
        SET risk_level = CASE
            WHEN risk_score >= 70 THEN 'high'
            WHEN risk_score >= 40 THEN 'medium'
            ELSE 'low'
        END
        WHERE risk_level IS NULL
        """
    )

    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_alert_events_scan_type  ON alert_events (scan_type)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_alert_events_risk_level ON alert_events (risk_level)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_alert_events_risk_level")
    op.execute("DROP INDEX IF EXISTS ix_alert_events_scan_type")
    op.execute("ALTER TABLE alert_events DROP COLUMN IF EXISTS extra_signals")
    op.execute("ALTER TABLE alert_events DROP COLUMN IF EXISTS risk_level")
    op.execute("ALTER TABLE alert_events DROP COLUMN IF EXISTS scan_type")
