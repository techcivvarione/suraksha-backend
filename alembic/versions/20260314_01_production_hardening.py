"""production hardening baseline

Revision ID: 20260314_01
Revises: 
Create Date: 2026-03-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260314_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    user_indexes = {index["name"] for index in inspector.get_indexes("users")}

    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    if "token_version" not in user_columns:
        op.add_column("users", sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
    if "idx_users_token_version" not in user_indexes:
        op.create_index("idx_users_token_version", "users", ["token_version"])

    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS accepted_terms BOOLEAN DEFAULT FALSE")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS accepted_terms_at TIMESTAMPTZ NULL")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_version TEXT")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS privacy_version TEXT")
    op.execute("UPDATE users SET accepted_terms = FALSE WHERE accepted_terms IS NULL")
    op.execute("UPDATE users SET terms_version = 'v1' WHERE terms_version IS NULL")
    op.execute("UPDATE users SET privacy_version = 'v1' WHERE privacy_version IS NULL")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_rate_limits (
            id BIGSERIAL PRIMARY KEY,
            key TEXT NOT NULL,
            attempt_time TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_key_time ON auth_rate_limits(key, attempt_time DESC)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS subscription_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            event_id VARCHAR(128) NOT NULL UNIQUE,
            user_id UUID NULL,
            event_type VARCHAR(64) NOT NULL,
            event_at TIMESTAMPTZ NULL,
            processing_status VARCHAR(32) NOT NULL DEFAULT 'RECEIVED',
            payload TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_subscription_events_user_id ON subscription_events(user_id)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scam_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            category TEXT,
            severity INTEGER,
            reports INTEGER,
            source TEXT,
            created_at TIMESTAMPTZ DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_scam_events_time ON scam_events(created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scam_events_location ON scam_events(latitude, longitude)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scam_events_source_time ON scam_events(source, created_at DESC)")

    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_user_created ON scan_history(user_id, created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alert_events_user ON alert_events(user_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_alert_events_user")
    op.execute("DROP INDEX IF EXISTS idx_scan_history_user_created")
    op.execute("DROP INDEX IF EXISTS idx_scam_events_source_time")
    op.execute("DROP INDEX IF EXISTS idx_scam_events_location")
    op.execute("DROP INDEX IF EXISTS idx_scam_events_time")
    op.execute("DROP TABLE IF EXISTS scam_events")
    op.execute("DROP INDEX IF EXISTS idx_subscription_events_user_id")
    op.execute("DROP TABLE IF EXISTS subscription_events")
    op.execute("DROP INDEX IF EXISTS idx_auth_rate_limits_key_time")
    op.execute("DROP TABLE IF EXISTS auth_rate_limits")
    op.execute("DROP INDEX IF EXISTS idx_users_token_version")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS privacy_version")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS terms_version")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS accepted_terms_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS accepted_terms")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS token_version")
