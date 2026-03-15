"""add google_sub for strict google identity binding

Revision ID: 20260314_04
Revises: 20260314_03
Create Date: 2026-03-14 00:30:00.000000
"""

from alembic import op

revision = "20260314_04"
down_revision = "20260314_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub_unique ON users(google_sub) WHERE google_sub IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_users_google_sub_unique")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS google_sub")
