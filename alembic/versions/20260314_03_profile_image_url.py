"""add profile image url to users

Revision ID: 20260314_03
Revises: 20260314_02
Create Date: 2026-03-14 00:20:00.000000
"""

from alembic import op

revision = "20260314_03"
down_revision = "20260314_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_image_url TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS profile_image_url")
