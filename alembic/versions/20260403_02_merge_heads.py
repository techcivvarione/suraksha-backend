"""merge multiple heads

Revision ID: 20260403_02
Revises: 20260327_03, 20260403_01
Create Date: 2026-04-03
"""

from alembic import op

revision = "20260403_02"
down_revision = ("20260327_03", "20260403_01")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
