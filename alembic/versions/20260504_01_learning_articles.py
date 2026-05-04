"""add learning articles

Revision ID: 20260504_01
Revises: 20260403_02
Create Date: 2026-05-04 00:00:00.000000
"""

from alembic import op

revision = "20260504_01"
down_revision = "20260403_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS learning_articles (
            id UUID PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            content TEXT NOT NULL,
            category VARCHAR(100) NOT NULL,
            read_time INTEGER NOT NULL,
            image_url TEXT NULL,
            is_featured BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_learning_articles_category ON learning_articles (category)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_learning_articles_created_at ON learning_articles (created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_learning_articles_is_featured ON learning_articles (is_featured)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_learning_articles_is_featured")
    op.execute("DROP INDEX IF EXISTS ix_learning_articles_created_at")
    op.execute("DROP INDEX IF EXISTS ix_learning_articles_category")
    op.execute("DROP TABLE IF EXISTS learning_articles")
