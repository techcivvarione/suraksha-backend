"""Add supabase_user_id to users table

Revision ID: 20260321_01
Revises: 20260316_01_phone_otp_auth
Create Date: 2026-03-21
"""

from alembic import op
import sqlalchemy as sa


revision = "20260321_01"
down_revision = "20260316_01_phone_otp_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("supabase_user_id", sa.String(), nullable=True),
    )
    # Unique partial index — allows multiple NULLs while enforcing uniqueness
    # for non-NULL values (matches SQLAlchemy unique=True behaviour on nullable cols)
    op.create_index(
        "ix_users_supabase_user_id",
        "users",
        ["supabase_user_id"],
        unique=True,
        postgresql_where=sa.text("supabase_user_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_users_supabase_user_id", table_name="users")
    op.drop_column("users", "supabase_user_id")
