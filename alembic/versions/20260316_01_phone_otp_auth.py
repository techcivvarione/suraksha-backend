"""phone otp auth

Revision ID: 20260316_01_phone_otp_auth
Revises: 20260314_04_google_sub
Create Date: 2026-03-16
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260316_01_phone_otp_auth"
down_revision = "20260314_04_google_sub"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("phone_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_users_phone_number
        ON users(phone_number)
        WHERE phone_number IS NOT NULL
        """
    )

    op.create_table(
        "phone_otps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("phone_number", sa.Text(), nullable=False),
        sa.Column("otp_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_phone_otps_phone_number", "phone_otps", ["phone_number"], unique=False)
    op.create_index("ix_phone_otps_expires_at", "phone_otps", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_phone_otps_expires_at", table_name="phone_otps")
    op.drop_index("ix_phone_otps_phone_number", table_name="phone_otps")
    op.drop_table("phone_otps")
    op.execute("DROP INDEX IF EXISTS uq_users_phone_number")
    op.drop_column("users", "phone_verified")
