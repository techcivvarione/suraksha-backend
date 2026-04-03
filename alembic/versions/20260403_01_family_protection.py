"""add family protection invites and secure now

Revision ID: 20260403_01
Revises: 20260322_01
Create Date: 2026-04-03 00:00:00.000000
"""

from alembic import op

revision = "20260403_01"
down_revision = "20260322_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE trusted_contacts
            ADD COLUMN IF NOT EXISTS family_link_enabled BOOLEAN NOT NULL DEFAULT true
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_contact_invites (
            id UUID PRIMARY KEY,
            sender_user_id UUID NOT NULL,
            receiver_user_id UUID NULL,
            receiver_phone VARCHAR(20) NOT NULL,
            contact_name VARCHAR(100) NULL,
            relationship VARCHAR(100) NULL,
            add_to_family BOOLEAN NOT NULL DEFAULT true,
            status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_trusted_contact_invites_sender ON trusted_contact_invites (sender_user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_trusted_contact_invites_receiver_phone ON trusted_contact_invites (receiver_phone)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_trusted_contact_invites_status ON trusted_contact_invites (status)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS secure_now_items (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL,
            source_scan_id UUID NULL,
            type VARCHAR(50) NOT NULL,
            title VARCHAR(120) NOT NULL,
            description TEXT NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            risk_level VARCHAR(10) NOT NULL DEFAULT 'high',
            auto_created BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            completed_at TIMESTAMPTZ NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_secure_now_items_user_id ON secure_now_items (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_secure_now_items_status ON secure_now_items (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_secure_now_items_created_at ON secure_now_items (created_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_secure_now_items_created_at")
    op.execute("DROP INDEX IF EXISTS ix_secure_now_items_status")
    op.execute("DROP INDEX IF EXISTS ix_secure_now_items_user_id")
    op.execute("DROP TABLE IF EXISTS secure_now_items")
    op.execute("DROP INDEX IF EXISTS ix_trusted_contact_invites_status")
    op.execute("DROP INDEX IF EXISTS ix_trusted_contact_invites_receiver_phone")
    op.execute("DROP INDEX IF EXISTS ix_trusted_contact_invites_sender")
    op.execute("DROP TABLE IF EXISTS trusted_contact_invites")
    op.execute("ALTER TABLE trusted_contacts DROP COLUMN IF EXISTS family_link_enabled")
