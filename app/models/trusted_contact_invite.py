import uuid

from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class TrustedContactInvite(Base):
    __tablename__ = "trusted_contact_invites"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    receiver_user_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    receiver_phone = Column(String(20), nullable=False, index=True)
    contact_name = Column(String(100), nullable=True)
    relationship = Column(String(100), nullable=True)
    add_to_family = Column(Boolean, nullable=False, default=True, server_default="true")
    status = Column(String(20), nullable=False, default="PENDING", server_default="PENDING", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
