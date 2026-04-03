import uuid

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class SecureNowItem(Base):
    __tablename__ = "secure_now_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    source_scan_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    type = Column(String(50), nullable=False, index=True)
    title = Column(String(120), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="PENDING", server_default="PENDING", index=True)
    risk_level = Column(String(10), nullable=False, default="high", server_default="high")
    auto_created = Column(Boolean, nullable=False, default=True, server_default="true")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
