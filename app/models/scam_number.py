import uuid

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func

from app.db import Base


class ScamNumber(Base):
    __tablename__ = "scam_numbers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    normalized_phone_number = Column(String(32), nullable=False, unique=True, index=True)
    display_phone_number = Column(String(32), nullable=True)
    report_count_24h = Column(Integer, nullable=False, default=0, server_default="0")
    report_count_7d = Column(Integer, nullable=False, default=0, server_default="0")
    report_count_30d = Column(Integer, nullable=False, default=0, server_default="0")
    first_reported_at = Column(DateTime(timezone=True), nullable=True)
    last_reported_at = Column(DateTime(timezone=True), nullable=True)
    risk_level = Column(String(32), nullable=False, default="low", server_default="low")
    status = Column(String(32), nullable=False, default="REPORTED_PATTERN", server_default="REPORTED_PATTERN")
    top_category = Column(String(64), nullable=True)
    top_regions = Column(JSONB, nullable=True)
    latest_alert_event_id = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
