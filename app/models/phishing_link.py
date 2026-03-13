import uuid

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class PhishingLink(Base):
    __tablename__ = "phishing_links"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    normalized_url = Column(Text, nullable=False, unique=True)
    domain = Column(String(255), nullable=False, index=True)
    report_count_24h = Column(Integer, nullable=False, default=0, server_default="0")
    report_count_7d = Column(Integer, nullable=False, default=0, server_default="0")
    report_count_30d = Column(Integer, nullable=False, default=0, server_default="0")
    status = Column(String(32), nullable=False, default="REPORTED_PATTERN", server_default="REPORTED_PATTERN")
    risk_level = Column(String(32), nullable=False, default="low", server_default="low")
    first_reported_at = Column(DateTime(timezone=True), nullable=True)
    last_reported_at = Column(DateTime(timezone=True), nullable=True)
    latest_alert_event_id = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
