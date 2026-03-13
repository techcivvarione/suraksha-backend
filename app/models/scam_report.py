import uuid

from sqlalchemy import Column, DateTime, Float, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class ScamReport(Base):
    __tablename__ = "scam_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    scam_type = Column(String(50), nullable=True)
    title = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    source = Column(String(255), nullable=True)
    scam_value = Column(String(50), nullable=True)

    report_type = Column(String(32), nullable=True, index=True)
    category = Column(String(64), nullable=True, index=True)
    scam_phone_number = Column(String(32), nullable=True)
    normalized_phone_number = Column(String(32), nullable=True, index=True)
    phishing_url = Column(Text, nullable=True)
    normalized_url = Column(Text, nullable=True)
    payment_handle = Column(String(255), nullable=True)
    payment_provider = Column(String(64), nullable=True)
    scam_description = Column(Text, nullable=True)
    report_hash = Column(String(128), nullable=True, index=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    city = Column(String(128), nullable=True)
    state = Column(String(128), nullable=True, index=True)
    country = Column(String(128), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="REPORTED", server_default="REPORTED")
    visibility_status = Column(String(32), nullable=False, default="SUSPICIOUS", server_default="SUSPICIOUS")

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    reported_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
