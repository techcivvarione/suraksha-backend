from sqlalchemy import BigInteger, Column, DateTime, Integer, String, Index, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func

from app.db import Base


class AlertEvent(Base):
    __tablename__ = "alert_events"
    __table_args__ = (
        Index("ix_alert_events_user_media_time", "user_id", "media_hash", "created_at"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    media_hash = Column(String(64), nullable=False, index=True)
    analysis_type = Column(String(10), nullable=False)
    risk_score = Column(Integer, nullable=False)
    notified_contact_id = Column(UUID(as_uuid=True), nullable=True)
    status = Column(String(20), nullable=False, server_default=text("'SENT'"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    # STEP 6: richer context columns (nullable — safe for existing rows)
    scan_type = Column(String(20), nullable=True, index=True)      # "THREAT", "EMAIL", "IMAGE"
    risk_level = Column(String(10), nullable=True, index=True)     # "high", "medium", "low"
    extra_signals = Column(JSONB, nullable=True)                   # phishing flags, domain, source
