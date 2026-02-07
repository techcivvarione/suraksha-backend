import uuid
from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class ScamReport(Base):
    __tablename__ = "scam_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False)

    scam_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)

    source = Column(String(255))
    scam_value = Column(String(50))

    ip_address = Column(String(45))
    user_agent = Column(Text)

    reported_at = Column(DateTime(timezone=True), server_default=func.now())
