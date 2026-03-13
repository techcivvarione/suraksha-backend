import uuid

from sqlalchemy import Column, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class AttackLocation(Base):
    __tablename__ = "attack_locations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    geohash = Column(String(32), nullable=False, index=True)
    latitude_center = Column(Float, nullable=False)
    longitude_center = Column(Float, nullable=False)
    city = Column(String(128), nullable=True)
    state = Column(String(128), nullable=True, index=True)
    country = Column(String(128), nullable=True, index=True)
    time_window = Column(String(16), nullable=False, index=True)
    report_count = Column(Integer, nullable=False, default=0, server_default="0")
    last_aggregated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
