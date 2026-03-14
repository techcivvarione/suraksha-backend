import uuid

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base
from app.enums.user_plan import UserPlan


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    name = Column(String, nullable=False)
    email = Column(String, unique=True)
    phone_number = Column(String(20), nullable=True, index=True)

    password_hash = Column(String, nullable=False)
    auth_provider = Column(String, nullable=False, default="password")
    token_version = Column(Integer, nullable=False, default=0, server_default="0")

    plan = Column(String, nullable=False, default=UserPlan.FREE.value)
    subscription_status = Column(String, nullable=False, default="ACTIVE")
    subscription_expires_at = Column(DateTime(timezone=True), nullable=True)
    last_subscription_event_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    password_changed_at = Column(DateTime(timezone=True), nullable=True)

    preferred_language = Column(String, nullable=False, default="en", server_default="en")
    ai_image_lifetime_used = Column(Integer, nullable=False, default=0, server_default="0")
    first_upgrade_used = Column(Boolean, nullable=False, default=False, server_default="false")
    accepted_terms = Column(Boolean, nullable=False, default=False, server_default="false")
    accepted_terms_at = Column(DateTime(timezone=True), nullable=True)
    terms_version = Column(String, nullable=True)
    privacy_version = Column(String, nullable=True)
