// SECURE EMAIL OTP START
import datetime

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.sql import func

from app.db import Base


class EmailOtp(Base):
    __tablename__ = "email_otps"

    email = Column(String, primary_key=True)
    otp_hash = Column(String, nullable=False)
    otp_expires_at = Column(DateTime(timezone=True), nullable=False)
    otp_attempts = Column(Integer, nullable=False, default=0)
    otp_locked_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
// SECURE EMAIL OTP END
