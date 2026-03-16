from __future__ import annotations

import hmac
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from app.models.phone_otp import PhoneOtp
from app.services.redis_store import get_redis
from app.services.sms_service import generate_otp, hash_otp


OTP_EXPIRY_MINUTES = 3
OTP_MAX_ATTEMPTS = 5
OTP_REQUEST_LIMIT = 3
OTP_REQUEST_WINDOW_SECONDS = 10 * 60
PHONE_PATTERN = re.compile(r"^\d{10,15}$")


def normalize_phone(phone: str) -> str:
    normalized = re.sub(r"\D", "", phone or "")
    if len(normalized) == 10:
        normalized = f"91{normalized}"
    if not PHONE_PATTERN.match(normalized):
        raise HTTPException(
            status_code=400,
            detail={"error_code": "INVALID_PHONE", "message": "Invalid phone number"},
        )
    return normalized


def _rate_limit_key(phone: str) -> str:
    return f"otp:{phone}"


def _enforce_send_rate_limit(db: Session, phone: str) -> None:
    key = _rate_limit_key(phone)
    try:
        redis = get_redis()
        current = redis.incr(key)
        if current == 1:
            redis.expire(key, OTP_REQUEST_WINDOW_SECONDS)
        if int(current or 0) > OTP_REQUEST_LIMIT:
            raise HTTPException(
                status_code=429,
                detail={"error_code": "OTP_RATE_LIMITED", "message": "Too many OTP requests"},
            )
        return
    except RuntimeError:
        pass
    except RedisError:
        pass

    window_start = datetime.now(timezone.utc) - timedelta(seconds=OTP_REQUEST_WINDOW_SECONDS)
    recent = (
        db.query(PhoneOtp)
        .filter(PhoneOtp.phone_number == phone, PhoneOtp.created_at >= window_start)
        .count()
    )
    if recent >= OTP_REQUEST_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={"error_code": "OTP_RATE_LIMITED", "message": "Too many OTP requests"},
        )


def create_phone_otp(db: Session, phone: str) -> str:
    normalized_phone = normalize_phone(phone)
    _enforce_send_rate_limit(db, normalized_phone)

    otp = generate_otp()
    record = PhoneOtp(
        phone_number=normalized_phone,
        otp_hash=hash_otp(normalized_phone, otp),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES),
        attempts=0,
    )
    db.add(record)
    db.commit()
    return otp


def verify_phone_otp(db: Session, phone: str, otp: str) -> str:
    normalized_phone = normalize_phone(phone)
    record = (
        db.query(PhoneOtp)
        .filter(PhoneOtp.phone_number == normalized_phone)
        .order_by(PhoneOtp.created_at.desc())
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=400,
            detail={"error_code": "INVALID_OTP", "message": "Invalid OTP"},
        )

    now = datetime.now(timezone.utc)
    expires_at = record.expires_at if record.expires_at.tzinfo else record.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        db.delete(record)
        db.commit()
        raise HTTPException(
            status_code=400,
            detail={"error_code": "OTP_EXPIRED", "message": "OTP expired"},
        )

    if int(record.attempts or 0) >= OTP_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail={"error_code": "OTP_ATTEMPTS_EXCEEDED", "message": "Too many attempts"},
        )

    expected_hash = hash_otp(normalized_phone, otp.strip())
    if not hmac.compare_digest(record.otp_hash, expected_hash):
        record.attempts = int(record.attempts or 0) + 1
        db.add(record)
        db.commit()
        if record.attempts >= OTP_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail={"error_code": "OTP_ATTEMPTS_EXCEEDED", "message": "Too many attempts"},
            )
        raise HTTPException(
            status_code=400,
            detail={"error_code": "INVALID_OTP", "message": "Invalid OTP"},
        )

    db.query(PhoneOtp).filter(PhoneOtp.phone_number == normalized_phone).delete()
    db.commit()
    return normalized_phone
