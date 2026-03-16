from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models.phone_otp import PhoneOtp
from app.models.user import User
from app.routes import auth
from app.services import phone_otp_service, sms_service


@pytest.fixture
def db_session(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[User.__table__, PhoneOtp.__table__])
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = Session()
    monkeypatch.setattr(phone_otp_service, "get_redis", lambda: (_ for _ in ()).throw(RuntimeError("redis unavailable")))
    monkeypatch.setattr(sms_service, "OTP_HASH_SECRET", "test-secret")
    yield session
    session.close()


def test_hash_otp_depends_on_phone_and_otp(monkeypatch):
    monkeypatch.setattr(sms_service, "OTP_HASH_SECRET", "test-secret")
    first = sms_service.hash_otp("919876543210", "123456")
    second = sms_service.hash_otp("919876543210", "654321")
    third = sms_service.hash_otp("918888888888", "123456")
    assert first != second
    assert first != third


def test_verify_phone_otp_rejects_expired(db_session):
    record = PhoneOtp(
        phone_number="919876543210",
        otp_hash=sms_service.hash_otp("919876543210", "123456"),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        attempts=0,
    )
    db_session.add(record)
    db_session.commit()

    with pytest.raises(HTTPException) as exc:
        phone_otp_service.verify_phone_otp(db_session, "919876543210", "123456")

    assert exc.value.detail["error_code"] == "OTP_EXPIRED"


def test_verify_phone_otp_enforces_attempt_limit(db_session):
    record = PhoneOtp(
        phone_number="919876543210",
        otp_hash=sms_service.hash_otp("919876543210", "123456"),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=3),
        attempts=4,
    )
    db_session.add(record)
    db_session.commit()

    with pytest.raises(HTTPException) as exc:
        phone_otp_service.verify_phone_otp(db_session, "919876543210", "000000")

    assert exc.value.detail["error_code"] == "OTP_ATTEMPTS_EXCEEDED"


def test_create_phone_otp_rate_limits_with_db_fallback(db_session, monkeypatch):
    monkeypatch.setattr(phone_otp_service, "generate_otp", lambda: "123456")

    for _ in range(3):
        db_session.add(
            PhoneOtp(
                phone_number="919876543210",
                otp_hash="existing",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=3),
                attempts=0,
            )
        )
    db_session.commit()

    with pytest.raises(HTTPException) as exc:
        phone_otp_service.create_phone_otp(db_session, "919876543210")

    assert exc.value.status_code == 429
    assert exc.value.detail["error_code"] == "OTP_RATE_LIMITED"


def test_verify_phone_otp_flow_creates_user(db_session):
    record = PhoneOtp(
        phone_number="919876543210",
        otp_hash=sms_service.hash_otp("919876543210", "123456"),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=3),
        attempts=0,
    )
    db_session.add(record)
    db_session.commit()

    normalized_phone = phone_otp_service.verify_phone_otp(db_session, "919876543210", "123456")
    user = auth._resolve_phone_user_identity(db_session, phone=normalized_phone)

    assert user.phone_number == "919876543210"
    assert user.phone_verified is True
    assert db_session.query(PhoneOtp).count() == 0


def test_verify_phone_otp_flow_reuses_existing_user(db_session):
    existing_user = User(
        name="Existing",
        email="existing@example.com",
        email_verified=True,
        phone_number="919876543210",
        phone_verified=False,
        password_hash="hash",
        auth_provider="email",
        plan="FREE",
        subscription_status="ACTIVE",
        token_version=0,
    )
    db_session.add(existing_user)
    db_session.commit()

    user = auth._resolve_phone_user_identity(db_session, phone="919876543210")

    assert user.id == existing_user.id
    assert user.phone_verified is True
    assert user.auth_provider == "phone"


def test_verify_phone_otp_links_authenticated_google_user_without_creating_duplicate(db_session):
    existing_google_user = User(
        name="Google User",
        email="google@example.com",
        email_verified=True,
        phone_number=None,
        phone_verified=False,
        password_hash="hash",
        auth_provider="google",
        google_sub="google-sub-1",
        plan="FREE",
        subscription_status="ACTIVE",
        token_version=0,
    )
    db_session.add(existing_google_user)
    db_session.commit()

    user = auth._resolve_phone_user_identity(db_session, phone="919876543210", current_user=existing_google_user)

    assert user.id == existing_google_user.id
    assert user.phone_number == "919876543210"
    assert user.phone_verified is True
    assert db_session.query(User).count() == 1
