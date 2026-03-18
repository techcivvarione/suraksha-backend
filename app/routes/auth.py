from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy import func, inspect, text
from sqlalchemy.orm import Session

from app.core.features import TIER_FREE, normalize_plan
from app.db import get_db
from app.models.email_otp import EmailOtp
from app.models.user import User
from app.schemas.auth import (
    AuthMeResponse,
    DeleteAccountRequest,
    GoogleLoginRequest,
    LoginResponse,
    SendPhoneOtpRequest,
    SignupRequest,
    VerifyPhoneOtpRequest,
)
from app.services.audit_logger import create_audit_log
from app.services.email_otp_rate_limiter import allow_email_send, allow_ip_send
from app.services.email_service import send_otp_email
from app.services.phone_otp_service import create_phone_otp, normalize_phone, verify_phone_otp
from app.services.sms_service import SMSDeliveryError, send_sms
from app.services.subscription import maybe_auto_downgrade_expired_subscription

router = APIRouter(prefix="/auth", tags=["Auth"])
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
OTP_SECRET_SALT = os.getenv("OTP_SECRET_SALT")
if not OTP_SECRET_SALT:
    raise RuntimeError("OTP_SECRET_SALT not set in environment")

OTP_EXPIRY_MINUTES = 5
OTP_LENGTH = 6
OTP_MAX_ATTEMPTS = 5
OTP_LOCK_MINUTES = 15
OTP_MIN_RESPONSE_MS = 300
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}

security = HTTPBearer()
security_optional = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str
    password: str


class SendEmailOtpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class VerifyEmailOtpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    otp: str


class GoogleAuthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id_token: str


GENERIC_SEND_RESPONSE = {"message": "If the email is valid, an OTP has been sent."}
GENERIC_VERIFY_FAILURE = {"success": False, "message": "Verification failed."}


def rate_limit(key: str, db: Session) -> None:
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    namespaced_key = f"gosuraksha:rate:auth:{key_hash}"
    now = datetime.now(tz=timezone.utc)
    window_start = now - timedelta(seconds=WINDOW_SECONDS)
    count = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM auth_rate_limits
            WHERE key = :key
              AND attempt_time >= :window_start
            """
        ),
        {"key": namespaced_key, "window_start": window_start},
    ).scalar()
    if count >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
    db.execute(text("INSERT INTO auth_rate_limits (key) VALUES (:key)"), {"key": namespaced_key})
    db.commit()


def _generate_otp() -> str:
    return str(secrets.randbelow(10**OTP_LENGTH)).zfill(OTP_LENGTH)


def _hash_otp(raw_otp: str) -> str:
    return hashlib.sha256(f"{OTP_SECRET_SALT}:{raw_otp}".encode("utf-8")).hexdigest()


def _ensure_min_delay(start_time: float) -> None:
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    remaining = OTP_MIN_RESPONSE_MS - elapsed_ms
    if remaining > 0:
        time.sleep(remaining / 1000)


def _compare_otp(stored_hash: str, provided_otp: str) -> bool:
    return hmac.compare_digest(stored_hash, _hash_otp(provided_otp))


def _normalize_email(email: EmailStr | str | None) -> str | None:
    if email is None:
        return None
    normalized = str(email).strip().lower()
    return normalized or None


def _effective_token_version(user: User | object) -> int:
    return int(getattr(user, "token_version", 0) or 0)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must include an uppercase letter")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must include a number")
    if not re.search(r"[^\w\s]", password):
        raise HTTPException(status_code=400, detail="Password must include a special character")


def invalidate_user_sessions(user: User) -> None:
    user.token_version = _effective_token_version(user) + 1
    user.updated_at = datetime.utcnow()


def create_access_token(user: User) -> str:
    now = datetime.now(tz=timezone.utc)
    issued_at = int(now.timestamp())
    expiration = int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp())
    token_version = _effective_token_version(user)
    payload = {
        "sub": str(user.id),
        "user_id": str(user.id),
        "email": user.email,
        "plan": user.plan,
        "tv": token_version,
        "token_version": token_version,
        "iat": issued_at,
        "issued_at": issued_at,
        "exp": expiration,
        "expiration": expiration,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _auth_error(error: str, message: str, status_code: int = 401) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error_code": error, "message": message})


def _touch_last_login(db: Session, user: User, provider: str) -> User:
    user.last_login = datetime.now(tz=timezone.utc)
    user.auth_provider = provider
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _token_response(user: User, *, needs_phone_verification: bool, include_terms: bool = False) -> dict:
    payload = {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "needs_phone_verification": needs_phone_verification,
    }
    if include_terms:
        payload["needs_terms_acceptance"] = not bool(getattr(user, "accepted_terms", False))
    return payload


def _auth_user_payload(user: User) -> dict:
    return {
        "id": str(user.id),
        "name": getattr(user, "name", None),
        "email": getattr(user, "email", None),
        "phone": _read_user_phone(user),
        "phone_verified": bool(getattr(user, "phone_verified", False)),
        "profile_image_url": getattr(user, "profile_image_url", None),
        "plan": normalize_plan(getattr(user, "plan", None)),
    }


def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    return _resolve_current_user(request=request, credentials=credentials, db=db, required=True)


def get_current_user_optional(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional), db: Session = Depends(get_db)):
    return _resolve_current_user(request=request, credentials=credentials, db=db, required=False)


def _load_user_with_token_version(db: Session, user_id: str) -> User | None:
    row = (
        db.query(User, func.coalesce(User.token_version, 0).label("effective_token_version"))
        .filter(User.id == user_id)
        .first()
    )
    if not row:
        return None
    user, effective_token_version = row
    user.token_version = int(effective_token_version or 0)
    return user


def _existing_table_names(db: Session) -> set[str]:
    bind = db.get_bind()
    return set(inspect(bind).get_table_names())


def _delete_account_related_data(db: Session, *, user_id: str) -> None:
    existing_tables = _existing_table_names(db)
    delete_statements: list[tuple[str, dict[str, str]]] = []

    if "trusted_alerts" in existing_tables and "trusted_contacts" in existing_tables:
        delete_statements.append(
            (
                """
                DELETE FROM trusted_alerts
                WHERE contact_id IN (
                    SELECT id
                    FROM trusted_contacts
                    WHERE owner_user_id = CAST(:user_id AS uuid)
                       OR contact_user_id = CAST(:user_id AS uuid)
                )
                """,
                {"user_id": user_id},
            )
        )

    if "family_alerts" in existing_tables:
        delete_statements.append(
            (
                """
                DELETE FROM family_alerts
                WHERE family_head_user_id = CAST(:user_id AS uuid)
                   OR member_user_id = CAST(:user_id AS uuid)
                """,
                {"user_id": user_id},
            )
        )

    if "trusted_contacts" in existing_tables:
        delete_statements.append(
            (
                """
                DELETE FROM trusted_contacts
                WHERE owner_user_id = CAST(:user_id AS uuid)
                   OR contact_user_id = CAST(:user_id AS uuid)
                """,
                {"user_id": user_id},
            )
        )

    for table_name in (
        "alert_events",
        "audit_logs",
        "qr_reports",
        "qr_scan_logs",
        "scan_history",
        "scan_jobs",
        "scam_reports",
        "subscription_events",
        "user_devices",
    ):
        if table_name in existing_tables:
            delete_statements.append(
                (
                    f"DELETE FROM {table_name} WHERE user_id = CAST(:user_id AS uuid)",
                    {"user_id": user_id},
                )
            )

    for statement, params in delete_statements:
        db.execute(text(statement), params)


def _find_user_by_email_exact(db: Session, email: str | None) -> User | None:
    normalized_email = _normalize_email(email)
    if not normalized_email:
        return None
    return db.query(User).filter(func.lower(User.email) == normalized_email).first()


def _find_login_user(db: Session, identifier: str) -> User | None:
    return _find_user_by_email_exact(db, identifier)


def _find_user_by_google_sub(db: Session, google_sub: str) -> User | None:
    return db.query(User).filter(User.google_sub == google_sub).first()


def _read_user_phone(user: User | object) -> str | None:
    return getattr(user, "phone", None) or getattr(user, "phone_number", None)


def _find_user_by_phone_exact(db: Session, phone: str) -> User | None:
    return db.query(User).filter(User.phone == phone).first()


def _resolve_phone_user_identity(db: Session, *, phone: str, current_user: User | None = None) -> tuple[User, bool]:
    existing_user = _find_user_by_phone_exact(db, phone)
    if existing_user:
        existing_user.phone_verified = True
        return _touch_last_login(db, existing_user, "phone"), False

    if current_user is not None:
        current_user.phone = phone
        current_user.phone_verified = True
        return _touch_last_login(db, current_user, current_user.auth_provider or "phone"), False

    temp_pwd = secrets.token_urlsafe(32)
    now = datetime.now(tz=timezone.utc)
    user = User(
        name=f"User {phone[-4:]}",
        email=None,
        email_verified=False,
        phone=phone,
        phone_verified=True,
        plan=TIER_FREE,
        subscription_status="ACTIVE",
        subscription_expires_at=None,
        auth_provider="phone",
        password_hash=hash_password(temp_pwd),
        password_changed_at=now,
        token_version=0,
        last_login=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, True


def _resolve_google_user_identity(db: Session, *, google_sub: str, email: str, name: str | None) -> User:
    user = _find_user_by_google_sub(db, google_sub)
    if user:
        if email and not getattr(user, "email", None):
            user.email = email
        user.email_verified = True
        if name and not getattr(user, "name", None):
            user.name = name
        return _touch_last_login(db, user, "google")

    existing_email_user = _find_user_by_email_exact(db, email)
    if existing_email_user:
        existing_email_user.google_sub = google_sub
        existing_email_user.email = email
        existing_email_user.email_verified = True
        if name and not getattr(existing_email_user, "name", None):
            existing_email_user.name = name
        return _touch_last_login(db, existing_email_user, "google")

    temp_pwd = secrets.token_urlsafe(32)
    now = datetime.now(tz=timezone.utc)
    user = User(
        name=name or "Google User",
        email=email,
        email_verified=True,
        phone=None,
        phone_verified=False,
        plan=TIER_FREE,
        subscription_status="ACTIVE",
        subscription_expires_at=None,
        auth_provider="google",
        google_sub=google_sub,
        password_hash=hash_password(temp_pwd),
        password_changed_at=now,
        token_version=0,
        last_login=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _resolve_current_user(request: Request, credentials: Optional[HTTPAuthorizationCredentials], db: Session, required: bool):
    if credentials is None:
        if required:
            raise _auth_error("INVALID_TOKEN", "Invalid token")
        return None

    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id") or payload.get("sub")
        issued_at = payload.get("issued_at", payload.get("iat"))
        token_version = payload.get("token_version", payload.get("tv"))
        if not user_id or issued_at is None or token_version is None:
            raise _auth_error("INVALID_TOKEN", "Invalid token")

        user = _load_user_with_token_version(db, str(user_id))
        if not user:
            raise _auth_error("INVALID_TOKEN", "Invalid token")
        if int(token_version) != _effective_token_version(user):
            raise _auth_error("TOKEN_EXPIRED", "Token expired")

        if user.password_changed_at:
            issued_at_dt = datetime.fromtimestamp(int(issued_at), tz=timezone.utc)
            pwd_changed = user.password_changed_at if user.password_changed_at.tzinfo else user.password_changed_at.replace(tzinfo=timezone.utc)
            if issued_at_dt < pwd_changed:
                raise _auth_error("TOKEN_EXPIRED", "Token expired")

        user = maybe_auto_downgrade_expired_subscription(db=db, user=user, request=request)
        request.state.user = user
        return user
    except ExpiredSignatureError:
        if required:
            raise _auth_error("TOKEN_EXPIRED", "Token expired")
        return None
    except JWTError:
        if required:
            raise _auth_error("INVALID_TOKEN", "Invalid token")
        return None


@router.post("/send-email-otp")
def send_email_otp(payload: SendEmailOtpRequest, request: Request, db: Session = Depends(get_db)):
    normalized_email = _normalize_email(payload.email)
    client_ip = request.client.host or "unknown"
    if not (allow_email_send(normalized_email) and allow_ip_send(client_ip)):
        return GENERIC_SEND_RESPONSE

    otp = _generate_otp()
    otp_hash = _hash_otp(otp)
    expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)
    with db.begin():
        existing = db.query(EmailOtp).with_for_update(nowait=False).filter(EmailOtp.email == normalized_email).one_or_none()
        if existing is None:
            db.add(EmailOtp(email=normalized_email, otp_hash=otp_hash, otp_expires_at=expires_at, otp_attempts=0, otp_locked_until=None))
        else:
            existing.otp_hash = otp_hash
            existing.otp_expires_at = expires_at
            existing.otp_attempts = 0
            existing.otp_locked_until = None
    try:
        send_otp_email(email=normalized_email, otp=otp)
    except Exception:
        logger.exception("otp_email_send_failed")
    return GENERIC_SEND_RESPONSE


@router.post("/verify-email-otp")
def verify_email_otp(payload: VerifyEmailOtpRequest, request: Request, db: Session = Depends(get_db)):
    start_time = time.perf_counter()
    normalized_email = _normalize_email(payload.email)
    provided_otp = payload.otp.strip()
    if len(provided_otp) != OTP_LENGTH or not provided_otp.isdigit():
        _ensure_min_delay(start_time)
        return GENERIC_VERIFY_FAILURE

    response_payload = GENERIC_VERIFY_FAILURE
    with db.begin():
        record = db.query(EmailOtp).with_for_update(nowait=False).filter(EmailOtp.email == normalized_email).one_or_none()
        now = datetime.now(tz=timezone.utc)
        if record is None:
            response_payload = GENERIC_VERIFY_FAILURE
        elif record.otp_locked_until and record.otp_locked_until > now:
            response_payload = {"success": False, "message": "Too many attempts. Try again later."}
        elif record.otp_expires_at < now:
            response_payload = GENERIC_VERIFY_FAILURE
        elif not _compare_otp(record.otp_hash, provided_otp):
            record.otp_attempts += 1
            if record.otp_attempts >= OTP_MAX_ATTEMPTS:
                record.otp_locked_until = now + timedelta(minutes=OTP_LOCK_MINUTES)
            response_payload = GENERIC_VERIFY_FAILURE
        else:
            db.delete(record)
            response_payload = {"success": True}
    _ensure_min_delay(start_time)
    return response_payload


@router.post("/send-phone-otp")
def send_phone_otp(payload: SendPhoneOtpRequest, db: Session = Depends(get_db)):
    normalized_phone = normalize_phone(payload.phone)
    otp = create_phone_otp(db, normalized_phone)
    try:
        send_sms(normalized_phone, otp)
    except SMSDeliveryError:
        logger.exception("phone_otp_sms_failed", extra={"phone": normalized_phone[-4:]})
        raise HTTPException(
            status_code=502,
            detail={"error_code": "SMS_SEND_FAILED", "message": "Unable to send OTP"},
        )
    return {"message": "OTP sent"}


@router.post("/verify-phone-otp")
def verify_phone_otp_login(
    payload: VerifyPhoneOtpRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    normalized_phone = verify_phone_otp(db, payload.phone, payload.otp)
    user, is_new_user = _resolve_phone_user_identity(db, phone=normalized_phone, current_user=current_user)
    logger.info("auth.phone_login", extra={"user_id": str(user.id), "phone_suffix": normalized_phone[-4:]})
    create_audit_log(db=db, user_id=user.id, event_type="PHONE_OTP_LOGIN_SUCCESS", event_description="User logged in with phone OTP", request=request)
    payload = _token_response(user, needs_phone_verification=False)
    payload["user"] = _auth_user_payload(user)
    payload["is_new_user"] = is_new_user
    return payload


@router.post("/signup")
def signup(payload: SignupRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"signup:{request.client.host}", db)
    if not payload.accepted_terms:
        raise HTTPException(status_code=400, detail="You must accept the Privacy Policy and Terms of Service to create an account.")
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    validate_password_strength(payload.password)
    normalized_email = _normalize_email(payload.email)
    normalized_phone = normalize_phone(payload.phone or payload.phone_number or "")
    exists = db.query(User).filter((func.lower(User.email) == normalized_email) | (User.phone == normalized_phone)).first()
    if exists:
        raise HTTPException(status_code=400, detail={"error_code": "DUPLICATE_ACCOUNT", "message": "User already exists"})

    now = datetime.now(tz=timezone.utc)
    user = User(
        name=payload.name,
        email=normalized_email,
        email_verified=False,
        phone=normalized_phone,
        phone_verified=False,
        plan=TIER_FREE,
        subscription_status="ACTIVE",
        subscription_expires_at=None,
        auth_provider="email",
        password_hash=hash_password(payload.password),
        password_changed_at=now,
        accepted_terms=True,
        accepted_terms_at=now,
        terms_version=payload.terms_version or "v1",
        privacy_version=payload.privacy_version or "v1",
        token_version=0,
        last_login=None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    if user.email:
        db.execute(
            text(
                """
                UPDATE trusted_contacts
                SET contact_user_id = :uid
                WHERE contact_user_id IS NULL
                  AND contact_email = :email
                """
            ),
            {"uid": str(user.id), "email": user.email},
        )
        db.commit()
    logger.info("auth.signup", extra={"user_id": str(user.id)})
    return {"status": "signup_success"}


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"login:{request.client.host}", db)
    user = _find_login_user(db, payload.identifier)
    if not user or not verify_password(payload.password, user.password_hash):
        create_audit_log(db=db, user_id=user.id if user else None, event_type="LOGIN_FAILED", event_description="Failed login attempt", request=request)
        raise HTTPException(status_code=401, detail={"error_code": "INVALID_CREDENTIALS", "message": "Invalid credentials"})

    if not bool(getattr(user, "phone_verified", False)):
        raise HTTPException(status_code=403, detail={"error_code": "PHONE_VERIFICATION_REQUIRED", "message": "Phone verification required"})

    user = _touch_last_login(db, user, "email")
    logger.info("auth.email_login", extra={"user_id": str(user.id)})
    create_audit_log(db=db, user_id=user.id, event_type="LOGIN_SUCCESS", event_description="User logged in", request=request)
    return _token_response(user, needs_phone_verification=False, include_terms=True)


def _verify_google_identity_token(token_value: str) -> dict:
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=503, detail={"error_code": "GOOGLE_AUTH_NOT_CONFIGURED", "message": "Google auth not configured"})
    try:
        idinfo = id_token.verify_oauth2_token(token_value, google_requests.Request(), GOOGLE_CLIENT_ID)
    except Exception:
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_GOOGLE_TOKEN", "message": "Invalid Google token"})

    issuer = str(idinfo.get("iss") or "").strip()
    google_sub = str(idinfo.get("sub") or "").strip()
    email = _normalize_email(idinfo.get("email") or "")
    name = idinfo.get("name") or (email.split("@")[0] if email else None)
    email_verified = bool(idinfo.get("email_verified"))
    if issuer not in GOOGLE_ISSUERS:
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_GOOGLE_TOKEN", "message": "Invalid Google token issuer"})
    if not google_sub:
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_GOOGLE_TOKEN", "message": "Invalid Google token subject"})
    if not email or not email_verified:
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_GOOGLE_TOKEN", "message": "Email not verified by Google"})
    return {"google_sub": google_sub, "email": email, "name": name}


def _handle_google_login(*, google_token: str, request: Request, db: Session) -> dict:
    identity = _verify_google_identity_token(google_token)
    user = _resolve_google_user_identity(db, **identity)
    needs_phone_verification = not bool(getattr(user, "phone_verified", False))
    logger.info("auth.google_login", extra={"user_id": str(user.id), "needs_phone_verification": needs_phone_verification})
    create_audit_log(db=db, user_id=user.id, event_type="GOOGLE_LOGIN_SUCCESS", event_description="User logged in with Google", request=request)
    payload = _token_response(user, needs_phone_verification=needs_phone_verification)
    payload["user"] = _auth_user_payload(user)
    payload["phone_verified"] = bool(getattr(user, "phone_verified", False))
    return payload


@router.post("/google-login")
def google_login(payload: GoogleLoginRequest, request: Request, db: Session = Depends(get_db)):
    return _handle_google_login(google_token=payload.google_id_token, request=request, db=db)


@router.post("/delete-account")
def delete_account(
    payload: DeleteAccountRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.confirm_username != current_user.name:
        raise HTTPException(status_code=400, detail="Confirmation name does not match")

    user_id = str(current_user.id)
    try:
        invalidate_user_sessions(current_user)
        db.add(current_user)
        _delete_account_related_data(db, user_id=user_id)
        db.delete(current_user)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logger.exception("auth.delete_account_failed", extra={"user_id": user_id})
        raise HTTPException(status_code=500, detail="Unable to delete account")

    logger.info("User %s deleted account", user_id, extra={"user_id": user_id, "path": request.url.path})
    return {"status": "success", "message": "Account deleted permanently"}


@router.post("/google")
def google_auth(payload: GoogleAuthRequest, request: Request, db: Session = Depends(get_db)):
    return _handle_google_login(google_token=payload.id_token, request=request, db=db)


@router.get("/me", response_model=AuthMeResponse)
def me(current_user: User = Depends(get_current_user)):
    phone = _read_user_phone(current_user)
    subscription_expires_at = getattr(current_user, "subscription_expires_at", None)
    plan = normalize_plan(getattr(current_user, "plan", None))
    subscription_status = getattr(current_user, "subscription_status", None) or ("FREE" if plan == TIER_FREE else "ACTIVE")
    return {
        "id": str(current_user.id),
        "name": getattr(current_user, "name", None),
        "email": getattr(current_user, "email", None),
        "phone": phone,
        "plan": plan,
        "profile_image_url": getattr(current_user, "profile_image_url", None),
        "token_version": _effective_token_version(current_user),
        "subscription_status": subscription_status,
        "subscription_expires_at": subscription_expires_at.isoformat() if hasattr(subscription_expires_at, "isoformat") and subscription_expires_at is not None else None,
    }
