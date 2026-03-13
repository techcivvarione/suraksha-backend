from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, EmailStr
from typing import Optional
from passlib.context import CryptContext
from jose import ExpiredSignatureError, jwt, JWTError
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import hmac
import os
import secrets
import time
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.core.features import TIER_FREE
from app.models.user import User
from app.models.email_otp import EmailOtp
from app.schemas.auth import SignupRequest
from app.services.audit_logger import create_audit_log
from app.services.subscription import maybe_auto_downgrade_expired_subscription
from app.services.email_service import send_otp_email
from app.services.email_otp_rate_limiter import allow_email_send, allow_ip_send

router = APIRouter(prefix="/auth", tags=["Auth"])
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()
security_optional = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ---------------- SECURE EMAIL OTP CONFIG ----------------
OTP_SECRET_SALT = os.getenv("OTP_SECRET_SALT")
if not OTP_SECRET_SALT:
    raise RuntimeError("OTP_SECRET_SALT not set in environment")

OTP_EXPIRY_MINUTES = 5
OTP_LENGTH = 6
OTP_MAX_ATTEMPTS = 5
OTP_LOCK_MINUTES = 15
OTP_MIN_RESPONSE_MS = 300

# ---------------- RATE LIMIT CONFIG ----------------
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


# ---------------- RATE LIMIT (DB-BASED) ----------------
def rate_limit(key: str, db: Session):
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    namespaced_key = f"gosuraksha:rate:auth:{key_hash}"
    now = datetime.now(tz=timezone.utc)
    window_start = now - timedelta(seconds=WINDOW_SECONDS)

    # Count attempts inside window
    count = db.execute(
        text("""
            SELECT COUNT(*)
            FROM auth_rate_limits
            WHERE key = :key
              AND attempt_time >= :window_start
        """),
        {
            "key": namespaced_key,
            "window_start": window_start
        }
    ).scalar()

    if count >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Please try again later."
        )

    # Insert new attempt
    db.execute(
        text("""
            INSERT INTO auth_rate_limits (key)
            VALUES (:key)
        """),
        {"key": namespaced_key}
    )

    db.commit()


# ---------------- SECURE EMAIL OTP HELPERS ----------------
def _generate_otp() -> str:
    number = secrets.randbelow(10**OTP_LENGTH)
    return str(number).zfill(OTP_LENGTH)


def _hash_otp(raw_otp: str) -> str:
    payload = f"{OTP_SECRET_SALT}:{raw_otp}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ensure_min_delay(start_time: float):
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    remaining = OTP_MIN_RESPONSE_MS - elapsed_ms
    if remaining > 0:
        time.sleep(remaining / 1000)


def _compare_otp(stored_hash: str, provided_otp: str) -> bool:
    candidate_hash = _hash_otp(provided_otp)
    return hmac.compare_digest(stored_hash, candidate_hash)


def _normalize_email(email: EmailStr) -> str:
    return email.strip().lower()


GENERIC_SEND_RESPONSE = {"message": "If the email is valid, an OTP has been sent."}
GENERIC_VERIFY_FAILURE = {"success": False, "message": "Verification failed."}


# ---------------- PASSWORD / TOKEN ----------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(user: User):
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "plan": user.plan,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ---------------- AUTH DEPENDENCY ----------------
def _redact_auth_header(raw_header: str | None) -> str | None:
    if not raw_header:
        return None
    if not raw_header.startswith("Bearer "):
        return raw_header[:24]
    token = raw_header[7:]
    return f"Bearer {token[:12]}..." if token else "Bearer <empty>"


def _auth_error(error: str, message: str, status_code: int = 401) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "error": error,
            "message": message,
        },
    )


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    return _resolve_current_user(request=request, credentials=credentials, db=db, required=True)


def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional),
    db: Session = Depends(get_db),
):
    return _resolve_current_user(request=request, credentials=credentials, db=db, required=False)


def _resolve_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
    db: Session,
    required: bool,
):
    auth_header = request.headers.get("authorization")
    logger.info(
        "auth_token_received",
        extra={
            "path": request.url.path,
            "authorization_header": _redact_auth_header(auth_header),
            "has_authorization": bool(auth_header),
            "scheme": getattr(credentials, "scheme", None),
        },
    )

    if credentials is None:
        if required:
            logger.warning("auth_missing_credentials", extra={"path": request.url.path})
            raise _auth_error("INVALID_TOKEN", "Invalid token")
        return None

    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.info(
            "jwt_payload_decoded",
            extra={
                "path": request.url.path,
                "user_id": payload.get("sub"),
                "jwt_payload": {
                    "sub": payload.get("sub"),
                    "email": payload.get("email"),
                    "plan": payload.get("plan"),
                    "iat": payload.get("iat"),
                    "exp": payload.get("exp"),
                },
            },
        )

        user_id = payload.get("sub")
        iat = payload.get("iat")

        if not user_id or not iat:
            logger.warning("auth_payload_missing_claims", extra={"path": request.url.path, "jwt_payload": payload})
            raise _auth_error("INVALID_TOKEN", "Invalid token")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.warning("auth_user_not_found", extra={"path": request.url.path, "user_id": user_id})
            raise _auth_error("INVALID_TOKEN", "Invalid token")

        if user.password_changed_at:
            issued_at = datetime.fromtimestamp(iat, tz=timezone.utc)
            pwd_changed = user.password_changed_at.replace(tzinfo=timezone.utc)
            if issued_at < pwd_changed:
                logger.warning("auth_session_expired", extra={"path": request.url.path, "user_id": user_id})
                raise _auth_error("TOKEN_EXPIRED", "Token expired")

        user = maybe_auto_downgrade_expired_subscription(db=db, user=user, request=request)
        request.state.user = user
        logger.info("auth_user_resolved", extra={"path": request.url.path, "user_id": str(user.id)})
        return user

    except ExpiredSignatureError:
        logger.warning("auth_token_expired", extra={"path": request.url.path})
        if required:
            raise _auth_error("TOKEN_EXPIRED", "Token expired")
        return None
    except JWTError:
        logger.warning("auth_token_invalid", extra={"path": request.url.path})
        if required:
            raise _auth_error("INVALID_TOKEN", "Invalid token")
        return None


# ---------------- REQUEST MODELS ----------------
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str
    password: str


# SECURE EMAIL OTP START
class SendEmailOtpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr


class VerifyEmailOtpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    otp: str
# SECURE EMAIL OTP END


class GoogleAuthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id_token: str


# ---------------- PASSWORD STRENGTH ----------------
import re

def validate_password_strength(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must include an uppercase letter")

    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must include a number")

    if not re.search(r"[^\w\s]", password):
        raise HTTPException(status_code=400, detail="Password must include a special character")


# ---------------- ROUTES ----------------
# SECURE EMAIL OTP START
@router.post("/send-email-otp")
def send_email_otp(payload: SendEmailOtpRequest, request: Request, db: Session = Depends(get_db)):
    normalized_email = _normalize_email(payload.email)
    client_ip = request.client.host or "unknown"

    email_allowed = allow_email_send(normalized_email)
    ip_allowed = allow_ip_send(client_ip)
    if not (email_allowed and ip_allowed):
        return GENERIC_SEND_RESPONSE

    otp = _generate_otp()
    otp_hash = _hash_otp(otp)
    expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)

    with db.begin():
        existing = (
            db.query(EmailOtp)
            .with_for_update(nowait=False)
            .filter(EmailOtp.email == normalized_email)
            .one_or_none()
        )
        if existing is None:
            record = EmailOtp(
                email=normalized_email,
                otp_hash=otp_hash,
                otp_expires_at=expires_at,
                otp_attempts=0,
                otp_locked_until=None,
            )
            db.add(record)
        else:
            existing.otp_hash = otp_hash
            existing.otp_expires_at = expires_at
            existing.otp_attempts = 0
            existing.otp_locked_until = None

    # Do not log OTP; email content only.
    try:
        send_otp_email(email=normalized_email, otp=otp)
        email_hash = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()[:10]
        logger.info("otp email sent", extra={"email_hash": email_hash})
    except Exception:
        logger.error("OTP email send failed for %s", normalized_email)

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
        record = (
            db.query(EmailOtp)
            .with_for_update(nowait=False)
            .filter(EmailOtp.email == normalized_email)
            .one_or_none()
        )

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
    if response_payload.get("success"):
        email_hash = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()[:10]
        logger.info("otp verified", extra={"email_hash": email_hash})
    return response_payload
# SECURE EMAIL OTP END

@router.post("/signup")
def signup(payload: SignupRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"signup:{request.client.host}", db)

    if not payload.accepted_terms:
        raise HTTPException(
            status_code=400,
            detail="You must accept the Privacy Policy and Terms of Service to create an account.",
        )

    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    validate_password_strength(payload.password)

    exists = db.query(User).filter(
        (User.email == payload.email) | (User.phone_number == payload.phone_number)
    ).first()
    if exists:
        raise HTTPException(status_code=400, detail="User already exists")

    now = datetime.now(tz=timezone.utc)

    user = User(
        name=payload.name,
        email=payload.email,
        phone_number=payload.phone_number,
        plan=TIER_FREE,
        subscription_status="ACTIVE",
        subscription_expires_at=None,
        password_hash=hash_password(payload.password),
        password_changed_at=now,
        accepted_terms=True,
        accepted_terms_at=now,
        terms_version=payload.terms_version or "v1",
        privacy_version=payload.privacy_version or "v1",
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(
        "terms_accepted",
        extra={
            "user_email": payload.email,
            "version": payload.terms_version or "v1",
            "privacy_version": payload.privacy_version or "v1",
        },
    )

    if user.email:
        db.execute(
            text("""
                UPDATE trusted_contacts
                SET contact_user_id = :uid
                WHERE contact_user_id IS NULL
                  AND contact_email = :email
            """),
            {
                "uid": str(user.id),
                "email": user.email,
            },
        )
        db.commit()

    return {"status": "signup_success"}


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"login:{request.client.host}", db)

    user = db.query(User).filter(
        (User.email == payload.identifier) | (User.phone_number == payload.identifier)
    ).first()

    if not user or not verify_password(payload.password, user.password_hash):
        create_audit_log(
            db=db,
            user_id=user.id if user else None,
            event_type="LOGIN_FAILED",
            event_description="Failed login attempt",
            request=request,
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not getattr(user, "accepted_terms", False):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "TERMS_REQUIRED",
                "message": "You must accept the Privacy Policy and Terms of Service to continue.",
            },
        )

    token = create_access_token(user)

    create_audit_log(
        db=db,
        user_id=user.id,
        event_type="LOGIN_SUCCESS",
        event_description="User logged in",
        request=request,
    )

    return {"access_token": token, "token_type": "bearer"}


@router.post("/google")
def google_auth(payload: GoogleAuthRequest, request: Request, db: Session = Depends(get_db)):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=503, detail="Google auth not configured")
    try:
        idinfo = id_token.verify_oauth2_token(payload.id_token, google_requests.Request(), GOOGLE_CLIENT_ID)
    except Exception:
        logger.warning("google login failure: invalid token")
        raise HTTPException(status_code=400, detail="Invalid Google token")

    email = idinfo.get("email")
    name = idinfo.get("name") or (email.split("@")[0] if email else None)
    picture = idinfo.get("picture")
    email_verified = idinfo.get("email_verified")

    if not email or not email_verified:
        logger.warning("google login failure: email not verified")
        raise HTTPException(status_code=400, detail="Email not verified by Google")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        temp_pwd = secrets.token_hex(16)
        user = User(
            name=name or "Google User",
            email=email,
            phone_number=None,
            plan="FREE",
            auth_provider="google",
            password_hash=hash_password(temp_pwd),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token(user)
    logger.info("google login success", extra={"user_id": str(user.id), "email_hash": hashlib.sha256(email.encode()).hexdigest()[:10]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "phone_number": user.phone_number,
            "plan": user.plan,
            "auth_provider": getattr(user, "auth_provider", "google"),
            "picture": picture,
        },
    }


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "phone_number": current_user.phone_number,
        "plan": current_user.plan,
        "subscription_status": current_user.subscription_status,
        "subscription_expires_at": current_user.subscription_expires_at,
    }
