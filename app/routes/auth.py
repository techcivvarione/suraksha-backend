from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict
from typing import Optional
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.core.features import TIER_FREE
from app.models.user import User
from app.services.audit_logger import create_audit_log
from app.services.subscription import maybe_auto_downgrade_expired_subscription

router = APIRouter(prefix="/auth", tags=["Auth"])

import os

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()
security_optional = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

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


# ---------------- PASSWORD / TOKEN ----------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(subject: str):
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ---------------- AUTH DEPENDENCY ----------------
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
    if credentials is None:
        if required:
            raise HTTPException(status_code=401, detail="Invalid token")
        return None

    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id = payload.get("sub")
        iat = payload.get("iat")

        if not user_id or not iat:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        if user.password_changed_at:
            issued_at = datetime.fromtimestamp(iat, tz=timezone.utc)
            pwd_changed = user.password_changed_at.replace(tzinfo=timezone.utc)
            if issued_at < pwd_changed:
                raise HTTPException(status_code=401, detail="Session expired")

        user = maybe_auto_downgrade_expired_subscription(db=db, user=user, request=request)
        return user

    except JWTError:
        if required:
            raise HTTPException(status_code=401, detail="Invalid token")
        return None


# ---------------- REQUEST MODELS ----------------
class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    email: Optional[str]
    phone: Optional[str]
    password: str
    confirm_password: str


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str
    password: str


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
@router.post("/signup")
def signup(payload: SignupRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"signup:{request.client.host}", db)

    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    validate_password_strength(payload.password)

    exists = db.query(User).filter(
        (User.email == payload.email) | (User.phone == payload.phone)
    ).first()
    if exists:
        raise HTTPException(status_code=400, detail="User already exists")

    now = datetime.now(tz=timezone.utc)

    user = User(
        name=payload.name,
        email=payload.email,
        phone=payload.phone,
        role="USER",
        plan=TIER_FREE,
        subscription_status="ACTIVE",
        subscription_expires_at=None,
        password_hash=hash_password(payload.password),
        password_changed_at=now,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

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
        (User.email == payload.identifier) | (User.phone == payload.identifier)
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

    token = create_access_token(str(user.id))

    create_audit_log(
        db=db,
        user_id=user.id,
        event_type="LOGIN_SUCCESS",
        event_description="User logged in",
        request=request,
    )

    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "phone": current_user.phone,
        "role": current_user.role,
        "plan": current_user.plan,
        "subscription_status": current_user.subscription_status,
        "subscription_expires_at": current_user.subscription_expires_at,
    }
