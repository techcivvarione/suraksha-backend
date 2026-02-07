from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session
from app.db import get_db
from app.models.user import User
from app.services.audit_logger import create_audit_log

router = APIRouter(prefix="/auth", tags=["Auth"])

SECRET_KEY = "207870f96b3161bb3ed2395d7cb3956910976fc6bf4deb2b4a4ac4a3db63a7d3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ---------------- rate limit ----------------
RATE_LIMIT = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


def rate_limit(key: str):
    now = datetime.utcnow().timestamp()
    record = RATE_LIMIT.get(key)

    if not record or now - record["ts"] > WINDOW_SECONDS:
        RATE_LIMIT[key] = {"count": 1, "ts": now}
        return

    record["count"] += 1
    if record["count"] > MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts")


# ---------------- helpers ----------------
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


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id = payload.get("sub")
        iat = payload.get("iat")

        if not user_id or not iat:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        if user.password_changed_at:
            token_issued_at = datetime.fromtimestamp(iat, tz=timezone.utc)

            pwd_changed_at = user.password_changed_at
            if pwd_changed_at.tzinfo is None:
                pwd_changed_at = pwd_changed_at.replace(tzinfo=timezone.utc)

            if token_issued_at < pwd_changed_at:
                raise HTTPException(status_code=401, detail="Session expired")

        return user

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------- models ----------------
class SignupRequest(BaseModel):
    name: str
    email: Optional[str]
    phone: Optional[str]
    role: str
    password: str
    confirm_password: str


class LoginRequest(BaseModel):
    identifier: str
    password: str


# ---------------- routes ----------------
@router.post("/signup")
def signup(payload: SignupRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"signup:{request.client.host}")

    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    exists = (
        db.query(User)
        .filter((User.email == payload.email) | (User.phone == payload.phone))
        .first()
    )
    if exists:
        raise HTTPException(status_code=400, detail="User already exists")

    now = datetime.now(tz=timezone.utc)

    user = User(
        name=payload.name,
        email=payload.email,
        phone=payload.phone,
        role=payload.role,
        password_hash=hash_password(payload.password),
        password_changed_at=now,
    )
    db.add(user)
    db.commit()

    return {"status": "signup_success"}


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"login:{request.client.host}")

    user = (
        db.query(User)
        .filter((User.email == payload.identifier) | (User.phone == payload.identifier))
        .first()
    )

    # ❌ LOGIN FAILED
    if not user or not verify_password(payload.password, user.password_hash):
        create_audit_log(
            db=db,
            user_id=user.id if user else None,
            event_type="LOGIN_FAILED",
            event_description="Failed login attempt",
            request=request
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ✅ LOGIN SUCCESS
    token = create_access_token(str(user.id))

    create_audit_log(
        db=db,
        user_id=user.id,
        event_type="LOGIN_SUCCESS",
        event_description="User logged in successfully",
        request=request
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
    }
