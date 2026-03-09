import uuid
from fastapi import Depends, HTTPException

from app.routes.auth import get_current_user
from app.services.rate_limit import enforce_rate_limit, RateLimitError


def require_user(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def generate_scan_id() -> uuid.UUID:
    return uuid.uuid4()


def apply_rate_limit(namespace: str, limit: int, window_seconds: int, *keys: str):
    try:
        enforce_rate_limit(namespace, limit, window_seconds, *keys)
    except RateLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc))
