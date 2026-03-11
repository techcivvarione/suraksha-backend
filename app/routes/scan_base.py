import uuid
import logging

from fastapi import Depends, HTTPException

from app.core.features import TIER_PRO, TIER_ULTRA, normalize_plan
from app.routes.auth import get_current_user
from app.services.rate_limit import RateLimitError, check_rate_limit, enforce_rate_limit

logger = logging.getLogger(__name__)


def require_user(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def generate_scan_id() -> uuid.UUID:
    return uuid.uuid4()


def build_scan_error(error: str, message: str) -> dict:
    return {
        "success": False,
        "error": error,
        "message": message,
    }


def raise_scan_error(status_code: int, error: str, message: str) -> None:
    raise HTTPException(status_code=status_code, detail=build_scan_error(error, message))


def is_unlimited_scan_plan(user) -> bool:
    return normalize_plan(getattr(user, "plan", None)) in {TIER_PRO, TIER_ULTRA}


def apply_rate_limit(namespace: str, limit: int, window_seconds: int, *keys: str):
    try:
        enforce_rate_limit(namespace, limit, window_seconds, *keys)
    except RateLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc))


def apply_scan_rate_limits(
    *,
    current_user,
    endpoint: str,
    client_ip: str,
    user_namespace: str,
    user_limit: int,
    ip_namespace: str,
    ip_limit: int,
) -> None:
    user_id = str(current_user.id)
    plan = normalize_plan(getattr(current_user, "plan", None))

    if is_unlimited_scan_plan(current_user):
        logger.info(
            "scan_limit_check user=%s plan=%s endpoint=%s allowed=true scan_count=%s limit=%s",
            user_id,
            plan,
            endpoint,
            0,
            "unlimited",
            extra={
                "scan_event": "scan_limit_check",
                "user_id": user_id,
                "plan": plan,
                "endpoint": endpoint,
                "allowed": True,
                "scan_count": 0,
                "limit": None,
            },
        )
        return

    for namespace, limit, key, scope in (
        (user_namespace, user_limit, user_id, "user"),
        (ip_namespace, ip_limit, client_ip, "ip"),
    ):
        try:
            result = check_rate_limit(namespace, limit, 3600, key)
        except RateLimitError:
            raise_scan_error(503, "SCAN_LIMIT_CHECK_FAILED", "Scan limit check is temporarily unavailable.")

        logger.info(
            "scan_limit_check user=%s plan=%s endpoint=%s scope=%s allowed=%s scan_count=%s limit=%s",
            user_id,
            plan,
            endpoint,
            scope,
            result.allowed,
            result.count,
            result.limit,
            extra={
                "scan_event": "scan_limit_check",
                "user_id": user_id,
                "plan": plan,
                "endpoint": endpoint,
                "scope": scope,
                "allowed": result.allowed,
                "scan_count": result.count,
                "limit": result.limit,
            },
        )
        if not result.allowed:
            message = (
                "Free scan limit reached."
                if scope == "user"
                else "Too many scan requests from this network. Please try later."
            )
            raise_scan_error(429, "SCAN_LIMIT_REACHED", message)
