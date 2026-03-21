import uuid
import logging
from dataclasses import dataclass

from fastapi import Depends, HTTPException

from app.core.features import TIER_FREE, TIER_PRO, TIER_ULTRA, normalize_plan
from app.routes.auth import get_current_user
from redis.exceptions import RedisError

from app.services.redis_store import allow_sliding_window, consume_scan_limit, consume_sliding_window

logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    pass


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: int
    limit: int


def enforce_rate_limit(namespace: str, limit: int, window_seconds: int, *key_parts: str):
    try:
        allowed = allow_sliding_window(namespace, limit, window_seconds, *key_parts)
    except RedisError:
        raise RateLimitError("Rate limiter unavailable")
    if not allowed:
        raise RateLimitError("Rate limited")


def check_rate_limit(namespace: str, limit: int, window_seconds: int, *key_parts: str) -> RateLimitResult:
    try:
        allowed, count = consume_sliding_window(namespace, limit, window_seconds, *key_parts)
    except RedisError:
        raise RateLimitError("Rate limiter unavailable")
    return RateLimitResult(allowed=allowed, count=count, limit=limit)


def check_scan_limit(user_id: str, scan_type: str, limit: int, period: str) -> RateLimitResult:
    try:
        allowed, count = consume_scan_limit(user_id, scan_type, limit, period)
    except RedisError:
        raise RateLimitError("Rate limiter unavailable")
    return RateLimitResult(allowed=allowed, count=count, limit=limit)


def _log_scan_limit_check(
    *,
    user_id: str,
    scan_type: str | None,
    plan: str,
    count: int,
    limit,
    allowed: bool,
    endpoint: str | None = None,
    scope: str | None = None,
) -> None:
    logger.info(
        "scan_limit_check",
        extra={
            "scan_event": "scan_limit_check",
            "user_id": user_id,
            "scan_type": scan_type,
            "plan": plan,
            "count": count,
            "limit": limit,
            "allowed": allowed,
            "endpoint": endpoint,
            "scope": scope,
        },
    )


def require_user(user=Depends(get_current_user)):
    if not user:
        logger.warning("authentication_failure", extra={"error": "INVALID_TOKEN", "path": "scan_guard"})
        raise HTTPException(status_code=401, detail={"error": "INVALID_TOKEN", "message": "Authentication required"})
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
    return normalize_plan(getattr(user, "plan", None)) == TIER_ULTRA


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
    plan_limit_policy: str | None = None,
    scan_type: str | None = None,
) -> None:
    user_id = str(current_user.id)
    plan = normalize_plan(getattr(current_user, "plan", None))

    if plan_limit_policy == "plan_quota":
        resolved_scan_type = scan_type or endpoint.strip("/").replace("/", "_")

        # PRO and ULTRA are fully unlimited — return immediately
        if plan in {TIER_PRO, TIER_ULTRA}:
            _log_scan_limit_check(
                user_id=user_id,
                scan_type=resolved_scan_type,
                plan=plan,
                count=0,
                limit=None,
                allowed=True,
                endpoint=endpoint,
            )
            return

        # FREE: per-scan-type windows
        scan_key = resolved_scan_type.lower()

        # image lifetime is enforced separately via enforce_limit in the route
        if scan_key == "image":
            return

        _FREE_PERIOD_CONFIG: dict[str, tuple[str, int]] = {
            "threat":   ("day",  1),
            "email":    ("week", 1),
            "password": ("week", 1),
            "qr":       ("week", 1),
        }
        pc = _FREE_PERIOD_CONFIG.get(scan_key)
        if pc is None:
            # Unknown scan type — allow through
            return

        period, limit = pc

        try:
            result = check_scan_limit(user_id, resolved_scan_type, limit, period)
        except RateLimitError:
            raise_scan_error(503, "SCAN_LIMIT_CHECK_FAILED", "Scan limit check is temporarily unavailable.")

        _log_scan_limit_check(
            user_id=user_id,
            scan_type=resolved_scan_type,
            plan=plan,
            count=result.count,
            limit=result.limit,
            allowed=result.allowed,
            endpoint=endpoint,
        )
        if not result.allowed:
            raise_scan_error(429, "SCAN_LIMIT_REACHED", "Free scan limit reached. Upgrade to continue.")
        return

    if plan in {TIER_PRO, TIER_ULTRA}:
        _log_scan_limit_check(
            user_id=user_id,
            scan_type=scan_type or endpoint.strip("/").replace("/", "_"),
            plan=plan,
            count=0,
            limit=None,
            allowed=True,
            endpoint=endpoint,
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

        _log_scan_limit_check(
            user_id=user_id,
            scan_type=scan_type or endpoint.strip("/").replace("/", "_"),
            plan=plan,
            count=result.count,
            limit=result.limit,
            allowed=result.allowed,
            endpoint=endpoint,
            scope=scope,
        )
        if not result.allowed:
            message = (
                "Free scan limit reached."
                if scope == "user"
                else "Too many scan requests from this network. Please try later."
            )
            raise_scan_error(429, "SCAN_LIMIT_REACHED", message)
