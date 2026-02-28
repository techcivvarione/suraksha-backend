from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fastapi import HTTPException
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Limit, TIER_PRO, TIER_ULTRA, get_plan_limit, normalize_plan
from app.services.audit_logger import create_audit_log
from app.services.redis_store import (
    acquire_cooldown,
    allow_daily_limit,
    allow_monthly_limit,
    allow_weekly_limit,
    is_cooldown_active,
)
from app.services.upgrade import build_upgrade_response


class LimitType(str, Enum):
    THREAT_DAILY = "THREAT_DAILY"
    EMAIL_MONTHLY = "EMAIL_MONTHLY"
    PASSWORD_MONTHLY = "PASSWORD_MONTHLY"
    QR_WEEKLY = "QR_WEEKLY"
    AI_IMAGE_LIFETIME = "AI_IMAGE_LIFETIME"


_LIMIT_TO_CONFIG: dict[LimitType, dict[str, Any]] = {
    LimitType.THREAT_DAILY: {
        "plan_limit": Limit.THREAT_DAILY,
        "window": "daily",
        "namespace": "plan-limit:threat:daily",
        "feature": "THREAT_SCAN",
    },
    LimitType.EMAIL_MONTHLY: {
        "plan_limit": Limit.EMAIL_MONTHLY,
        "window": "monthly",
        "namespace": "plan-limit:email:monthly",
        "feature": "EMAIL_BREACH_COUNT",
    },
    LimitType.PASSWORD_MONTHLY: {
        "plan_limit": Limit.PASSWORD_MONTHLY,
        "window": "monthly",
        "namespace": "plan-limit:password:monthly",
        "feature": "PASSWORD_SCAN",
    },
    LimitType.QR_WEEKLY: {
        "plan_limit": Limit.QR_WEEKLY,
        "window": "weekly",
        "namespace": "plan-limit:qr:weekly",
        "feature": "QR_UNLIMITED",
    },
    LimitType.AI_IMAGE_LIFETIME: {
        "plan_limit": Limit.AI_IMAGE_LIFETIME,
        "window": "lifetime",
        "feature": "AI_IMAGE_SCAN",
    },
}

_EXCEEDED_COOLDOWN_SECONDS = 60


def _log_plan_limit_exceeded(
    db: Session | None,
    user: Any,
    plan: str,
    feature: str | None,
    endpoint: str,
    limit_type: LimitType,
) -> None:
    if db is None:
        return
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        auto_commit = not bool(db.in_transaction())
        create_audit_log(
            db=db,
            user_id=getattr(user, "id", None),
            event_type="PLAN_LIMIT_EXCEEDED",
            event_description=(
                f"user_id={getattr(user, 'id', None)} "
                f"plan={plan} "
                f"feature={feature or 'UNKNOWN'} "
                f"endpoint={endpoint} "
                f"limit_type={limit_type.value} "
                f"timestamp={timestamp}"
            ),
            auto_commit=auto_commit,
        )
    except Exception:
        # Logging must never block request handling.
        pass


def _raise_plan_limit_exceeded(
    user: Any,
    plan: str,
    limit_type: LimitType,
    limit: int,
    window: str,
    feature: str | None,
    db: Session | None,
    endpoint: str,
    reason: str = "plan_limit_exceeded",
) -> None:
    upgrade = build_upgrade_response(
        user=user,
        reason=reason,
        feature=feature,
        db=db,
        endpoint=endpoint,
    )
    _log_plan_limit_exceeded(db, user, plan, feature, endpoint, limit_type)
    raise HTTPException(
        status_code=429,
        detail={
            "error": {
                "code": "PLAN_LIMIT_EXCEEDED",
                "message": "Plan usage limit reached",
                "plan": plan,
                "limit_type": limit_type.value,
                "window": window,
                "limit": limit,
                "upgrade": upgrade["error"],
            }
        },
    )


def enforce_limit(
    user: Any,
    limit_type: LimitType | str,
    db: Session | None = None,
    endpoint: str | None = None,
) -> None:
    resolved = LimitType(limit_type) if isinstance(limit_type, str) else limit_type
    plan = normalize_plan(getattr(user, "plan", None))
    resolved_endpoint = endpoint or "unknown"

    if plan in {TIER_PRO, TIER_ULTRA}:
        return

    config = _LIMIT_TO_CONFIG[resolved]
    feature = config.get("feature")
    max_allowed = get_plan_limit(plan, config["plan_limit"])
    if max_allowed is None:
        return

    user_id = str(getattr(user, "id", "unknown"))
    cooldown_key_part = feature or resolved.value
    try:
        if is_cooldown_active("plan-limit:cooldown", user_id, cooldown_key_part):
            _raise_plan_limit_exceeded(
                user,
                plan,
                resolved,
                int(max_allowed),
                config["window"],
                feature,
                db,
                resolved_endpoint,
                reason="limit_cooldown_active",
            )
    except RedisError:
        logging.exception("Redis plan limit cooldown check failed for %s", resolved.value)
        raise HTTPException(status_code=503, detail="Rate limiter unavailable")

    if resolved == LimitType.AI_IMAGE_LIFETIME:
        if db is None:
            raise RuntimeError("Database session required for AI_IMAGE_LIFETIME limit enforcement")
        result = db.execute(
            text(
                """
                UPDATE users
                SET ai_image_lifetime_used = ai_image_lifetime_used + 1
                WHERE id = CAST(:uid AS uuid)
                  AND ai_image_lifetime_used < :max_allowed
                """
            ),
            {
                "uid": str(getattr(user, "id")),
                "max_allowed": int(max_allowed),
            },
        )
        if int(result.rowcount or 0) < 1:
            try:
                acquire_cooldown("plan-limit:cooldown", _EXCEEDED_COOLDOWN_SECONDS, user_id, cooldown_key_part)
            except RedisError:
                logging.exception("Redis plan limit cooldown set failed for %s", resolved.value)
                raise HTTPException(status_code=503, detail="Rate limiter unavailable")
            _raise_plan_limit_exceeded(
                user,
                plan,
                resolved,
                max_allowed,
                config["window"],
                feature,
                db,
                resolved_endpoint,
            )
        current_used = int(getattr(user, "ai_image_lifetime_used", 0) or 0)
        setattr(user, "ai_image_lifetime_used", current_used + 1)
        return

    try:
        if config["window"] == "daily":
            allowed = allow_daily_limit(config["namespace"], max_allowed, user_id)
        elif config["window"] == "weekly":
            allowed = allow_weekly_limit(config["namespace"], max_allowed, user_id)
        elif config["window"] == "monthly":
            allowed = allow_monthly_limit(config["namespace"], max_allowed, user_id)
        else:
            raise RuntimeError(f"Unsupported limit window: {config['window']}")
    except RedisError:
        logging.exception("Redis plan limit check failed for %s", resolved.value)
        raise HTTPException(status_code=503, detail="Rate limiter unavailable")

    if not allowed:
        try:
            acquire_cooldown("plan-limit:cooldown", _EXCEEDED_COOLDOWN_SECONDS, user_id, cooldown_key_part)
        except RedisError:
            logging.exception("Redis plan limit cooldown set failed for %s", resolved.value)
            raise HTTPException(status_code=503, detail="Rate limiter unavailable")
        _raise_plan_limit_exceeded(
            user,
            plan,
            resolved,
            max_allowed,
            config["window"],
            feature,
            db,
            resolved_endpoint,
        )
