from datetime import datetime, timedelta

from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import normalize_plan, TIER_PRO, TIER_ULTRA
from app.services.redis_store import allow_sliding_window, acquire_cooldown

# Plan-aware daily caps:  FREE=3/day, GO_PRO=20/day, GO_ULTRA=100/day
_PLAN_DAILY_CAP: dict[str, int] = {
    TIER_PRO:   20,
    TIER_ULTRA: 100,
}
_DEFAULT_DAILY_CAP = 3  # FREE


class AlertRateLimiterError(Exception):
    pass


def enforce_alert_limits(
    db: Session,
    user_id: str,
    ip: str | None = None,
    media_hash: str | None = None,
    plan: str | None = None,
):
    normalized = normalize_plan(plan)
    daily_cap = _PLAN_DAILY_CAP.get(normalized, _DEFAULT_DAILY_CAP)

    try:
        # Hourly cap: always 5 regardless of plan (abuse prevention)
        if not allow_sliding_window("alert:user:hour", 5, 3600, user_id):
            raise AlertRateLimiterError("Hourly alert limit reached")
        # Daily cap: plan-aware
        if not allow_sliding_window("alert:user:day", daily_cap, 86400, user_id):
            raise AlertRateLimiterError("Daily alert limit reached")
        if ip and not allow_sliding_window("alert:ip:minute", 20, 60, ip):
            raise AlertRateLimiterError("Rate limited")
        if media_hash and not acquire_cooldown("alert:media:cooldown", 300, user_id, media_hash):
            raise AlertRateLimiterError("Duplicate alert within cooldown")
    except RedisError as exc:
        if _db_limit_exceeded(db, user_id=user_id, window=timedelta(hours=1), limit=5):
            raise AlertRateLimiterError("Hourly alert limit reached") from exc
        if _db_limit_exceeded(db, user_id=user_id, window=timedelta(days=1), limit=daily_cap):
            raise AlertRateLimiterError("Daily alert limit reached") from exc


def _db_limit_exceeded(db: Session, *, user_id: str, window: timedelta, limit: int) -> bool:
    since = datetime.utcnow() - window
    count = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM alert_events
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= :since
            """
        ),
        {"uid": user_id, "since": since},
    ).scalar()
    return int(count or 0) >= limit
