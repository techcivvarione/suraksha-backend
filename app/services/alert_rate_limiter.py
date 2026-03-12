from datetime import datetime, timedelta

from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.redis_store import allow_sliding_window, acquire_cooldown


class AlertRateLimiterError(Exception):
    pass


def enforce_alert_limits(db: Session, user_id: str, ip: str | None = None, media_hash: str | None = None):
    try:
        if not allow_sliding_window("alert:user:hour", 5, 3600, user_id):
            raise AlertRateLimiterError("Hourly alert limit reached")
        if not allow_sliding_window("alert:user:day", 20, 86400, user_id):
            raise AlertRateLimiterError("Daily alert limit reached")
        if ip and not allow_sliding_window("alert:ip:minute", 20, 60, ip):
            raise AlertRateLimiterError("Rate limited")
        if media_hash and not acquire_cooldown("alert:media:cooldown", 300, user_id, media_hash):
            raise AlertRateLimiterError("Duplicate alert within cooldown")
    except RedisError as exc:
        if _db_limit_exceeded(db, user_id=user_id, window=timedelta(hours=1), limit=5):
            raise AlertRateLimiterError("Hourly alert limit reached") from exc
        if _db_limit_exceeded(db, user_id=user_id, window=timedelta(days=1), limit=20):
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
