from redis.exceptions import RedisError

from app.services.redis_store import allow_sliding_window, acquire_cooldown


class AlertRateLimiterError(Exception):
    pass


def enforce_alert_limits(user_id: str, ip: str, media_hash: str):
    try:
        if not allow_sliding_window("alert:user:hour", 5, 3600, user_id):
            raise AlertRateLimiterError("Rate limited")
        if not allow_sliding_window("alert:ip:minute", 20, 60, ip):
            raise AlertRateLimiterError("Rate limited")
        if not acquire_cooldown("alert:media:cooldown", 300, user_id, media_hash):
            raise AlertRateLimiterError("Duplicate alert within cooldown")
    except RedisError as exc:
        # Fail closed for safety
        raise AlertRateLimiterError("Rate limiter unavailable") from exc
