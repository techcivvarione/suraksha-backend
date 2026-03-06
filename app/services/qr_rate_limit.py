from redis.exceptions import RedisError

from app.services.redis_store import allow_sliding_window, acquire_cooldown


# SECURE QR START
def enforce_rate_limits(user_id: str, ip: str, qr_hash: str):
    """
    Raises ValueError on rate limit breach.
    """
    try:
        if not allow_sliding_window("qr:ip", 30, 60, ip):
            raise ValueError("Rate limited (IP)")
        if not allow_sliding_window("qr:user", 60, 300, user_id):
            raise ValueError("Rate limited (user)")
        if not acquire_cooldown("qr:dedupe", 20, user_id, qr_hash):
            raise ValueError("Duplicate request too soon")
    except RedisError:
        # Fail closed: if Redis unavailable, block to be safe
        raise ValueError("Rate limiting unavailable")
# SECURE QR END
