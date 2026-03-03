# SECURE EMAIL OTP START
from redis.exceptions import RedisError

from app.services.redis_store import allow_sliding_window, build_hashed_key


EMAIL_LIMIT_PER_10_MIN = 3
EMAIL_WINDOW_SECONDS = 10 * 60

IP_LIMIT_PER_HOUR = 5
IP_WINDOW_SECONDS = 60 * 60


def allow_email_send(email: str) -> bool:
    """
    Sliding window rate limit keyed by normalized email.
    Returns False when limit exceeded or Redis unavailable.
    """
    try:
        return allow_sliding_window(
            "email-otp:email",
            EMAIL_LIMIT_PER_10_MIN,
            EMAIL_WINDOW_SECONDS,
            email.lower().strip(),
        )
    except RedisError:
        # Fail-closed to avoid abuse when Redis is down
        return False


def allow_ip_send(ip: str) -> bool:
    """
    Sliding window rate limit keyed by client IP.
    Returns False when limit exceeded or Redis unavailable.
    """
    try:
        return allow_sliding_window(
            "email-otp:ip",
            IP_LIMIT_PER_HOUR,
            IP_WINDOW_SECONDS,
            ip,
        )
    except RedisError:
        return False
# SECURE EMAIL OTP END
