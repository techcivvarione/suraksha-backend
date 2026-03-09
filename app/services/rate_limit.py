from redis.exceptions import RedisError

from app.services.redis_store import allow_sliding_window


class RateLimitError(Exception):
    pass


def enforce_rate_limit(namespace: str, limit: int, window_seconds: int, *key_parts: str):
    """
    Sliding-window rate limit using Redis.
    Raises RateLimitError on deny or redis failure (fail closed).
    """
    try:
        allowed = allow_sliding_window(namespace, limit, window_seconds, *key_parts)
    except RedisError:
        raise RateLimitError("Rate limiter unavailable")
    if not allowed:
        raise RateLimitError("Rate limited")
