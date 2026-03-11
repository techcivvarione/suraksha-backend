from dataclasses import dataclass

from redis.exceptions import RedisError

from app.services.redis_store import allow_sliding_window, consume_sliding_window


class RateLimitError(Exception):
    pass


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: int
    limit: int


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


def check_rate_limit(namespace: str, limit: int, window_seconds: int, *key_parts: str) -> RateLimitResult:
    try:
        allowed, count = consume_sliding_window(namespace, limit, window_seconds, *key_parts)
    except RedisError:
        raise RateLimitError("Rate limiter unavailable")
    return RateLimitResult(allowed=allowed, count=count, limit=limit)
