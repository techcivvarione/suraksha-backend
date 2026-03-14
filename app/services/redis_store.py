from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from redis import Redis

KEY_PREFIX = "gosuraksha"

_redis_client: Redis | None = None


def _require_redis_url() -> str:
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        raise RuntimeError("REDIS_URL not set")
    return redis_url


def get_redis() -> Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(_require_redis_url(), decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
    return _redis_client


def build_hashed_key(namespace: str, *parts: Any) -> str:
    payload = "|".join(str(part) for part in parts)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{KEY_PREFIX}:{namespace}:{digest}"


def _seconds_until_utc_day_end() -> int:
    now = datetime.now(timezone.utc)
    day_end = datetime(now.year, now.month, now.day, 23, 59, 59, tzinfo=timezone.utc)
    return max(1, int((day_end - now).total_seconds()) + 1)


def _seconds_until_utc_week_end() -> int:
    now = datetime.now(timezone.utc)
    next_monday = datetime(now.year, now.month, now.day, tzinfo=timezone.utc) + timedelta(days=7 - now.weekday())
    return max(1, int((next_monday - now).total_seconds()) + 1)


def _seconds_until_utc_month_end() -> int:
    now = datetime.now(timezone.utc)
    if now.month == 12:
        next_month = datetime(year=now.year + 1, month=1, day=1, tzinfo=timezone.utc)
    else:
        next_month = datetime(year=now.year, month=now.month + 1, day=1, tzinfo=timezone.utc)
    return max(1, int((next_month - now).total_seconds()) + 1)


def _bucket_for_period(period: str) -> tuple[str, int]:
    normalized = str(period).strip().lower()
    if normalized == "day":
        return datetime.now(timezone.utc).strftime("%Y%m%d"), _seconds_until_utc_day_end()
    if normalized == "month":
        return datetime.now(timezone.utc).strftime("%Y%m"), _seconds_until_utc_month_end()
    raise ValueError(f"Unsupported limit period: {period}")


def _allow_window_limit_atomic(key: str, limit: int, ttl_seconds: int) -> bool:
    redis = get_redis()
    script = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    if current <= tonumber(ARGV[2]) then
        return 1
    end
    return 0
    """
    allowed = redis.eval(script, 1, key, int(ttl_seconds), int(limit))
    return int(allowed or 0) == 1


def allow_daily_limit(namespace: str, limit: int, *parts: Any) -> bool:
    return _allow_window_limit_atomic(build_hashed_key(namespace, *parts, datetime.now(timezone.utc).strftime("%Y-%m-%d")), limit, _seconds_until_utc_day_end())


def allow_weekly_limit(namespace: str, limit: int, *parts: Any) -> bool:
    now = datetime.now(timezone.utc)
    year, week, _ = now.isocalendar()
    return _allow_window_limit_atomic(build_hashed_key(namespace, *parts, f"{year}-W{week:02d}"), limit, _seconds_until_utc_week_end())


def allow_monthly_limit(namespace: str, limit: int, *parts: Any) -> bool:
    return _allow_window_limit_atomic(build_hashed_key(namespace, *parts, datetime.now(timezone.utc).strftime("%Y-%m")), limit, _seconds_until_utc_month_end())


def acquire_cooldown(namespace: str, cooldown_seconds: int, *parts: Any) -> bool:
    return bool(get_redis().set(build_hashed_key(namespace, *parts), "1", nx=True, ex=cooldown_seconds))


def is_cooldown_active(namespace: str, *parts: Any) -> bool:
    return bool(get_redis().exists(build_hashed_key(namespace, *parts)))


def allow_sliding_window(namespace: str, limit: int, window_seconds: int, *parts: Any) -> bool:
    allowed, _ = consume_sliding_window(namespace, limit, window_seconds, *parts)
    return allowed


def consume_sliding_window(namespace: str, limit: int, window_seconds: int, *parts: Any) -> tuple[bool, int]:
    redis = get_redis()
    key = build_hashed_key(namespace, *parts)
    now_ms = int(time.time() * 1000)
    window_start = now_ms - (window_seconds * 1000)

    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)
    pipe.zcard(key)
    _, current = pipe.execute()
    if int(current or 0) >= limit:
        return False, int(current or 0)

    member = f"{now_ms}:{uuid.uuid4().hex}"
    pipe = redis.pipeline()
    pipe.zadd(key, {member: now_ms})
    pipe.expire(key, window_seconds + 5)
    pipe.execute()
    return True, int(current or 0) + 1


def consume_period_limit(namespace: str, limit: int, period: str, *parts: Any) -> tuple[bool, int]:
    redis = get_redis()
    bucket, ttl_seconds = _bucket_for_period(period)
    key = build_hashed_key(namespace, *parts, bucket)
    script = """
    local current = tonumber(redis.call('GET', KEYS[1]) or '0')
    local limit = tonumber(ARGV[2])
    if current >= limit then
        return {0, current}
    end
    current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return {1, current}
    """
    result = redis.eval(script, 1, key, int(ttl_seconds), int(limit))
    return bool(int(result[0] or 0)), int(result[1] or 0)


def consume_scan_limit(user_id: str, scan_type: str, limit: int, period: str) -> tuple[bool, int]:
    redis = get_redis()
    bucket, ttl_seconds = _bucket_for_period(period)
    key = f"scan:{user_id}:{scan_type}:{bucket}"
    script = """
    local current = tonumber(redis.call('GET', KEYS[1]) or '0')
    local limit = tonumber(ARGV[2])
    if current >= limit then
        return {0, current}
    end
    current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return {1, current}
    """
    result = redis.eval(script, 1, key, int(ttl_seconds), int(limit))
    return bool(int(result[0] or 0)), int(result[1] or 0)


def get_json(namespace: str, *parts: Any) -> dict[str, Any] | None:
    value = get_redis().get(build_hashed_key(namespace, *parts))
    if not value:
        return None
    return json.loads(value)


def set_json(namespace: str, data: dict[str, Any], ttl_seconds: int, *parts: Any) -> None:
    get_redis().set(build_hashed_key(namespace, *parts), json.dumps(data), ex=ttl_seconds)


@contextmanager
def distributed_lock(namespace: str, ttl_seconds: int, *parts: Any) -> Iterator[bool]:
    redis = get_redis()
    key = build_hashed_key(namespace, *parts)
    token = uuid.uuid4().hex
    acquired = bool(redis.set(key, token, nx=True, ex=ttl_seconds))
    try:
        yield acquired
    finally:
        if not acquired:
            return
        script = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """
        redis.eval(script, 1, key, token)
