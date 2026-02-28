from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

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
        _redis_client = Redis.from_url(
            _require_redis_url(),
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
    return _redis_client


def build_hashed_key(namespace: str, *parts: Any) -> str:
    payload = "|".join(str(part) for part in parts)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{KEY_PREFIX}:{namespace}:{digest}"


def _seconds_until_utc_day_end() -> int:
    now = datetime.now(timezone.utc)
    day_end = datetime(
        year=now.year,
        month=now.month,
        day=now.day,
        hour=23,
        minute=59,
        second=59,
        tzinfo=timezone.utc,
    )
    return max(1, int((day_end - now).total_seconds()) + 1)


def _seconds_until_utc_week_end() -> int:
    now = datetime.now(timezone.utc)
    days_until_next_monday = 7 - now.weekday()
    next_monday = datetime(
        year=now.year,
        month=now.month,
        day=now.day,
        tzinfo=timezone.utc,
    ) + timedelta(days=days_until_next_monday)
    return max(1, int((next_monday - now).total_seconds()) + 1)


def _seconds_until_utc_month_end() -> int:
    now = datetime.now(timezone.utc)
    if now.month == 12:
        next_month = datetime(year=now.year + 1, month=1, day=1, tzinfo=timezone.utc)
    else:
        next_month = datetime(year=now.year, month=now.month + 1, day=1, tzinfo=timezone.utc)
    return max(1, int((next_month - now).total_seconds()) + 1)


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
    date_bucket = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = build_hashed_key(namespace, *parts, date_bucket)
    return _allow_window_limit_atomic(key, limit, _seconds_until_utc_day_end())


def allow_weekly_limit(namespace: str, limit: int, *parts: Any) -> bool:
    now = datetime.now(timezone.utc)
    year, week, _ = now.isocalendar()
    week_bucket = f"{year}-W{week:02d}"
    key = build_hashed_key(namespace, *parts, week_bucket)
    return _allow_window_limit_atomic(key, limit, _seconds_until_utc_week_end())


def allow_monthly_limit(namespace: str, limit: int, *parts: Any) -> bool:
    month_bucket = datetime.now(timezone.utc).strftime("%Y-%m")
    key = build_hashed_key(namespace, *parts, month_bucket)
    return _allow_window_limit_atomic(key, limit, _seconds_until_utc_month_end())


def acquire_cooldown(namespace: str, cooldown_seconds: int, *parts: Any) -> bool:
    redis = get_redis()
    key = build_hashed_key(namespace, *parts)
    return bool(redis.set(key, "1", nx=True, ex=cooldown_seconds))


def is_cooldown_active(namespace: str, *parts: Any) -> bool:
    redis = get_redis()
    key = build_hashed_key(namespace, *parts)
    return bool(redis.exists(key))


def allow_sliding_window(
    namespace: str,
    limit: int,
    window_seconds: int,
    *parts: Any,
) -> bool:
    redis = get_redis()
    key = build_hashed_key(namespace, *parts)
    now_ms = int(time.time() * 1000)
    window_start = now_ms - (window_seconds * 1000)

    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)
    pipe.zcard(key)
    _, current = pipe.execute()
    if int(current or 0) >= limit:
        return False

    member = f"{now_ms}:{uuid.uuid4().hex}"
    pipe = redis.pipeline()
    pipe.zadd(key, {member: now_ms})
    pipe.expire(key, window_seconds + 5)
    pipe.execute()
    return True


def get_json(namespace: str, *parts: Any) -> dict[str, Any] | None:
    redis = get_redis()
    key = build_hashed_key(namespace, *parts)
    value = redis.get(key)
    if not value:
        return None
    return json.loads(value)


def set_json(namespace: str, data: dict[str, Any], ttl_seconds: int, *parts: Any) -> None:
    redis = get_redis()
    key = build_hashed_key(namespace, *parts)
    redis.set(key, json.dumps(data), ex=ttl_seconds)
