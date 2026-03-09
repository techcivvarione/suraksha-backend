import hashlib
import logging
from typing import Optional

import requests
from redis.exceptions import RedisError

from app.services.redis_store import get_redis, build_hashed_key

HIBP_URL = "https://api.pwnedpasswords.com/range/{}"
TIMEOUT_SECONDS = 5
CACHE_TTL = 24 * 3600  # 1 day

logger = logging.getLogger(__name__)


def _cache_get(prefix: str) -> Optional[str]:
    try:
        redis = get_redis()
        key = build_hashed_key("pwned:range", prefix)
        return redis.get(key)
    except RedisError:
        return None


def _cache_set(prefix: str, value: str):
    try:
        redis = get_redis()
        key = build_hashed_key("pwned:range", prefix)
        redis.set(key, value, ex=CACHE_TTL)
    except RedisError:
        return


def check_password_pwned(password: str) -> int:
    """
    Returns breach count from HIBP Pwned Passwords using k-anonymity.
    - Sends only SHA1 prefix.
    - Full hash never leaves server.
    - On failure, returns 0 (safe fallback).
    """
    if not password:
        return 0

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    cached = _cache_get(prefix)
    body = cached

    if cached is None:
        try:
            resp = requests.get(
                HIBP_URL.format(prefix),
                headers={"User-Agent": "gosuraksha/1.0"},
                timeout=TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            body = resp.text
            _cache_set(prefix, body)
        except Exception as exc:
            logger.warning("HIBP lookup failed: %s", exc)
            return 0

    for line in (body or "").splitlines():
        if ":" not in line:
            continue
        suf, count = line.split(":")
        if suf.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0
