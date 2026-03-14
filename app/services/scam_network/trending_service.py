from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.redis_store import get_json, set_json

logger = logging.getLogger(__name__)

CACHE_NAMESPACE = "scam:trending"
CACHE_TTL_SECONDS = 120
MAX_TRENDING_ITEMS = 20


def fetch_trending_categories(db: Session, *, time_window: str, limit: int) -> list[dict]:
    safe_limit = max(1, min(limit, MAX_TRENDING_ITEMS))
    cache_key = (time_window, safe_limit)
    cached = _read_cache(*cache_key)
    if cached is not None:
        return cached

    since = _since_for_window(time_window)
    rows = db.execute(
        text(
            """
            WITH counts AS (
                SELECT
                    COALESCE(category, 'unknown') AS category,
                    COUNT(*) AS count
                FROM scam_reports
                WHERE created_at >= :since
                GROUP BY COALESCE(category, 'unknown')
            ),
            ranked AS (
                SELECT
                    category,
                    count,
                    ROW_NUMBER() OVER (ORDER BY count DESC, category) AS row_num
                FROM counts
            )
            SELECT category, count
            FROM ranked
            WHERE row_num <= :limit
            ORDER BY count DESC, category
            """
        ),
        {"since": since, "limit": safe_limit},
    ).mappings().all()
    trending = [
        {
            "category": str(row["category"]),
            "count": int(row["count"] or 0),
        }
        for row in rows
    ]
    _write_cache(trending, *cache_key)
    return trending


def _read_cache(time_window: str, limit: int) -> list[dict] | None:
    try:
        cached = get_json(CACHE_NAMESPACE, time_window, limit)
    except (RedisError, RuntimeError):
        logger.warning("scam_trending_cache_read_failed", exc_info=True)
        return None
    if not cached:
        return None
    trending = cached.get("trending")
    return trending if isinstance(trending, list) else None


def _write_cache(trending: list[dict], time_window: str, limit: int) -> None:
    try:
        set_json(CACHE_NAMESPACE, {"trending": trending}, CACHE_TTL_SECONDS, time_window, limit)
    except (RedisError, RuntimeError):
        logger.warning("scam_trending_cache_write_failed", exc_info=True)


def _since_for_window(time_window: str) -> datetime:
    now = datetime.now(timezone.utc)
    mapping = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    return now - mapping[time_window]
