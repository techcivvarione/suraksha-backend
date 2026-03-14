from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.redis_store import get_json, set_json

logger = logging.getLogger(__name__)

CACHE_NAMESPACE = "scam:heatmap"
CACHE_TTL_SECONDS = 60
MAX_HEATMAP_POINTS = 500


def fetch_heatmap_points(
    db: Session,
    *,
    scope: str,
    time_window: str,
    category: str | None,
    limit: int,
) -> list[dict]:
    safe_limit = max(1, min(limit, MAX_HEATMAP_POINTS))
    cache_key = (scope, time_window, category or "all", safe_limit)
    cached = _read_cache(*cache_key)
    if cached is not None:
        return cached

    since = _since_for_window(time_window)
    rows = db.execute(
        text(_query_for_scope(scope)),
        {"since": since, "category": category, "limit": safe_limit},
    ).mappings().all()
    points = [
        {
            "lat": float(row["lat"]),
            "lng": float(row["lng"]),
            "count": int(row["count"] or 0),
            "verified": bool(row["verified"]),
            "category_breakdown": {
                str(key): int(value)
                for key, value in dict(row["category_breakdown"] or {}).items()
            },
        }
        for row in rows
    ]
    _write_cache(points, *cache_key)
    return points


def _read_cache(scope: str, time_window: str, category: str, limit: int) -> list[dict] | None:
    try:
        cached = get_json(CACHE_NAMESPACE, scope, time_window, category, limit)
    except (RedisError, RuntimeError):
        logger.warning("scam_heatmap_cache_read_failed", exc_info=True)
        return None
    if not cached:
        return None
    points = cached.get("points")
    return points if isinstance(points, list) else None


def _write_cache(points: list[dict], scope: str, time_window: str, category: str, limit: int) -> None:
    try:
        set_json(
            CACHE_NAMESPACE,
            {"points": points},
            CACHE_TTL_SECONDS,
            scope,
            time_window,
            category,
            limit,
        )
    except (RedisError, RuntimeError):
        logger.warning("scam_heatmap_cache_write_failed", exc_info=True)


def _since_for_window(time_window: str) -> datetime:
    now = datetime.now(timezone.utc)
    mapping = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    return now - mapping[time_window]


def _query_for_scope(scope: str) -> str:
    if scope == "global":
        return _global_query()
    if scope == "city":
        return _regional_query(
            region_filter="city IS NOT NULL",
            region_key_columns="city_key, state_key, country_key",
            category_group_columns="city_key, state_key, country_key, category",
            join_condition="cc.city_key = rr.city_key AND cc.state_key = rr.state_key AND cc.country_key = rr.country_key",
            group_by_columns="rr.city_key, rr.state_key, rr.country_key, rr.lat, rr.lng, rr.count",
        )
    if scope == "state":
        return _regional_query(
            region_filter="state IS NOT NULL",
            region_key_columns="state_key, country_key",
            category_group_columns="state_key, country_key, category",
            join_condition="cc.state_key = rr.state_key AND cc.country_key = rr.country_key",
            group_by_columns="rr.state_key, rr.country_key, rr.lat, rr.lng, rr.count",
        )
    return _regional_query(
        region_filter="country IS NOT NULL",
        region_key_columns="country_key",
        category_group_columns="country_key, category",
        join_condition="cc.country_key = rr.country_key",
        group_by_columns="rr.country_key, rr.lat, rr.lng, rr.count",
    )


def _global_query() -> str:
    return """
        WITH filtered AS (
            SELECT
                ROUND(latitude::numeric, 2) AS lat,
                ROUND(longitude::numeric, 2) AS lng,
                COALESCE(category, 'unknown') AS category,
                TRUE AS verified
            FROM scam_reports
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
              AND created_at >= :since
              AND (:category IS NULL OR category = :category)

            UNION ALL

            SELECT
                ROUND(latitude::numeric, 2) AS lat,
                ROUND(longitude::numeric, 2) AS lng,
                COALESCE(category, 'unknown') AS category,
                FALSE AS verified
            FROM scam_events
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
              AND created_at >= :since
              AND (:category IS NULL OR category = :category)
        ),
        category_counts AS (
            SELECT
                lat,
                lng,
                category,
                COUNT(*) AS category_count,
                BOOL_OR(verified) AS verified
            FROM filtered
            GROUP BY lat, lng, category
        ),
        point_totals AS (
            SELECT
                lat,
                lng,
                SUM(category_count) AS count,
                BOOL_OR(verified) AS verified
            FROM category_counts
            GROUP BY lat, lng
        ),
        ranked_points AS (
            SELECT
                lat,
                lng,
                count,
                verified,
                ROW_NUMBER() OVER (ORDER BY count DESC, lat, lng) AS point_rank
            FROM point_totals
        )
        SELECT
            rp.lat,
            rp.lng,
            rp.count,
            rp.verified,
            JSONB_OBJECT_AGG(cc.category, cc.category_count) AS category_breakdown
        FROM ranked_points rp
        JOIN category_counts cc
          ON cc.lat = rp.lat AND cc.lng = rp.lng
        WHERE rp.point_rank <= :limit
        GROUP BY rp.lat, rp.lng, rp.count, rp.verified
        ORDER BY rp.count DESC, rp.lat, rp.lng
    """


def _regional_query(
    *,
    region_filter: str,
    region_key_columns: str,
    category_group_columns: str,
    join_condition: str,
    group_by_columns: str,
) -> str:
    return f"""
        WITH filtered AS (
            SELECT
                latitude,
                longitude,
                COALESCE(category, 'unknown') AS category,
                COALESCE(city, '') AS city_key,
                COALESCE(state, '') AS state_key,
                COALESCE(country, '') AS country_key
            FROM scam_reports
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
              AND created_at >= :since
              AND (:category IS NULL OR category = :category)
              AND {region_filter}
        ),
        region_centers AS (
            SELECT
                {region_key_columns},
                ROUND(AVG(latitude)::numeric, 4) AS lat,
                ROUND(AVG(longitude)::numeric, 4) AS lng,
                COUNT(*) AS count
            FROM filtered
            GROUP BY {region_key_columns}
        ),
        ranked_regions AS (
            SELECT
                {region_key_columns},
                lat,
                lng,
                count,
                ROW_NUMBER() OVER (ORDER BY count DESC, lat, lng) AS point_rank
            FROM region_centers
        ),
        category_counts AS (
            SELECT
                {category_group_columns},
                COUNT(*) AS category_count
            FROM filtered
            GROUP BY {category_group_columns}
        )
        SELECT
            rr.lat,
            rr.lng,
            rr.count,
            TRUE AS verified,
            JSONB_OBJECT_AGG(cc.category, cc.category_count) AS category_breakdown
        FROM ranked_regions rr
        JOIN category_counts cc
          ON {join_condition}
        WHERE rr.point_rank <= :limit
        GROUP BY {group_by_columns}
        ORDER BY rr.count DESC, rr.lat, rr.lng
    """
