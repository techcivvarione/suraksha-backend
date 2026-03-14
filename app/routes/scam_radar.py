from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request
from redis.exceptions import RedisError
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from app.db import SessionLocal
from app.schemas.scam_network import ScamRadarLiveResponse
from app.services.redis_store import consume_sliding_window, get_redis

router = APIRouter(prefix="/scam", tags=["Scam Radar"])
logger = logging.getLogger(__name__)

RADAR_CACHE_TTL_SECONDS = 5
DEFAULT_LIMIT = 200
MAX_LIMIT = 500


@router.get("/radar/live", response_model=ScamRadarLiveResponse, summary="Get live scam radar events")
async def get_live_scam_radar(
    request: Request,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
):
    logger.info("radar_requests", extra={"limit": limit})
    _enforce_radar_rate_limit(request=request)

    cache_key = f"radar_live_{limit}"
    cached = _read_cache(cache_key)
    if cached is not None:
        logger.info("cache_hits", extra={"cache": "radar_live", "limit": limit})
        return ScamRadarLiveResponse(**cached)

    try:
        events = await run_in_threadpool(_fetch_live_radar_events, limit)
    except Exception:
        logger.exception("scam_radar_live_failed")
        raise HTTPException(status_code=500, detail="Unable to load live scam radar")

    payload = {
        "events": events,
        "count": len(events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _write_cache(cache_key, payload)
    return ScamRadarLiveResponse(**payload)


def _fetch_live_radar_events(limit: int) -> list[dict]:
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT latitude, longitude, category, source, created_at
                FROM (
                    SELECT latitude, longitude, category, source, created_at
                    FROM scan_events
                    WHERE created_at > now() - interval '30 minutes'
                      AND latitude IS NOT NULL
                      AND longitude IS NOT NULL

                    UNION ALL

                    SELECT latitude, longitude, category, source, created_at
                    FROM scam_events
                    WHERE created_at > now() - interval '30 minutes'
                      AND latitude IS NOT NULL
                      AND longitude IS NOT NULL
                ) radar_events
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).mappings().all()
        return [
            {
                "lat": float(row["latitude"]),
                "lng": float(row["longitude"]),
                "category": row["category"],
                "source": row["source"],
            }
            for row in rows
        ]
    finally:
        db.close()


def _read_cache(cache_key: str) -> dict | None:
    try:
        value = get_redis().get(cache_key)
    except (RedisError, RuntimeError):
        logger.warning("scam_radar_cache_unavailable", exc_info=True)
        return None
    if not value:
        return None
    import json

    return json.loads(value)


def _write_cache(cache_key: str, payload: dict) -> None:
    try:
        import json

        get_redis().set(cache_key, json.dumps(payload), ex=RADAR_CACHE_TTL_SECONDS)
    except (RedisError, RuntimeError):
        logger.warning("scam_radar_cache_write_failed", exc_info=True)


def _enforce_radar_rate_limit(*, request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    try:
        allowed, _ = consume_sliding_window("scam:radar:live:ip", 60, 60, client_ip)
    except (RedisError, RuntimeError):
        logger.warning("scam_radar_rate_limit_unavailable", exc_info=True)
        return
    if not allowed:
        logger.info("rate_limit_hits", extra={"endpoint": "scam_radar_live"})
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
