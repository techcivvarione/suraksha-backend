from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from redis.exceptions import RedisError
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from app.db import SessionLocal
from app.routes.auth import get_current_user
from app.schemas.scam_network import ScamRadarLiveResponse
from app.services.redis_store import consume_sliding_window

router = APIRouter(prefix="/scam", tags=["Scam Radar"])
logger = logging.getLogger(__name__)


@router.get("/radar/live", response_model=ScamRadarLiveResponse, summary="Get live scam radar events")
async def get_live_scam_radar(
    request: Request,
    current_user=Depends(get_current_user),
):
    _enforce_radar_rate_limit(request=request, current_user=current_user)
    try:
        events = await run_in_threadpool(_fetch_live_radar_events)
    except Exception:
        logger.exception("scam_radar_live_failed")
        raise HTTPException(status_code=500, detail="Unable to load live scam radar")
    return ScamRadarLiveResponse(events=events)


def _fetch_live_radar_events() -> list[dict]:
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT latitude,
                       longitude,
                       category,
                       source
                FROM scan_events
                WHERE created_at > now() - interval '10 minutes'
                ORDER BY created_at DESC
                LIMIT 500
                """
            )
        ).mappings().all()
        return [
            {
                "lat": float(row["latitude"]) if row["latitude"] is not None else None,
                "lng": float(row["longitude"]) if row["longitude"] is not None else None,
                "category": row["category"],
                "source": row["source"],
            }
            for row in rows
        ]
    finally:
        db.close()


def _enforce_radar_rate_limit(*, request: Request, current_user) -> None:
    identifier = str(getattr(current_user, "id", "anonymous"))
    try:
        allowed, _ = consume_sliding_window("scam:radar:live", 60, 60, identifier)
    except (RedisError, RuntimeError):
        logger.warning("scam_radar_rate_limit_unavailable", exc_info=True)
        return
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
