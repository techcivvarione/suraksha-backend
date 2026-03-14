from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from redis.exceptions import RedisError
from starlette.concurrency import run_in_threadpool

from app.db import SessionLocal
from app.routes.auth import get_current_user
from app.schemas.scam_network import (
    HeatmapScope,
    HeatmapTimeWindow,
    ScamHeatmapResponse,
    ScamHotspotsResponse,
    TrendingScamsResponse,
)
from app.services.redis_store import consume_sliding_window
from app.services.scam_network.aggregation_service import fetch_hotspots
from app.services.scam_network.heatmap_service import MAX_HEATMAP_POINTS, fetch_heatmap_points
from app.services.scam_network.trending_service import fetch_trending_categories

router = APIRouter(prefix="/scam", tags=["Scam Heatmap"])
logger = logging.getLogger(__name__)


@router.get("/heatmap", response_model=ScamHeatmapResponse, summary="Get regional scam heatmap points")
async def get_scam_heatmap(
    request: Request,
    scope: HeatmapScope = Query("global"),
    time_window: HeatmapTimeWindow = Query("24h"),
    category: str | None = Query(None),
    limit: int = Query(MAX_HEATMAP_POINTS, ge=1, le=MAX_HEATMAP_POINTS),
    current_user=Depends(get_current_user),
):
    _enforce_rate_limit(
        namespace="scam:heatmap:read",
        limit=20,
        request=request,
        current_user=current_user,
    )
    try:
        points = await run_in_threadpool(_fetch_heatmap_points, scope, time_window, category, limit)
    except HTTPException:
        raise
    except Exception:
        logger.exception("scam_heatmap_failed")
        raise HTTPException(status_code=500, detail="Unable to load scam heatmap")
    return ScamHeatmapResponse(scope=scope, time_window=time_window, points=points)


@router.get("/hotspots", response_model=ScamHotspotsResponse, summary="Get top regional scam hotspots")
async def get_scam_hotspots(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    current_user=Depends(get_current_user),
):
    _enforce_rate_limit(
        namespace="scam:hotspots:read",
        limit=10,
        request=request,
        current_user=current_user,
    )
    try:
        hotspots = await run_in_threadpool(_fetch_hotspots, limit)
    except HTTPException:
        raise
    except Exception:
        logger.exception("scam_hotspots_failed")
        raise HTTPException(status_code=500, detail="Unable to load scam hotspots")
    return ScamHotspotsResponse(hotspots=hotspots)


@router.get("/trending", response_model=TrendingScamsResponse, summary="Get trending scam categories")
async def get_scam_trending(
    time_window: HeatmapTimeWindow = Query("24h"),
    limit: int = Query(10, ge=1, le=20),
    current_user=Depends(get_current_user),
):
    try:
        trending = await run_in_threadpool(_fetch_trending, time_window, limit)
    except HTTPException:
        raise
    except Exception:
        logger.exception("scam_trending_failed")
        raise HTTPException(status_code=500, detail="Unable to load trending scam categories")
    return TrendingScamsResponse(trending=trending)


def _fetch_heatmap_points(scope: str, time_window: str, category: str | None, limit: int) -> list[dict]:
    db = SessionLocal()
    try:
        return fetch_heatmap_points(
            db,
            scope=scope,
            time_window=time_window,
            category=category,
            limit=limit,
        )
    finally:
        db.close()


def _fetch_hotspots(limit: int) -> list[dict]:
    db = SessionLocal()
    try:
        return fetch_hotspots(db, category=None, limit=limit)
    finally:
        db.close()


def _fetch_trending(time_window: str, limit: int) -> list[dict]:
    db = SessionLocal()
    try:
        return fetch_trending_categories(db, time_window=time_window, limit=limit)
    finally:
        db.close()


def _enforce_rate_limit(*, namespace: str, limit: int, request: Request, current_user) -> None:
    identifier = str(getattr(current_user, "id", "anonymous"))
    client_ip = request.client.host if request.client else "unknown"
    try:
        allowed, _ = consume_sliding_window(namespace, limit, 60, identifier, client_ip)
    except (RedisError, RuntimeError):
        logger.warning("scam_read_rate_limit_unavailable", exc_info=True)
        return
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
