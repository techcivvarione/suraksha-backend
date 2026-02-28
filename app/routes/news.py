import logging

from fastapi import APIRouter, Depends
from redis.exceptions import RedisError

from app.dependencies.language import resolve_language
from app.services.redis_store import get_json, set_json
from app.services.supabase_client import get_supabase

router = APIRouter(prefix="/news", tags=["News"])
logger = logging.getLogger(__name__)


def pick(local: str | None, fallback: str | None) -> str:
    """
    Strong fallback:
    - no None
    - no empty
    - no whitespace-only
    """
    if local and local.strip():
        return local.strip()
    if fallback and fallback.strip():
        return fallback.strip()
    return ""


NEWS_CACHE_TTL_SECONDS = 120


@router.get("/")
def get_news(
    language: str = Depends(resolve_language),
):
    try:
        cached = get_json("cache:news:list", language)
        if cached:
            return cached
    except RedisError:
        logger.exception("Redis news cache read failed")

    supabase = get_supabase()

    resp = (
        supabase
        .table("news")
        .select("*")
        .order("published_at", desc=True)
        .limit(30)
        .execute()
    )

    data = resp.data or []
    results = []

    for n in data:
        # ---------- TITLE ----------
        if language == "te":
            title = pick(n.get("headline_te"), n.get("headline"))
        elif language == "hi":
            title = pick(n.get("headline_hi"), n.get("headline"))
        else:
            title = pick(n.get("headline"), None)

        # ---------- SUMMARY (FIXED) ----------
        if language == "te":
            summary = pick(n.get("summary_400_te"), n.get("summary_400"))
        elif language == "hi":
            summary = pick(n.get("summary_400_hi"), n.get("summary_400"))
        else:
            summary = pick(n.get("summary_400"), None)

        # ---------- FINAL GUARANTEE ----------
        if not summary:
            summary = "Summary will be updated shortly."

        results.append({
            "source": n.get("source") or "",
            "category": n.get("category") or "",
            "title": title,
            "summary": summary,
            "image": n.get("image"),          # ✅ IMPORTANT
            "link": n.get("link"),            # ✅ IMPORTANT
            "published_at": n.get("published_at"),
            "is_trending": n.get("is_trending", False),
        })

    payload = {
        "count": len(results),
        "language": language,
        "news": results
    }
    try:
        set_json("cache:news:list", payload, NEWS_CACHE_TTL_SECONDS, language)
    except RedisError:
        logger.exception("Redis news cache write failed")
    return payload
