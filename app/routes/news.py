from fastapi import APIRouter, Query
from app.services.supabase_client import get_supabase

router = APIRouter(prefix="/news", tags=["News"])


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


@router.get("/")
def get_news(lang: str = Query("en")):
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
        if lang == "te":
            title = pick(n.get("headline_te"), n.get("headline"))
        elif lang == "hi":
            title = pick(n.get("headline_hi"), n.get("headline"))
        else:
            title = pick(n.get("headline"), None)

        # ---------- SUMMARY (FIXED) ----------
        if lang == "te":
            summary = pick(n.get("summary_400_te"), n.get("summary_400"))
        elif lang == "hi":
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

    return {
        "count": len(results),
        "news": results
    }
