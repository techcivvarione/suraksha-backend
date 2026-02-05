from fastapi import APIRouter, Query
from app.services.supabase_client import get_supabase

router = APIRouter(prefix="/news", tags=["News"])


def pick(local: str | None, fallback: str | None) -> str:
    """
    Safe language fallback:
    - avoids None
    - avoids empty strings
    """
    if local and local.strip():
        return local
    return fallback or ""


@router.get("/")
def get_news(lang: str = Query("en")):
    # ✅ CREATE CLIENT SAFELY
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
        # -------- TITLE --------
        if lang == "te":
            title = pick(n.get("headline_te"), n.get("headline"))
        elif lang == "hi":
            title = pick(n.get("headline_hi"), n.get("headline"))
        else:
            title = n.get("headline") or ""

        # -------- SUMMARY --------
        if lang == "te":
            summary = pick(n.get("summary_400_te"), n.get("summary_400"))
        elif lang == "hi":
            summary = pick(n.get("summary_400_hi"), n.get("summary_400"))
        else:
            summary = n.get("summary_400") or ""

        results.append({
            "source": n.get("source"),
            "category": n.get("category"),
            "title": title,
            "summary": summary,
            "published_at": n.get("published_at"),
            "is_trending": True,  # placeholder
        })

    return {
        "count": len(results),
        "news": results
    }
