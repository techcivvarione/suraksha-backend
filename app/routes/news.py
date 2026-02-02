from fastapi import APIRouter, Query
from app.data.news_data import fetch_news, NEWS_CACHE

router = APIRouter(prefix="/news", tags=["News"])


@router.get("/")
def get_news(
    category: str | None = Query(default=None),
    source: str | None = Query(default=None),
    search: str | None = Query(default=None),
):
    if not NEWS_CACHE:
        fetch_news()

    results = NEWS_CACHE

    if category:
        results = [n for n in results if n["category"].lower() == category.lower()]

    if source:
        results = [n for n in results if source.lower() in n["source"].lower()]

    if search:
        results = [
            n for n in results
            if search.lower() in n["title"].lower()
            or search.lower() in n["summary"].lower()
        ]

    return {
        "count": len(results),
        "news": results
    }
