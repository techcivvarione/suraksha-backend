from fastapi import APIRouter, Query
from app.data.news_data import fetch_news

router = APIRouter(
    prefix="/news",
    tags=["News"]
)


@router.get("/")
def get_news(
    category: str | None = Query(default=None, description="Filter by category"),
    source: str | None = Query(default=None, description="Filter by source"),
    search: str | None = Query(default=None, description="Search in title and summary"),
):
    # Always fetch via cache-aware function
    news_items = fetch_news()

    results = news_items

    if category:
        results = [
            n for n in results
            if n.get("category", "").lower() == category.lower()
        ]

    if source:
        results = [
            n for n in results
            if source.lower() in n.get("source", "").lower()
        ]

    if search:
        search_l = search.lower()
        results = [
            n for n in results
            if search_l in n.get("title", "").lower()
            or search_l in n.get("summary", "").lower()
        ]

    return {
        "count": len(results),
        "news": results
    }
