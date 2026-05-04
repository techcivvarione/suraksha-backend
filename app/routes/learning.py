from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.learning_article import LearningArticle
from app.models.user import User
from app.routes.auth import get_current_user
from app.schemas.learning import (
    LearningArticleDetail,
    LearningArticlesListResponse,
    LearningRecommendedResponse,
)
from app.services.learning_service import (
    build_article_detail,
    build_article_summary,
    list_recommended_articles,
    normalize_category,
)

router = APIRouter(prefix="/learn", tags=["Learning"])


@router.get("/articles", response_model=LearningArticlesListResponse)
def list_articles(
    category: str | None = Query(default=None, min_length=1, max_length=100),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    normalized_category = normalize_category(category)
    query = db.query(LearningArticle)
    if normalized_category:
        query = query.filter(func.lower(LearningArticle.category) == normalized_category)

    total = query.count()
    items = (
        query
        .order_by(LearningArticle.is_featured.desc(), LearningArticle.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return LearningArticlesListResponse(
        total=total,
        limit=limit,
        offset=offset,
        category=normalized_category,
        items=[build_article_summary(article) for article in items],
    )


@router.get("/recommended", response_model=LearningRecommendedResponse)
def recommended_articles(
    limit: int = Query(5, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, source, matched_categories = list_recommended_articles(
        db,
        user_id=str(current_user.id),
        limit=limit,
    )
    return {
        "items": [build_article_summary(article) for article in items],
        "meta": {
            "source": source,
            "matched_categories": matched_categories,
        },
    }


@router.get("/{article_id}", response_model=LearningArticleDetail)
def article_detail(
    article_id: UUID,
    db: Session = Depends(get_db),
):
    article = db.query(LearningArticle).filter(LearningArticle.id == article_id).first()
    if not article:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "ARTICLE_NOT_FOUND", "message": "Article not found"},
        )
    return build_article_detail(article)
