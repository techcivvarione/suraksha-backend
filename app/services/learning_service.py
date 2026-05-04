from __future__ import annotations

from sqlalchemy import case, func, text
from sqlalchemy.orm import Session

from app.models.learning_article import LearningArticle

_SCAN_TYPE_CATEGORY_MAP: dict[str, tuple[str, ...]] = {
    "email": ("email_security", "phishing_awareness"),
    "password": ("password_security", "account_protection"),
    "qr": ("qr_safety", "payment_scams"),
    "threat": ("phishing_awareness", "social_engineering"),
    "reality_image": ("deepfake_awareness", "misinformation"),
    "reality_video": ("deepfake_awareness", "misinformation"),
    "reality_audio": ("deepfake_awareness", "misinformation"),
}


def build_article_summary(article: LearningArticle) -> dict:
    return {
        "id": article.id,
        "title": article.title,
        "description": article.description,
        "category": article.category,
        "read_time": int(article.read_time),
        "image_url": article.image_url,
        "is_featured": bool(article.is_featured),
        "created_at": article.created_at,
    }


def build_article_detail(article: LearningArticle) -> dict:
    payload = build_article_summary(article)
    payload["content"] = article.content
    return payload


def normalize_category(category: str | None) -> str | None:
    if category is None:
        return None
    normalized = category.strip().lower()
    return normalized or None


def get_recommended_categories(db: Session, user_id: str, limit: int = 3) -> list[str]:
    rows = db.execute(
        text(
            """
            SELECT LOWER(COALESCE(scan_type, '')) AS scan_type, COUNT(*) AS total
            FROM scan_history
            WHERE user_id = CAST(:user_id AS uuid)
            GROUP BY LOWER(COALESCE(scan_type, ''))
            ORDER BY total DESC, scan_type ASC
            LIMIT :limit
            """
        ),
        {"user_id": user_id, "limit": limit},
    ).mappings().all()

    categories: list[str] = []
    for row in rows:
        for category in _SCAN_TYPE_CATEGORY_MAP.get(row["scan_type"], ()):
            if category not in categories:
                categories.append(category)
    return categories


def list_recommended_articles(
    db: Session,
    *,
    user_id: str,
    limit: int = 5,
) -> tuple[list[LearningArticle], str, list[str]]:
    matched_categories = get_recommended_categories(db, user_id=user_id)
    if matched_categories:
        ordering = case(
            {category: index for index, category in enumerate(matched_categories)},
            value=func.lower(LearningArticle.category),
            else_=len(matched_categories),
        )
        items = (
            db.query(LearningArticle)
            .filter(func.lower(LearningArticle.category).in_(matched_categories))
            .order_by(ordering, LearningArticle.is_featured.desc(), LearningArticle.created_at.desc())
            .limit(limit)
            .all()
        )
        if items:
            return items, "history_match", matched_categories

    items = (
        db.query(LearningArticle)
        .order_by(LearningArticle.is_featured.desc(), LearningArticle.created_at.desc())
        .limit(limit)
        .all()
    )
    return items, "featured_fallback", []
