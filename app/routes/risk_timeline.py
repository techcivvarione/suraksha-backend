from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/risk", tags=["Risk"])


@router.get("/timeline")
def risk_timeline(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text("""
            SELECT
                DATE(created_at) AS day,
                COUNT(*) FILTER (WHERE risk = 'high')   AS high,
                COUNT(*) FILTER (WHERE risk = 'medium') AS medium,
                COUNT(*) FILTER (WHERE risk = 'low')    AS low
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY day
            ORDER BY day
        """),
        {"uid": str(current_user.id)},
    ).mappings().all()

    timeline = []

    for r in rows:
        score = 100
        score -= r["high"] * 15
        score -= r["medium"] * 8

        score = max(0, min(100, score))

        timeline.append({
            "date": r["day"],
            "score": score,
            "high": r["high"],
            "medium": r["medium"],
            "low": r["low"],
        })

    return {
        "window": "30_days",
        "points": timeline,
    }
