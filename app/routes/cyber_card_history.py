from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(
    prefix="/cyber-card",
    tags=["Cyber Card"]
)

@router.get("/history")
def cyber_card_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔐 only PAID users
    if current_user.plan != "PAID":
        raise HTTPException(
            status_code=403,
            detail="Cyber Card available for paid users only",
        )

    rows = db.execute(
        text("""
            SELECT
                score_month,
                score,
                max_score,
                risk_level,
                signals
            FROM cyber_card_scores
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY score_month DESC
        """),
        {"uid": str(current_user.id)},
    ).mappings().all()

    if not rows:
        return {
            "message": "Cyber Card will be available from next month",
            "data": [],
        }

    return {
        "count": len(rows),
        "history": [
            {
                "month": r["score_month"],
                "score": r["score"],
                "max_score": r["max_score"],
                "risk_level": r["risk_level"],
                "signals": r["signals"],
            }
            for r in rows
        ],
    }

