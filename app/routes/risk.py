from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/risk", tags=["User Risk"])


@router.get("/score")
def user_risk_score(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # ---- fetch scan history ----
    history_rows = db.execute(
        text("""
            SELECT risk
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
        """),
        {"uid": str(current_user.id)},
    ).scalars().all()

    if not history_rows:
        return {
            "risk_score": 0,
            "risk_level": "Low",
            "message": "No scans found yet"
        }

    # ---- scoring logic ----
    score = 0
    for risk in history_rows:
        if risk == "high":
            score += 15
        elif risk == "medium":
            score += 7
        elif risk == "low":
            score += 2

    score = min(score, 100)

    # ---- level mapping ----
    if score >= 70:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_score": score,
        "risk_level": level,
        "total_scans": len(history_rows),
    }
