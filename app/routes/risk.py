from fastapi import APIRouter, Depends
from datetime import datetime

from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/risk", tags=["User Risk"])


@router.get("/score")
def user_risk_score(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    score = 0
    reasons = []

    # ---- HISTORY BASED SCORING (DB) ----
    history_rows = db.execute(
        """
        select risk
        from scan_history
        where user_id = :uid
        """,
        {"uid": str(current_user.id)},
    ).scalars().all()

    for risk in history_rows:
        if risk == "high":
            score += 30
            reasons.append("High-risk scam detected previously")
        elif risk == "medium":
            score += 15
            reasons.append("Medium-risk scam detected previously")

    # ---- ALERT BASED SCORING (DB) ----
    alert_rows = db.execute(
        """
        select severity, type, read
        from alerts
        where user_id = :uid
        """,
        {"uid": str(current_user.id)},
    ).all()

    for severity, alert_type, read in alert_rows:
        if not read:
            if severity == "HIGH":
                score += 25
                reasons.append("Unread high-severity alert")
            elif severity == "MEDIUM":
                score += 10
                reasons.append("Unread medium-severity alert")

        if alert_type == "history":
            score += 40
            reasons.append("Repeated scam pattern detected")

    # ---- FINAL RISK LEVEL ----
    if score >= 70:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_level": level,
        "risk_score": score,
        "factors": list(set(reasons)),
        "evaluated_at": datetime.utcnow(),
    }
