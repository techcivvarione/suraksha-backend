from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/risk", tags=["Risk"])


RISK_WEIGHTS = {
    "low": 2,
    "medium": -5,
    "high": -15,
}


@router.get("/score")
def user_risk_score(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text("""
            SELECT risk
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= NOW() - INTERVAL '30 days'
        """),
        {"uid": str(current_user.id)},
    ).scalars().all()

    score = 100

    for risk in rows:
        weight = RISK_WEIGHTS.get(risk.lower(), 0)
        score += weight

    # clamp score
    score = max(0, min(100, score))

    if score >= 80:
        level = "LOW"
        message = "Your security posture looks strong."
    elif score >= 50:
        level = "MEDIUM"
        message = "Some risky activity detected."
    else:
        level = "HIGH"
        message = "Immediate attention recommended."

    return {
        "score": score,
        "risk_level": level,
        "window": "30_days",
        "total_scans": len(rows),
        "generated_at": datetime.utcnow(),
        "summary": message,
    }
