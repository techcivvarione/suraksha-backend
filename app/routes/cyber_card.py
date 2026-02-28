from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature
from app.db import get_db
from app.dependencies.access import require_feature
from app.models.user import User
from app.services.cyber_card import get_cyber_card

router = APIRouter(prefix="/cyber-card", tags=["Cyber Card"])


@router.get("")
def fetch_cyber_card(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_feature(Feature.CYBER_CARD_ACCESS)
    ),
):

    card = get_cyber_card(db, str(current_user.id))

    if not card:
        return {
            "card_status": "PENDING",
            "message": (
                "Your Cyber Card will be available from next month "
                "after completing mandatory security scans."
            ),
        }

    signals = card.get("signals") or {}
    eligibility = signals.get("eligibility", "ELIGIBLE")

    if eligibility == "LOCKED_THIS_MONTH":
        return {
            "card_status": "LOCKED",
            "score": card["score"],
            "max_score": card["max_score"],
            "risk_level": "Locked",
            "signals": signals,
            "message": (
                "Mandatory Email & Password scans were not completed "
                "between 1st-5th of this month. "
                "Cyber Card will update next month."
            ),
        }

    return {
        "card_status": "ACTIVE",
        **card,
    }


@router.get("/history")
def cyber_card_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_feature(Feature.CYBER_CARD_ACCESS)
    ),
):

    rows = db.execute(
        text(
            """
            SELECT
                score_month,
                score,
                max_score,
                risk_level,
                signals
            FROM cyber_card_scores
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY score_month DESC
        """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    if not rows:
        return {
            "count": 0,
            "history": [],
            "message": "No Cyber Card history available yet",
        }

    return {
        "count": len(rows),
        "history": [
            {
                "month": row["score_month"],
                "score": row["score"],
                "max_score": row["max_score"],
                "risk_level": row["risk_level"],
                "signals": row["signals"],
            }
            for row in rows
        ],
    }
