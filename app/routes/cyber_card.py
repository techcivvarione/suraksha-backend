from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User
from app.services.cyber_card import get_cyber_card

router = APIRouter(prefix="/cyber-card", tags=["Cyber Card"])


# =========================================================
# API 1 — CURRENT CYBER CARD
# =========================================================
@router.get("")
def fetch_cyber_card(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔒 PAID ONLY
    if current_user.plan != "PAID":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "UPGRADE_REQUIRED",
                "message": "Cyber Card is available only for paid users",
            },
        )

    card = get_cyber_card(db, str(current_user.id))

    # 🆕 NEW USER (no previous month data)
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

    # 🔐 LOCKED THIS MONTH (missed 1–5 rule)
    if eligibility == "LOCKED_THIS_MONTH":
        return {
            "card_status": "LOCKED",
            "score": card["score"],
            "max_score": card["max_score"],
            "risk_level": "Locked",
            "signals": signals,
            "message": (
                "Mandatory Email & Password scans were not completed "
                "between 1st–5th of this month. "
                "Cyber Card will update next month."
            ),
        }

    # ✅ NORMAL CARD
    return {
        "card_status": "ACTIVE",
        **card,
    }


# =========================================================
# API 2 — CYBER CARD HISTORY (PREVIOUS MONTHS)
# =========================================================
@router.get("/history")
def cyber_card_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔒 PAID ONLY
    if current_user.plan != "PAID":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "UPGRADE_REQUIRED",
                "message": "Cyber Card history is available only for paid users",
            },
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
            "count": 0,
            "history": [],
            "message": "No Cyber Card history available yet",
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
