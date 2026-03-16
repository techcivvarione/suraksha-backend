import hashlib
import logging
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature
from app.db import get_db
from app.dependencies.access import require_feature
from app.models.user import User
from app.schemas.cyber_card import (
    CyberCardActiveResponse,
    CyberCardHistoryResponse,
    CyberCardLockedResponse,
    CyberCardPendingResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cyber-card", tags=["Cyber Card"])


def _generate_card_id(name: str, user_id: str):
    initial = name[0].upper() if name else "X"
    h = hashlib.sha1(user_id.encode()).hexdigest()[:6].upper()
    year = datetime.utcnow().year % 100
    return f"CC-{year:02d}-{initial}-{h}"


def _normalize_cyber_card_signals(raw_signals) -> dict:
    signals = dict(raw_signals or {})
    email_scan_count = int(signals.get("email_scan_count", signals.get("email_breaches", 0)) or 0)
    password_scan_count = int(signals.get("password_scan_count", signals.get("password_breaches", 0)) or 0)
    return {
        "email_scan_count": email_scan_count,
        "password_scan_count": password_scan_count,
        "scan_reward_points": int(signals.get("scan_reward_points", 0) or 0),
        "ocr_bonus": int(signals.get("ocr_bonus", 0) or 0),
        "scam_reports": int(signals.get("scam_reports", 0) or 0),
        "eligibility": str(signals.get("eligibility", "ELIGIBLE")),
        "lock_reason": signals.get("lock_reason"),
    }


def _get_cyber_card(db: Session, user_id: str):
    logger.info("cyber_card_fetch", extra={"user_id": user_id})
    user = db.execute(
        text("SELECT name, plan FROM users WHERE id = CAST(:uid AS uuid)"),
        {"uid": user_id},
    ).mappings().first()

    if not user:
        return None

    card = db.execute(
        text(
            """
            SELECT score, max_score, risk_level, signals, score_month
            FROM cyber_card_scores
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY score_month DESC
            LIMIT 1
            """
        ),
        {"uid": user_id},
    ).mappings().first()

    if not card:
        return None

    return {
        "card_id": _generate_card_id(user["name"], user_id),
        "name": user["name"],
        "is_paid": user["plan"] in ("GO_PRO", "GO_ULTRA"),
        "signals": _normalize_cyber_card_signals(card["signals"]),
        "score_version": "v1",
        "score": card["score"],
        "max_score": card["max_score"],
        "risk_level": card["risk_level"],
        "score_month": card["score_month"],
    }


def _get_cyber_card_history(db: Session, user_id: str) -> list[dict]:
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
        {"uid": user_id},
    ).mappings().all()
    return [
        {
            "month": row["score_month"],
            "score": row["score"],
            "max_score": row["max_score"],
            "risk_level": row["risk_level"],
            "signals": _normalize_cyber_card_signals(row["signals"]),
        }
        for row in rows
    ]


@router.get("", response_model=CyberCardPendingResponse | CyberCardLockedResponse | CyberCardActiveResponse)
def fetch_cyber_card(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_feature(Feature.CYBER_CARD_ACCESS)),
):
    user_id = str(current_user.id)
    try:
        card = _get_cyber_card(db, user_id)
    except SQLAlchemyError:
        logger.exception("cyber_card_fetch_failed", extra={"user_id": user_id})
        return CyberCardPendingResponse(
            card_status="PENDING",
            message="Your Cyber Card will be available after completing required security scans.",
        )

    if not card:
        return CyberCardPendingResponse(
            card_status="PENDING",
            message="Your Cyber Card will be available after completing required security scans.",
        )

    signals = card.get("signals") or {}
    eligibility = signals.get("eligibility", "ELIGIBLE")

    if eligibility == "LOCKED_THIS_MONTH":
        return CyberCardLockedResponse(
            card_status="LOCKED",
            score=card["score"],
            max_score=card["max_score"],
            risk_level="Locked",
            signals=signals,
            message=(
                "Mandatory Email & Password scans were not completed "
                "between 1st-5th of this month. "
                "Cyber Card will update next month."
            ),
        )

    return CyberCardActiveResponse(card_status="ACTIVE", **card)


@router.get("/history", response_model=CyberCardHistoryResponse)
def cyber_card_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_feature(Feature.CYBER_CARD_ACCESS)),
):
    user_id = str(current_user.id)
    try:
        history = _get_cyber_card_history(db, user_id)
    except SQLAlchemyError:
        logger.exception("cyber_card_history_failed", extra={"user_id": user_id})
        return CyberCardHistoryResponse(count=0, history=[], message="No Cyber Card history available yet")

    if not history:
        return CyberCardHistoryResponse(
            count=0,
            history=[],
            message="No Cyber Card history available yet",
        )

    return CyberCardHistoryResponse(
        count=len(history),
        history=history,
    )
