import logging

from fastapi import APIRouter, Depends
from sqlalchemy.exc import SQLAlchemyError
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
from app.services.cyber_card import get_cyber_card, get_cyber_card_history

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cyber-card", tags=["Cyber Card"])


@router.get("", response_model=CyberCardPendingResponse | CyberCardLockedResponse | CyberCardActiveResponse)
def fetch_cyber_card(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_feature(Feature.CYBER_CARD_ACCESS)),
):
    user_id = str(current_user.id)
    try:
        card = get_cyber_card(db, user_id)
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
        history = get_cyber_card_history(db, user_id)
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
