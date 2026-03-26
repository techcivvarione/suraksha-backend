import hashlib
import json
import logging
import uuid
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

_BASE_SCORE = 600
_MIN_SCORE  = 300
_MAX_SCORE  = 999

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


def _compute_and_cache_card(db: Session, user_id: str) -> None:
    """Compute a real-time Cyber Card score for a user and persist it to
    ``cyber_card_scores``.  Called by the endpoint when no current-month row
    exists yet (i.e. the monthly batch job hasn't run).  Mirrors the scoring
    logic in ``cyber_card_score_job.py`` but skips the 1st-5th eligibility
    window so users unlock their card as soon as they've done ≥1 email scan
    AND ≥1 password scan."""
    try:
        from app.services.cyber_card_constants import get_risk_level

        month_start = db.execute(
            text(
                "SELECT date_trunc('month', now() AT TIME ZONE 'Asia/Kolkata')"
            )
        ).scalar()

        # ── Guard: only compute if mandatory scans are present ────────────
        email_count = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'EMAIL'
                  AND created_at >= :start
                """
            ),
            {"uid": user_id, "start": month_start},
        ).scalar() or 0

        password_count = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'PASSWORD'
                  AND created_at >= :start
                """
            ),
            {"uid": user_id, "start": month_start},
        ).scalar() or 0

        if email_count == 0 or password_count == 0:
            # Not enough scans yet — leave card as PENDING
            logger.info(
                "cyber_card_pending_insufficient_scans",
                extra={
                    "user_id": user_id,
                    "email_count": email_count,
                    "password_count": password_count,
                },
            )
            return

        # ── Score calculation (mirrors cyber_card_score_job.py) ───────────
        score = _BASE_SCORE

        if email_count <= 3:
            score -= 30
        elif email_count <= 6:
            score -= 60
        elif email_count <= 10:
            score -= 100
        elif email_count <= 50:
            score -= 180
        else:
            score -= 300

        if password_count <= 3:
            score -= 50
        elif password_count <= 6:
            score -= 100
        elif password_count <= 10:
            score -= 180
        else:
            score -= 300

        scan_rows = db.execute(
            text(
                """
                SELECT risk, COUNT(*) AS cnt FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'THREAT'
                  AND created_at >= :start
                GROUP BY risk
                """
            ),
            {"uid": user_id, "start": month_start},
        ).mappings().all()

        reward = 0
        for row in scan_rows:
            r = (row["risk"] or "").lower()
            if r == "low":
                reward += int(row["cnt"]) * 1
            elif r == "medium":
                reward += int(row["cnt"]) * 2
            elif r == "high":
                reward += int(row["cnt"]) * 3
        reward = min(reward, 50)
        score += reward

        score = max(_MIN_SCORE, min(score, _MAX_SCORE))
        risk_level = get_risk_level(score)

        signals = {
            "email_scan_count": email_count,
            "password_scan_count": password_count,
            "scan_reward_points": reward,
            "ocr_bonus": 0,
            "scam_reports": 0,
            "eligibility": "ELIGIBLE",
            "lock_reason": None,
        }

        db.execute(
            text(
                """
                INSERT INTO cyber_card_scores (
                    id, user_id, score, max_score, risk_level, signals, score_month
                )
                VALUES (
                    :id, CAST(:uid AS uuid), :score, :max,
                    :level, CAST(:signals AS jsonb), :month
                )
                ON CONFLICT (user_id, score_month)
                DO UPDATE SET
                    score      = EXCLUDED.score,
                    risk_level = EXCLUDED.risk_level,
                    signals    = EXCLUDED.signals,
                    created_at = now()
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "uid": user_id,
                "score": score,
                "max": _MAX_SCORE,
                "level": risk_level,
                "signals": json.dumps(signals),
                "month": month_start,
            },
        )
        db.commit()
        logger.info(
            "cyber_card_computed_on_demand",
            extra={"user_id": user_id, "score": score, "risk_level": risk_level},
        )
    except Exception as e:
        logger.exception(
            "cyber_card_compute_failed",
            extra={"user_id": user_id, "error": str(e)},
        )
        # Never break the endpoint — caller handles the no-card case


@router.get("", response_model=CyberCardPendingResponse | CyberCardLockedResponse | CyberCardActiveResponse)
def fetch_cyber_card(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_feature(Feature.CYBER_CARD_ACCESS)),
):
    user_id = str(current_user.id)
    try:
        card = _get_cyber_card(db, user_id)

        # No card yet — compute one on-the-fly if the user has qualifying scans
        if not card:
            _compute_and_cache_card(db, user_id)
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
