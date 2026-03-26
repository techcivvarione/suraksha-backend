"""
cyber_card_score_job.py — Monthly batch job that (re)scores every user.

Eligibility rule: a user must have performed at least one EMAIL scan
AND one PASSWORD scan during the first 5 calendar days of the month
(in the Asia/Kolkata timezone).  If they miss the window their card is
locked for the month.

Eligible users are scored via the shared calculate_cyber_score() engine
so that batch scores are always consistent with real-time scores.
"""
import json
import uuid
import logging

from sqlalchemy import text

from app.db import SessionLocal
from app.services.cyber_card_constants import get_risk_level
from app.services.cyber_card_scorer import calculate_cyber_score

logger = logging.getLogger(__name__)


def run_cyber_card_score_job() -> None:
    db = SessionLocal()

    try:
        users = db.execute(text("SELECT id FROM users")).mappings().all()

        month_start = db.execute(
            text(
                "SELECT date_trunc('month', now() AT TIME ZONE 'Asia/Kolkata')"
            )
        ).scalar()

        from datetime import timedelta
        eligibility_window_end = month_start + timedelta(days=5)

        processed = locked = errors = 0

        for user in users:
            uid = str(user["id"])
            try:
                _process_user(db, uid, month_start, eligibility_window_end)
                processed += 1
            except Exception:
                logger.exception(
                    "cyber_card_job_user_failed", extra={"user_id": uid}
                )
                errors += 1

        db.commit()
        logger.info(
            "cyber_card_job_complete",
            extra={"processed": processed, "locked": locked, "errors": errors},
        )

    except Exception:
        logger.exception("cyber_card_job_fatal")
        db.rollback()
    finally:
        db.close()


def _process_user(db, uid: str, month_start, eligibility_window_end) -> None:
    """Score (or lock) a single user for the current month."""

    # ── Eligibility check: email + password scan in first 5 days ─────────────
    email_done = db.execute(
        text(
            """
            SELECT COUNT(*) FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND scan_type = 'EMAIL'
              AND created_at >= :start
              AND created_at < :end
            """
        ),
        {"uid": uid, "start": month_start, "end": eligibility_window_end},
    ).scalar() or 0

    password_done = db.execute(
        text(
            """
            SELECT COUNT(*) FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND scan_type = 'PASSWORD'
              AND created_at >= :start
              AND created_at < :end
            """
        ),
        {"uid": uid, "start": month_start, "end": eligibility_window_end},
    ).scalar() or 0

    if email_done == 0 or password_done == 0:
        # User missed the mandatory scan window — insert a locked placeholder
        _upsert_locked(db, uid, month_start)
        return

    # ── Eligible user — compute real-time score ───────────────────────────────
    result = calculate_cyber_score(db, uid)
    score  = result["score"]

    db.execute(
        text(
            """
            INSERT INTO cyber_card_scores (
                id, user_id, score, max_score, risk_level,
                signals, factors, insights, actions,
                score_month, updated_at
            )
            VALUES (
                :id, CAST(:uid AS uuid), :score, 1000, :risk_level,
                '{}',
                CAST(:factors  AS jsonb),
                CAST(:insights AS jsonb),
                CAST(:actions  AS jsonb),
                :month, now()
            )
            ON CONFLICT (user_id, score_month) DO UPDATE SET
                score      = EXCLUDED.score,
                risk_level = EXCLUDED.risk_level,
                factors    = EXCLUDED.factors,
                insights   = EXCLUDED.insights,
                actions    = EXCLUDED.actions,
                updated_at = now()
            """
        ),
        {
            "id":         str(uuid.uuid4()),
            "uid":        uid,
            "score":      score,
            "risk_level": get_risk_level(score),
            "factors":    json.dumps(result["factors"]),
            "insights":   json.dumps(result["insights"]),
            "actions":    json.dumps(result["actions"]),
            "month":      month_start,
        },
    )
    logger.info(
        "cyber_card_job_scored",
        extra={"user_id": uid, "score": score, "level": result["level"]},
    )


def _upsert_locked(db, uid: str, month_start) -> None:
    """Insert a LOCKED placeholder so the card shows a locked state."""
    signals = {
        "eligibility": "LOCKED_THIS_MONTH",
        "lock_reason": "Mandatory Email/Password scan missed (days 1–5)",
    }
    db.execute(
        text(
            """
            INSERT INTO cyber_card_scores (
                id, user_id, score, max_score,
                risk_level, signals, score_month, updated_at
            )
            VALUES (
                :id, CAST(:uid AS uuid), 0, 1000,
                'Locked', CAST(:signals AS jsonb), :month, now()
            )
            ON CONFLICT (user_id, score_month) DO UPDATE SET
                score      = EXCLUDED.score,
                risk_level = EXCLUDED.risk_level,
                signals    = EXCLUDED.signals,
                updated_at = now()
            """
        ),
        {
            "id":      str(uuid.uuid4()),
            "uid":     uid,
            "signals": json.dumps(signals),
            "month":   month_start,
        },
    )
    logger.info("cyber_card_job_locked", extra={"user_id": uid})
