import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
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
    CyberCardSignals,
)
from app.services.cyber_card_constants import get_risk_level, get_risk_level_v2

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cyber-card", tags=["Cyber Card"])

# How long (seconds) a cached score is considered fresh before recomputing
_CACHE_TTL_SECONDS = 300  # 5 minutes


# ── Helpers ──────────────────────────────────────────────────────────────────

def _generate_card_id(name: str, user_id: str) -> str:
    initial = name[0].upper() if name else "X"
    h = hashlib.sha1(user_id.encode()).hexdigest()[:6].upper()
    year = datetime.utcnow().year % 100
    return f"CC-{year:02d}-{initial}-{h}"


def _normalize_signals(raw) -> CyberCardSignals:
    d = dict(raw or {})

    def _int(key: str) -> int:
        v = d.get(key, 0)
        return int(v) if isinstance(v, (int, float)) else (int(v) if str(v).isdigit() else 0)

    return CyberCardSignals(
        email_scan_count    = _int("email_scan_count"),
        password_scan_count = _int("password_scan_count"),
        scan_reward_points  = _int("scan_reward_points"),
        ocr_bonus           = _int("ocr_bonus"),
        scam_reports        = _int("scam_reports"),
        eligibility         = str(d.get("eligibility", "ELIGIBLE")),
        lock_reason         = d.get("lock_reason"),
    )


def _to_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_stale(updated_at: datetime | None, now: datetime, ttl: int) -> bool:
    """Return True if updated_at is absent or older than *ttl* seconds."""
    aware = _to_aware(updated_at)
    if aware is None:
        return True
    return (now - aware).total_seconds() > ttl


def _get_cyber_card(db: Session, user_id: str) -> dict | None:
    """Fetch the most-recent cyber card row for *user_id*.  Returns None if
    the user or card doesn't exist."""
    user = db.execute(
        text("SELECT name, plan FROM users WHERE id = CAST(:uid AS uuid)"),
        {"uid": user_id},
    ).mappings().first()
    if not user:
        return None

    # Try the full V2 query first; gracefully fall back if the new columns
    # haven't been added yet (migration pending on this environment).
    try:
        row = db.execute(
            text(
                """
                SELECT score, max_score, risk_level, signals,
                       factors, insights, actions,
                       score_month, updated_at
                FROM cyber_card_scores
                WHERE user_id = CAST(:uid AS uuid)
                ORDER BY score_month DESC, updated_at DESC NULLS LAST
                LIMIT 1
                """
            ),
            {"uid": user_id},
        ).mappings().first()
    except Exception:
        # V2 columns not yet present — fall back to legacy schema
        db.rollback()
        try:
            row = db.execute(
                text(
                    """
                    SELECT score, max_score, risk_level, signals,
                           score_month,
                           NULL::jsonb        AS factors,
                           NULL::jsonb        AS insights,
                           NULL::jsonb        AS actions,
                           NULL::timestamptz  AS updated_at
                    FROM cyber_card_scores
                    WHERE user_id = CAST(:uid AS uuid)
                    ORDER BY score_month DESC
                    LIMIT 1
                    """
                ),
                {"uid": user_id},
            ).mappings().first()
        except Exception:
            logger.exception("cyber_card_read_failed", extra={"user_id": user_id})
            return None

    if not row:
        return None

    score = int(row["score"] or 0)
    return {
        "card_id":    _generate_card_id(user["name"], user_id),
        "name":       user["name"],
        "is_paid":    user["plan"] in ("GO_PRO", "GO_ULTRA"),
        "score":      score,
        "max_score":  1000,
        "risk_level": row["risk_level"] or get_risk_level(score),
        "level":      get_risk_level_v2(score),
        "signals":    _normalize_signals(row["signals"]),
        "factors":    dict(row["factors"]) if row["factors"] else {},
        "insights":   list(row["insights"]) if row["insights"] else [],
        "actions":    list(row["actions"]) if row["actions"] else [],
        "score_month": row["score_month"],
        "updated_at": row["updated_at"],
        "score_version": "v2",
    }


def _check_eligibility(db: Session, user_id: str) -> tuple[bool, int, list[str]]:
    """Return (eligible, distinct_count, scan_types_list).

    Eligible = COUNT(DISTINCT LOWER(scan_type)) >= 2.
    Uses LOWER() so 'email', 'EMAIL', 'Email' are all counted as one type.
    Never raises — returns (False, 0, []) on DB error.
    """
    try:
        rows = db.execute(
            text(
                """
                SELECT LOWER(scan_type) AS st, COUNT(*) AS cnt
                FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                GROUP BY LOWER(scan_type)
                """
            ),
            {"uid": user_id},
        ).mappings().all()
        type_map  = {r["st"]: int(r["cnt"]) for r in rows}
        scan_types = sorted(type_map.keys())
        distinct   = len(scan_types)
        eligible   = distinct >= 2
        logger.info(
            "cyber_card_debug",
            extra={
                "user_id":        user_id,
                "scan_types":     type_map,
                "distinct_count": distinct,
                "eligible":       eligible,
            },
        )
        return eligible, distinct, scan_types
    except Exception:
        logger.exception("cyber_card_eligibility_failed", extra={"user_id": user_id})
        return False, 0, []


def _compute_and_upsert(db: Session, user_id: str) -> None:
    """Run the scoring engine for *user_id* and persist results.
    Never raises — caller checks the return value of _get_cyber_card instead."""
    try:
        from app.services.cyber_card_scorer import calculate_cyber_score

        result = calculate_cyber_score(db, user_id)
        score  = result["score"]
        level  = result["level"]

        month_start = db.execute(
            text(
                "SELECT date_trunc('month', now() AT TIME ZONE 'Asia/Kolkata')"
            )
        ).scalar()

        upsert_params = {
            "id":         str(uuid.uuid4()),
            "uid":        user_id,
            "score":      score,
            "risk_level": get_risk_level(score),
            "factors":    json.dumps(result["factors"]),
            "insights":   json.dumps(result["insights"]),
            "actions":    json.dumps(result["actions"]),
            "month":      month_start,
        }

        try:
            # Full V2 upsert — requires migration 20260326_01 to have run
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
                        '{}', CAST(:factors AS jsonb), CAST(:insights AS jsonb),
                        CAST(:actions AS jsonb), :month, now()
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
                upsert_params,
            )
        except Exception:
            # V2 columns absent — fall back to legacy upsert
            db.rollback()
            db.execute(
                text(
                    """
                    INSERT INTO cyber_card_scores (
                        id, user_id, score, max_score, risk_level, signals, score_month
                    )
                    VALUES (
                        :id, CAST(:uid AS uuid), :score, 1000, :risk_level, '{}', :month
                    )
                    ON CONFLICT (user_id, score_month) DO UPDATE SET
                        score      = EXCLUDED.score,
                        risk_level = EXCLUDED.risk_level
                    """
                ),
                upsert_params,
            )
        db.commit()
        logger.info(
            "cyber_card_computed",
            extra={"user_id": user_id, "score": score, "level": level},
        )
    except Exception as e:
        logger.exception(
            "cyber_card_compute_failed",
            extra={"user_id": user_id, "error": str(e)},
        )
        # Never raise — the endpoint handles a missing card gracefully


def _get_cyber_card_history(db: Session, user_id: str) -> list[dict]:
    rows = db.execute(
        text(
            """
            SELECT score_month, score, max_score, risk_level, signals
            FROM cyber_card_scores
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY score_month DESC
            """
        ),
        {"uid": user_id},
    ).mappings().all()
    return [
        {
            "month":      row["score_month"],
            "score":      row["score"],
            "max_score":  row["max_score"] or 1000,
            "risk_level": row["risk_level"],
            "signals":    _normalize_signals(row["signals"]),
        }
        for row in rows
    ]


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=CyberCardPendingResponse | CyberCardLockedResponse | CyberCardActiveResponse,
)
def fetch_cyber_card(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_feature(Feature.CYBER_CARD_ACCESS)),
):
    user_id = str(current_user.id)
    now = datetime.now(timezone.utc)

    # ── Step 1: Check eligibility (distinct scan types >= 2) ─────────────────
    eligible, distinct_count, scan_types = _check_eligibility(db, user_id)

    if not eligible:
        # User hasn't done enough varied scans yet — tell them clearly
        if distinct_count == 0:
            msg = "Run your first scan to start building your Cyber Safety Score."
        else:
            msg = "Run one more type of scan (email, password, or message) to unlock your score."
        return CyberCardPendingResponse(
            card_status        = "PENDING",
            message            = msg,
            eligible           = False,
            distinct_scan_types = distinct_count,
        )

    # ── Step 2: Eligible — fetch or compute score ─────────────────────────────
    try:
        card = _get_cyber_card(db, user_id)

        # Compute when card is absent or the cached score is stale (> 5 min)
        if card is None or _is_stale(card.get("updated_at"), now, _CACHE_TTL_SECONDS):
            _compute_and_upsert(db, user_id)
            card = _get_cyber_card(db, user_id)

    except SQLAlchemyError:
        logger.exception("cyber_card_fetch_failed", extra={"user_id": user_id})
        return CyberCardPendingResponse(
            card_status        = "PENDING",
            message            = "Your score is being prepared. Please try again in a moment.",
            eligible           = True,
            distinct_scan_types = distinct_count,
        )

    if not card:
        # Eligible but compute failed silently — show "preparing" not "no scans"
        return CyberCardPendingResponse(
            card_status        = "PENDING",
            message            = "Your Cyber Safety Score is being prepared. Please wait a moment.",
            eligible           = True,
            distinct_scan_types = distinct_count,
        )

    return CyberCardActiveResponse(
        card_status  = "ACTIVE",
        card_id      = card["card_id"],
        name         = card["name"],
        is_paid      = card["is_paid"],
        score        = card["score"],
        max_score    = 1000,
        risk_level   = card["risk_level"],
        level        = card["level"],
        signals      = card["signals"],
        factors      = card["factors"],
        insights     = card["insights"],
        actions      = card["actions"],
        score_month  = card["score_month"],
        updated_at   = card["updated_at"],
        score_version= "v2",
    )


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
            count=0, history=[], message="No Cyber Card history available yet"
        )

    return CyberCardHistoryResponse(count=len(history), history=history)
