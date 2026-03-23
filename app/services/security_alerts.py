from __future__ import annotations

import hashlib
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.alert_event import AlertEvent
from app.services.alert_logging import log_alert_event
from app.services.family_alerts import notify_family_head
from app.services.notification_service import NotificationService, NotificationError
from app.services.security_plan_limits import (
    allows_automatic_trusted_alerts,
    allows_family_alerts,
    normalized_plan,
)
from app.services.trusted_alerts import notify_trusted_contacts

logger = logging.getLogger(__name__)
notifier = NotificationService()


def create_alert_event(
    db: Session,
    *,
    user_id,
    trigger_type: str,
    risk_score: int,
    media_hash: str | None = None,
    analysis_type: str = "SYSTEM",
    status: str = "PENDING",
    # STEP 6: richer signal fields
    scan_type: str | None = None,
    risk_level: str | None = None,
    extra_signals: dict | None = None,
) -> AlertEvent:
    # STEP 1: mandatory field validation — skip if risk_score is unusable
    if risk_score is None:
        raise ValueError("risk_score is required for alert creation")

    derived_risk_level = risk_level or _risk_level_for_score(int(risk_score))

    event = AlertEvent(
        user_id=user_id,
        media_hash=media_hash or _build_event_hash(
            user_id=str(user_id), trigger_type=trigger_type, risk_score=risk_score
        ),
        analysis_type=(analysis_type or "SYSTEM")[:10],
        risk_score=int(risk_score),
        notified_contact_id=None,
        status=status,
        scan_type=(scan_type or analysis_type or "SYSTEM")[:20] if scan_type or analysis_type else None,
        risk_level=derived_risk_level,
        extra_signals=extra_signals,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # STEP 1: structured alert_created log for every alert
    logger.info(
        "alert_created",
        extra={
            "alert_event_id": event.id,
            "user_id":        str(user_id),
            "trigger_type":   trigger_type,
            "risk_score":     int(risk_score),
            "risk_level":     derived_risk_level,
            "scan_type":      event.scan_type,
            "analysis_type":  event.analysis_type,
        },
    )

    log_alert_event(
        alert_event_id=event.id,
        user_id=str(user_id),
        trigger_type=trigger_type,
        delivery_method="event_record",
        status=status,
    )
    return event


def dispatch_plan_alerts(
    db: Session,
    *,
    user,
    trigger_type: str,
    risk_score: int = 0,
    scan_id: str | None = None,
    alert_event_id: int | None = None,
    force_trusted: bool = False,
) -> dict[str, Any]:
    plan = normalized_plan(getattr(user, "plan", None))
    push_result = {"delivered": 0}
    trusted_result = {"stored": 0, "delivered": 0}
    family_result = {"stored": 0}

    try:
        push_deliveries = notifier.send_alert(
            db=db,
            user_id=str(user.id),
            media_hash=str(alert_event_id or scan_id or trigger_type),
            analysis_type=trigger_type,
            risk_score=int(risk_score or 0),
            alert_event_id=alert_event_id,
            title="GO Suraksha Alert",
            body=_user_alert_body(trigger_type),
        )
        push_result = {"delivered": len(push_deliveries)}
    except NotificationError:
        push_result = {"delivered": 0}

    if force_trusted or allows_automatic_trusted_alerts(plan):
        trusted_result = notify_trusted_contacts(
            db=db,
            user_id=str(user.id),
            scan_id=scan_id,
            alert_type=trigger_type,
            alert_event_id=alert_event_id,
        )

    if allows_family_alerts(plan):
        family_result = notify_family_head(
            db=db,
            member_user_id=str(user.id),
            scan_id=scan_id,
            alert_type=trigger_type,
            alert_event_id=alert_event_id,
        )

    return {
        "plan": plan,
        "user_push": push_result,
        "trusted_alerts": trusted_result,
        "family_alerts": family_result,
    }


def try_create_scan_alert(
    db: Session,
    *,
    user,
    client_ip: str | None,
    risk_score: int,
    analysis_type: str,
    scan_id: str | None = None,
    extra_signals: dict | None = None,
) -> None:
    """
    Non-throwing helper: create an alert_event for MEDIUM (≥40) or HIGH (≥70)
    risk scans.  Safe to call from any scan route — never raises.

    STEP 5: Smart severity — if extra_signals contains phishing_detected=True
    or suspicious_domain=True, the effective risk is upgraded to HIGH (≥70)
    even if the numeric score is lower.
    """
    # STEP 1: validate inputs before doing anything
    if risk_score is None:
        logger.warning("try_create_scan_alert: risk_score is None, skipping", extra={"analysis_type": analysis_type})
        return

    # STEP 5: smart severity upgrade from extra signals
    effective_score = int(risk_score)
    signals = extra_signals or {}
    if signals.get("phishing_detected") or signals.get("suspicious_domain"):
        effective_score = max(effective_score, 70)  # force HIGH

    if effective_score < 40:
        return

    trigger = (
        f"{analysis_type.upper()}_HIGH_RISK_SCAN"
        if effective_score >= 70
        else f"{analysis_type.upper()}_MEDIUM_RISK_SCAN"
    )
    try:
        from app.services.alert_rate_limiter import enforce_alert_limits  # local import avoids circular
        enforce_alert_limits(db, str(user.id), client_ip, None,
                             plan=getattr(user, "plan", None))
        event = create_alert_event(
            db=db,
            user_id=user.id,
            trigger_type=trigger,
            analysis_type=analysis_type[:10],
            risk_score=effective_score,
            scan_type=analysis_type.upper()[:20],
            risk_level=_risk_level_for_score(effective_score),
            extra_signals=extra_signals,
        )
        dispatch_plan_alerts(
            db=db,
            user=user,
            trigger_type=trigger,
            risk_score=effective_score,
            scan_id=scan_id,
            alert_event_id=event.id,
        )
        event.status = "SENT"
        db.add(event)
        db.commit()
    except Exception:
        # STEP 2 — Alert system must NEVER break the scan.
        # Log the failure so it is visible in monitoring, but do NOT re-raise.
        logger.exception(
            "alert_creation_failed",
            extra={
                "analysis_type": analysis_type,
                "risk_score":    risk_score,
                "user_id":       str(getattr(user, "id", "unknown")),
            },
        )


def _risk_level_for_score(risk_score: int) -> str:
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def _build_event_hash(*, user_id: str, trigger_type: str, risk_score: int) -> str:
    payload = f"{user_id}:{trigger_type}:{risk_score}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _user_alert_body(trigger_type: str) -> str:
    label = trigger_type.replace("_", " ").lower()
    return f"High risk {label} detected on your device"
