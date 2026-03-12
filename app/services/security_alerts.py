from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy.orm import Session

from app.models.alert_event import AlertEvent
from app.services.alert_logging import log_alert_event
from app.services.family_alerts import notify_family_head
from app.services.security_plan_limits import (
    allows_automatic_trusted_alerts,
    allows_family_alerts,
    normalized_plan,
)
from app.services.trusted_alerts import notify_trusted_contacts

def create_alert_event(
    db: Session,
    *,
    user_id,
    trigger_type: str,
    risk_score: int,
    media_hash: str | None = None,
    analysis_type: str = "SYSTEM",
    status: str = "PENDING",
) -> AlertEvent:
    event = AlertEvent(
        user_id=user_id,
        media_hash=media_hash or _build_event_hash(user_id=str(user_id), trigger_type=trigger_type, risk_score=risk_score),
        analysis_type=(analysis_type or "SYSTEM")[:10],
        risk_score=int(risk_score),
        notified_contact_id=None,
        status=status,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
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
    scan_id: str | None = None,
    alert_event_id: int | None = None,
    force_trusted: bool = False,
) -> dict[str, Any]:
    plan = normalized_plan(getattr(user, "plan", None))
    trusted_result = {"stored": 0, "delivered": 0}
    family_result = {"stored": 0}

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
        "trusted_alerts": trusted_result,
        "family_alerts": family_result,
    }
def _build_event_hash(*, user_id: str, trigger_type: str, risk_score: int) -> str:
    payload = f"{user_id}:{trigger_type}:{risk_score}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
