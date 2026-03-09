import uuid
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert_event import AlertEvent
from app.routes.auth import get_current_user
from app.services.alert_rate_limiter import enforce_alert_limits, AlertRateLimiterError
from app.services.alert_validator import validate_request_payload, validate_recent_analysis
from app.services.notification_service import NotificationService, NotificationError
from sqlalchemy import text

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = logging.getLogger(__name__)
notifier = NotificationService()


@router.post("/media-risk", status_code=200)
def trigger_media_alert(
    payload: dict,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    correlation_id = uuid.uuid4().hex
    client_ip = request.client.host or "unknown"
    user_id = str(current_user.id)

    try:
        validate_request_payload(payload)
    except HTTPException:
        raise

    # confirm trusted contact exists
    contact = db.execute(
        text(
            """
            SELECT id
            FROM trusted_contacts
            WHERE owner_user_id = CAST(:uid AS uuid)
              AND status = 'ACTIVE'
            LIMIT 1
            """
        ),
        {"uid": user_id},
    ).first()
    if not contact:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No trusted contact configured")

    try:
        enforce_alert_limits(user_id, client_ip, payload["media_hash"])
    except AlertRateLimiterError as exc:
        msg = str(exc)
        if msg == "Duplicate alert within cooldown":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")

    # validate recent analysis (redis-backed freshness + ownership)
    validate_recent_analysis(db, user_id, payload["media_hash"])

    try:
        event = AlertEvent(
            user_id=current_user.id,
            media_hash=payload["media_hash"],
            analysis_type=payload["analysis_type"],
            risk_score=int(payload["risk_score"]),
            notified_contact_id=None,
            status="SENT",
        )
        db.add(event)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Unable to process alert")

    try:
        notifier.send_alert(
            db=db,
            user_id=user_id,
            media_hash=payload["media_hash"],
            analysis_type=payload["analysis_type"],
            risk_score=int(payload["risk_score"]),
        )
    except NotificationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to process alert")

    logger.info(
        "media_alert_sent",
        extra={
            "cid": correlation_id,
            "user_id": user_id,
            "ip": client_ip,
            "media_hash_prefix": payload["media_hash"][:8],
            "analysis_type": payload["analysis_type"],
            "risk_score": int(payload["risk_score"]),
        },
    )

    return {
        "status": "ALERT_SENT",
        "message": "Trusted contact notified successfully.",
    }
