import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.routes.auth import get_current_user
from app.services.alert_rate_limiter import enforce_alert_limits, AlertRateLimiterError
from app.services.alert_validator import validate_request_payload, validate_recent_analysis
from app.services.security_alerts import create_alert_event, dispatch_plan_alerts
from app.services.security_plan_limits import allows_automatic_trusted_alerts, allows_family_alerts
from sqlalchemy import text

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = logging.getLogger(__name__)


@router.post("/media-risk", status_code=200)
def trigger_media_alert(
    payload: dict,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    client_ip = request.client.host or "unknown"
    user_id = str(current_user.id)

    try:
        validate_request_payload(payload)
    except HTTPException:
        raise

    if allows_automatic_trusted_alerts(current_user.plan):
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
        enforce_alert_limits(db, user_id, client_ip, payload["media_hash"])
    except AlertRateLimiterError as exc:
        msg = str(exc)
        if msg == "Duplicate alert within cooldown":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=msg)

    # validate recent analysis (redis-backed freshness + ownership)
    validate_recent_analysis(db, user_id, payload["media_hash"])

    try:
        event = create_alert_event(
            db,
            user_id=current_user.id,
            trigger_type="MEDIA_RISK_ALERT",
            media_hash=payload["media_hash"],
            analysis_type=payload["analysis_type"],
            risk_score=int(payload["risk_score"]),
            status="PENDING",
        )
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Unable to process alert")

    try:
        dispatch = dispatch_plan_alerts(
            db=db,
            user=current_user,
            trigger_type="MEDIA_RISK_ALERT",
            scan_id=None,
            alert_event_id=event.id,
        )
        event.status = "SENT"
        db.add(event)
        db.commit()
    except Exception:
        event.status = "FAILED"
        db.add(event)
        db.commit()
        raise HTTPException(status_code=500, detail="Unable to process alert")

    logger.info(
        "media_alert_sent",
        extra={
            "alert_event_id": event.id,
            "user_id": user_id,
            "ip": client_ip,
            "media_hash_prefix": payload["media_hash"][:8],
            "analysis_type": payload["analysis_type"],
            "risk_score": int(payload["risk_score"]),
            "trusted_enabled": allows_automatic_trusted_alerts(current_user.plan),
            "family_enabled": allows_family_alerts(current_user.plan),
        },
    )

    return {
        "status": "ALERT_SENT",
        "message": "Alert processed successfully.",
        "dispatch": dispatch,
    }
