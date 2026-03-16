import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.schemas.alerts import MediaRiskAlertRequest, MediaRiskAlertResponse
from app.services.alert_rate_limiter import AlertRateLimiterError, enforce_alert_limits
from app.services.alert_validator import validate_recent_analysis, validate_request_payload
from app.services.security_alerts import create_alert_event, dispatch_plan_alerts
from app.services.security_plan_limits import allows_automatic_trusted_alerts, allows_family_alerts

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = logging.getLogger(__name__)


@router.get("")
def list_alerts(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    total = db.execute(text("SELECT COUNT(*) FROM alert_events WHERE user_id = CAST(:uid AS uuid)"), {"uid": str(current_user.id)}).scalar()
    rows = db.execute(
        text(
            """
            SELECT id, analysis_type, risk_score, created_at, status
            FROM alert_events
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {"uid": str(current_user.id), "limit": limit, "offset": offset},
    ).mappings().all()
    alerts = [_build_alert_response(row) for row in rows]
    payload = {"alerts": alerts, "total": int(total or 0), "page": (offset // limit) + 1}
    return {**payload, "data": payload}


@router.get("/summary")
def alert_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.execute(
        text(
            """
            SELECT id, analysis_type, risk_score, created_at, status
            FROM alert_events
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY created_at DESC
            """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()
    alerts = [_build_alert_response(row) for row in rows]
    payload = {
        "total_alerts": len(alerts),
        "high_risk": sum(1 for alert in alerts if alert["severity"] == "high"),
        "medium_risk": sum(1 for alert in alerts if alert["severity"] == "medium"),
        "low_risk": sum(1 for alert in alerts if alert["severity"] == "low"),
        "latest_alert": alerts[0] if alerts else None,
    }
    return {**payload, "data": payload}


@router.post("/media-risk", status_code=200, response_model=MediaRiskAlertResponse)
def trigger_media_alert(
    payload: MediaRiskAlertRequest,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    client_ip = request.client.host or "unknown"
    user_id = str(current_user.id)
    payload_data = payload.model_dump()
    validate_request_payload(payload_data)

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
        enforce_alert_limits(db, user_id, client_ip, payload.media_hash)
    except AlertRateLimiterError as exc:
        msg = str(exc)
        if msg == "Duplicate alert within cooldown":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=msg)

    validate_recent_analysis(db, user_id, payload.media_hash)

    try:
        event = create_alert_event(
            db,
            user_id=current_user.id,
            trigger_type="MEDIA_RISK_ALERT",
            media_hash=payload.media_hash,
            analysis_type=payload.analysis_type,
            risk_score=int(payload.risk_score),
            status="PENDING",
        )
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Unable to process alert")

    try:
        dispatch = dispatch_plan_alerts(db=db, user=current_user, trigger_type="MEDIA_RISK_ALERT", risk_score=int(payload.risk_score), scan_id=None, alert_event_id=event.id)
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
            "risk_score": int(payload.risk_score),
            "trusted_enabled": allows_automatic_trusted_alerts(current_user.plan),
            "family_enabled": allows_family_alerts(current_user.plan),
        },
    )
    return MediaRiskAlertResponse(status="ALERT_SENT", message="Alert processed successfully.", dispatch=dispatch)



def _build_alert_response(row) -> dict:
    severity = _severity_for_score(int(row["risk_score"]))
    title = _title_for_alert(str(row["analysis_type"]), severity)
    return {
        "id": row["id"],
        "alert_type": str(row["analysis_type"]).upper(),
        "severity": severity,
        "title": title,
        "description": _description_for_alert(str(row["analysis_type"]), int(row["risk_score"]), row["status"]),
        "created_at": row["created_at"],
        "related_scan_id": None,
    }


def _severity_for_score(risk_score: int) -> str:
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def _title_for_alert(alert_type: str, severity: str) -> str:
    return f"{severity.title()} Risk {alert_type.replace('_', ' ').title()}"


def _description_for_alert(alert_type: str, risk_score: int, status: str) -> str:
    return f"{alert_type.replace('_', ' ').lower()} triggered with risk score {risk_score}. Status: {status.lower()}."
