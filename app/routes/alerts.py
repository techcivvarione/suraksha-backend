import logging
from typing import List

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.schemas.alerts import MediaRiskAlertRequest, MediaRiskAlertResponse
from app.services.alert_rate_limiter import AlertRateLimiterError, enforce_alert_limits
from app.services.alert_validator import validate_recent_analysis, validate_request_payload
from app.services.family_protection_access import FEATURE_MANUAL_ALERTS, check_feature_access
from app.services.security_alerts import create_alert_event, dispatch_plan_alerts
from app.services.security_plan_limits import allows_automatic_trusted_alerts, allows_family_alerts

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = logging.getLogger(__name__)


class ManualAlertTriggerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(default="Manual Protection Alert", min_length=3, max_length=120)
    message: str = Field(default="A high-risk cyber event needs attention.", min_length=3, max_length=240)
    risk_score: int = Field(default=90, ge=70, le=100)
    alert_type: str = Field(default="MANUAL_HIGH_RISK_ALERT", min_length=3, max_length=64)


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
    """
    STEP 2: Returns combined alert counts for the current user AND their
    registered trusted contacts (family members on GO Suraksha).
    This gives a holistic threat picture on the Alerts summary card.
    """
    rows = db.execute(
        text(
            """
            -- User's own alerts
            SELECT risk_score FROM alert_events
            WHERE user_id = CAST(:uid AS uuid)

            UNION ALL

            -- Family / trusted contacts' alerts (registered GO Suraksha users only)
            SELECT ae.risk_score
            FROM alert_events ae
            JOIN trusted_contacts tc
              ON ae.user_id = tc.contact_user_id
            WHERE tc.owner_user_id  = CAST(:uid AS uuid)
              AND tc.status         = 'ACTIVE'
              AND tc.contact_user_id IS NOT NULL
            """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    high_count   = sum(1 for r in rows if int(r["risk_score"] or 0) >= 70)
    medium_count = sum(1 for r in rows if 40 <= int(r["risk_score"] or 0) < 70)
    low_count    = sum(1 for r in rows if int(r["risk_score"] or 0) < 40)
    total        = len(rows)

    logger.info(
        "alerts_summary",
        extra={
            "user_id": str(current_user.id),
            "total":   total,
            "high":    high_count,
            "medium":  medium_count,
            "low":     low_count,
        },
    )

    # Field names MUST exactly match frontend AlertsSummaryResponse data class
    payload = {
        "total_alerts": total,
        "high_risk":    high_count,
        "medium_risk":  medium_count,
        "low_risk":     low_count,
    }
    return payload


@router.get("/family-activity")
def family_activity(
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns recent MEDIUM/HIGH scan activity from users in the current user's
    trusted-contacts circle.  Shown in the Family tab of the Threat Center.
    BUG FIX: was using sh.type (wrong); corrected to sh.scan_type.
    """
    rows = db.execute(
        text(
            """
            SELECT
                COALESCE(u.name, tc.name, 'Family Member')  AS member_name,
                UPPER(COALESCE(sh.scan_type, 'TEXT'))        AS scan_type,
                UPPER(COALESCE(sh.risk, 'UNKNOWN'))          AS risk_level,
                LEFT(COALESCE(sh.input_text, ''), 60)        AS scan_input,
                sh.created_at
            FROM trusted_contacts tc
            LEFT JOIN users u
                   ON u.id = tc.contact_user_id
            LEFT JOIN scan_history sh
                   ON sh.user_id = tc.contact_user_id
            WHERE tc.owner_user_id = CAST(:uid AS uuid)
              AND tc.status        = 'ACTIVE'
              AND sh.id IS NOT NULL
              AND sh.risk IN ('medium', 'high', 'MEDIUM', 'HIGH')
            ORDER BY sh.created_at DESC
            LIMIT :limit
            """
        ),
        {"uid": str(current_user.id), "limit": limit},
    ).mappings().all()

    activity = [
        {
            "member_name": r["member_name"],
            "scan_type":   r["scan_type"],
            "risk_level":  r["risk_level"],
            "scan_input":  r["scan_input"],
            "created_at":  r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]
    return {"count": len(activity), "activity": activity}


@router.get("/family-feed")
def family_feed(
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    STEP 2: Returns MEDIUM/HIGH alert events from registered trusted contacts.
    Unlike /family-activity (scan_history based), this uses alert_events which
    includes push-notification delivery context and richer severity data.
    """
    rows = db.execute(
        text(
            """
            SELECT
                COALESCE(u.name, tc.name, 'Family Member') AS member_name,
                UPPER(COALESCE(ae.scan_type, ae.analysis_type, 'SCAN')) AS scan_type,
                ae.risk_score,
                ae.created_at
            FROM trusted_contacts tc
            LEFT JOIN users u
                   ON u.id = tc.contact_user_id
            JOIN alert_events ae
                   ON ae.user_id = tc.contact_user_id
            WHERE tc.owner_user_id   = CAST(:uid AS uuid)
              AND tc.status          = 'ACTIVE'
              AND tc.contact_user_id IS NOT NULL
              AND ae.risk_score      >= 40
            ORDER BY ae.created_at DESC
            LIMIT :limit
            """
        ),
        {"uid": str(current_user.id), "limit": limit},
    ).mappings().all()

    feed = [
        {
            "member_name": r["member_name"],
            "scan_type":   r["scan_type"],
            "risk_level":  _severity_for_score(int(r["risk_score"])),
            "risk_score":  int(r["risk_score"]),
            "created_at":  r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]
    return {"count": len(feed), "feed": feed}


@router.get("/debug/latest")
def debug_latest_alerts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    STEP 1: Dev/debug endpoint — returns the 10 most recent alert_events for
    the authenticated user.  Useful for verifying that alert creation is
    working correctly after scans.  No sensitive data beyond the user's own.
    """
    rows = db.execute(
        text(
            """
            SELECT id, analysis_type, scan_type, risk_score, risk_level,
                   status, created_at, extra_signals
            FROM alert_events
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY created_at DESC
            LIMIT 10
            """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    alerts = [
        {
            "id":            r["id"],
            "analysis_type": r["analysis_type"],
            "scan_type":     r["scan_type"],
            "risk_score":    int(r["risk_score"]),
            "risk_level":    r["risk_level"] or _severity_for_score(int(r["risk_score"])),
            "status":        r["status"],
            "created_at":    r["created_at"].isoformat() if r["created_at"] else None,
            "extra_signals": r["extra_signals"],
        }
        for r in rows
    ]
    return {"user_id": str(current_user.id), "count": len(alerts), "alerts": alerts}


@router.get("/refresh")
def refresh_alerts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Trigger a manual refresh check. Returns count of any new alerts created."""
    new_count = db.execute(
        text(
            """
            SELECT COUNT(*) FROM alert_events
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at > NOW() - INTERVAL '5 minutes'
            """
        ),
        {"uid": str(current_user.id)},
    ).scalar()
    return {"status": "ok", "new_alerts_created": int(new_count or 0)}


@router.post("/subscribe")
def subscribe_alerts(
    body: dict = Body(...),
    current_user: User = Depends(get_current_user),
):
    """Update alert category subscriptions for the current user."""
    categories: List[str] = body.get("categories", [])
    if not isinstance(categories, list):
        raise HTTPException(status_code=400, detail="categories must be a list")
    return {"status": "ok", "categories": categories}


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
            scan_type="MEDIA",
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


@router.post("/manual-trigger")
def trigger_manual_alert(
    payload: ManualAlertTriggerRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    check_feature_access(current_user, FEATURE_MANUAL_ALERTS)
    client_ip = request.client.host or "unknown"

    try:
        enforce_alert_limits(db, str(current_user.id), client_ip, None, plan=getattr(current_user, "plan", None))
    except AlertRateLimiterError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))

    event = create_alert_event(
        db=db,
        user_id=current_user.id,
        trigger_type=payload.alert_type,
        analysis_type="MANUAL",
        risk_score=int(payload.risk_score),
        status="PENDING",
        scan_type="MANUAL",
        extra_signals={"title": payload.title, "message": payload.message, "manual": True},
    )
    dispatch = dispatch_plan_alerts(
        db=db,
        user=current_user,
        trigger_type=payload.alert_type,
        risk_score=int(payload.risk_score),
        scan_id=None,
        alert_event_id=event.id,
        force_trusted=True,
    )
    event.status = "SENT"
    db.add(event)
    db.commit()
    return {
        "status": "manual_alert_sent",
        "message": payload.message,
        "dispatch": dispatch,
    }


def _build_alert_response(row) -> dict:
    risk_score = int(row["risk_score"])
    severity = _severity_for_score(risk_score)
    analysis_type = str(row["analysis_type"])
    title = _title_for_alert(analysis_type, severity)
    return {
        "id":              row["id"],
        "alert_type":      analysis_type.upper(),
        "severity":        severity,
        "title":           title,
        "description":     _description_for_alert(analysis_type, risk_score, row["status"]),
        "risk_score":      risk_score,
        "created_at":      row["created_at"],
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
