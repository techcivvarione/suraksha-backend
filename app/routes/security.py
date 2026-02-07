from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.scam_report import ScamReport
from app.routes.auth import get_current_user, verify_password, hash_password
from app.services.audit_logger import create_audit_log
from app.services.evidence_exporter import generate_evidence_bundle

router = APIRouter(prefix="/security", tags=["Account Security"])


# =========================================================
# MODELS
# =========================================================

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


class ScamReportRequest(BaseModel):
    scam_type: str
    title: str
    description: str
    source: Optional[str] = None
    scam_value: Optional[str] = None


# =========================================================
# ACCOUNT SECURITY
# =========================================================

@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")

    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    current_user.password_hash = hash_password(payload.new_password)
    current_user.updated_at = datetime.utcnow()
    current_user.password_changed_at = datetime.utcnow()

    db.add(current_user)
    db.commit()

    create_audit_log(
        db=db,
        user_id=current_user.id,
        event_type="PASSWORD_CHANGED",
        event_description="User changed account password",
        request=None,
    )

    return {"status": "password_changed"}


@router.post("/logout-all")
def logout_all_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    current_user.updated_at = datetime.utcnow()
    db.add(current_user)
    db.commit()

    create_audit_log(
        db=db,
        user_id=current_user.id,
        event_type="LOGOUT_ALL",
        event_description="User logged out from all sessions",
        request=None,
    )

    return {"status": "all_sessions_logged_out"}


@router.get("/status")
def security_status(current_user: User = Depends(get_current_user)):
    return {
        "password_last_changed": current_user.password_changed_at,
        "session_model": "stateless JWT",
        "note": "All tokens issued before password change are invalid",
    }


# =========================================================
# SECURITY HEALTH SCORE (30 DAYS)
# =========================================================

@router.get("/health-score")
def security_health_score(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=30)

    rows = db.execute(
        text("""
            SELECT risk, COUNT(*) AS count, MAX(created_at) AS last_scan
            FROM scan_history
            WHERE user_id = CAST(:user_id AS uuid)
              AND created_at >= :since
            GROUP BY risk
        """),
        {
            "user_id": str(current_user.id),
            "since": since,
        },
    ).mappings().all()

    # base score
    score = 100

    stats = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    last_scan_at = None

    for row in rows:
        risk = row["risk"]
        count = row["count"]
        stats[risk] += count

        if row["last_scan"]:
            if not last_scan_at or row["last_scan"] > last_scan_at:
                last_scan_at = row["last_scan"]

    # scoring logic (transparent)
    score -= stats["high"] * 20
    score -= stats["medium"] * 10

    if sum(stats.values()) == 0:
        score -= 25  # no scans = blind spot

    score = max(0, min(100, score))

    if score >= 80:
        level = "good"
        summary = "Your digital security posture is strong."
    elif score >= 50:
        level = "warning"
        summary = "Some risks detected. Review recent activity."
    else:
        level = "critical"
        summary = "High risk detected. Immediate action advised."

    recommendations = []

    if stats["high"] > 0:
        recommendations.append("Review high-risk scans and secure affected accounts")

    if stats["medium"] > 0:
        recommendations.append("Be cautious with links and unknown messages")

    if sum(stats.values()) == 0:
        recommendations.append("Run your first security scan to establish baseline")

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "window": "last_30_days",
        "signals": {
            "total_scans": sum(stats.values()),
            "high_risk": stats["high"],
            "medium_risk": stats["medium"],
            "low_risk": stats["low"],
            "last_scan_at": last_scan_at,
        },
        "recommendations": recommendations,
    }


# =========================================================
# AUDIT LOGS
# =========================================================

@router.get("/audit-logs")
def get_audit_logs(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(AuditLog).filter(AuditLog.user_id == current_user.id)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)

    logs = (
        query.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "count": len(logs),
        "data": [
            {
                "event_type": log.event_type,
                "event_description": log.event_description,
                "ip_address": log.ip_address,
                "created_at": log.created_at,
            }
            for log in logs
        ],
    }


# =========================================================
# SCAM REPORTING
# =========================================================

@router.post("/scam-report")
def submit_scam_report(
    payload: ScamReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report = ScamReport(
        user_id=current_user.id,
        scam_type=payload.scam_type,
        title=payload.title,
        description=payload.description,
        source=payload.source,
        scam_value=payload.scam_value,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    create_audit_log(
        db=db,
        user_id=current_user.id,
        event_type="SCAM_REPORTED",
        event_description=f"Scam reported: {payload.title}",
        request=request,
    )

    return {
        "status": "reported",
        "report_id": str(report.id),
        "reported_at": report.reported_at,
    }


@router.get("/scam-reports")
def get_my_scam_reports(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    reports = (
        db.query(ScamReport)
        .filter(ScamReport.user_id == current_user.id)
        .order_by(ScamReport.reported_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "count": len(reports),
        "data": [
            {
                "id": str(r.id),
                "scam_type": r.scam_type,
                "title": r.title,
                "description": r.description,
                "source": r.source,
                "scam_value": r.scam_value,
                "reported_at": r.reported_at,
            }
            for r in reports
        ],
    }


# =========================================================
# EVIDENCE EXPORT
# =========================================================

@router.get("/evidence/export")
def export_evidence(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    bundle = generate_evidence_bundle(db, current_user)

    create_audit_log(
        db=db,
        user_id=current_user.id,
        event_type="EVIDENCE_EXPORTED",
        event_description="User exported security evidence",
        request=None,
    )

    return JSONResponse(
        content=bundle,
        headers={
            "Content-Disposition": "attachment; filename=go-suraksha-evidence.json"
        },
    )

@router.get("/health-trend")
def health_trend(
    days: int = Query(30, ge=7, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text("""
            SELECT score_date, score
            FROM daily_security_scores
            WHERE user_id = CAST(:uid AS uuid)
              AND score_date >= CURRENT_DATE - :days
            ORDER BY score_date ASC
        """),
        {"uid": str(current_user.id), "days": days},
    ).mappings().all()

    if not rows:
        return {
            "window_days": days,
            "current_score": None,
            "trend": [],
            "message": "Not enough data yet"
        }

    start = rows[0]["score"]
    end = rows[-1]["score"]

    change = end - start

    return {
        "window_days": days,
        "current_score": end,
        "trend": [
            {"date": r["score_date"], "score": r["score"]}
            for r in rows
        ],
        "change": change,
        "direction": "improving" if change > 0 else "declining" if change < 0 else "stable"
    }
