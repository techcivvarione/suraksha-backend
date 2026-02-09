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
from app.services.cyber_complaint_generator import generate_cyber_complaint_text

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


# 🔹 NEW — Cyber Complaint Preview
class CyberComplaintPreviewRequest(BaseModel):
    scam_type: str
    incident_date: str
    description: str
    loss_amount: Optional[str] = None


# 🔹 NEW — Cyber SOS Request (FIX)
class CyberSOSRequest(BaseModel):
    scam_type: str
    incident_date: str
    description: str
    loss_amount: Optional[str] = None
    source: Optional[str] = None


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
        {"user_id": str(current_user.id), "since": since},
    ).mappings().all()

    score = 100
    stats = {"high": 0, "medium": 0, "low": 0}
    last_scan_at = None

    for row in rows:
        stats[row["risk"]] += row["count"]
        if row["last_scan"]:
            last_scan_at = max(last_scan_at or row["last_scan"], row["last_scan"])

    score -= stats["high"] * 20
    score -= stats["medium"] * 10

    if sum(stats.values()) == 0:
        score -= 25

    score = max(0, min(100, score))

    level = "good" if score >= 80 else "warning" if score >= 50 else "critical"

    return {
        "score": score,
        "level": level,
        "window": "last_30_days",
        "signals": {
            "total_scans": sum(stats.values()),
            "high_risk": stats["high"],
            "medium_risk": stats["medium"],
            "low_risk": stats["low"],
            "last_scan_at": last_scan_at,
        },
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

    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()

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

    return {"status": "reported", "report_id": str(report.id)}


# =========================================================
# 🧾 CYBER COMPLAINT PREVIEW (NEW)
# =========================================================

@router.post("/cyber-complaint/preview")
def preview_cyber_complaint(
    payload: CyberComplaintPreviewRequest,
    current_user: User = Depends(get_current_user),
):
    complaint_text = generate_cyber_complaint_text(
        user_name=current_user.name,
        phone=current_user.phone or "Not provided",
        email=current_user.email,
        scam_type=payload.scam_type,
        incident_date=payload.incident_date,
        loss_amount=payload.loss_amount,
        description=payload.description,
    )

    return {
        "helpline": "1930",
        "portal": "https://cybercrime.gov.in",
        "complaint_text": complaint_text.strip(),
        "note": "Copy and paste this text into cybercrime.gov.in",
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
        headers={"Content-Disposition": "attachment; filename=go-suraksha-evidence.json"},
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
        return {"window_days": days, "trend": []}

    return {
        "window_days": days,
        "current_score": rows[-1]["score"],
        "trend": [{"date": r["score_date"], "score": r["score"]} for r in rows],
    }

# =========================================================
# 🚨 SCAM CONFIRMATION (FINAL – SCORE IMPACT)
# =========================================================

class ScamConfirmRequest(BaseModel):
    scam_type: str
    title: str
    description: str
    source: Optional[str] = None
    scam_value: Optional[str] = None


@router.post("/scam-confirm")
def confirm_scam(
    payload: ScamConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    FINAL confirmation.
    Triggers Cyber Score penalty via monthly job.
    """

    # 1️⃣ Block multiple confirmations in same month
    already = db.execute(
        text("""
            SELECT 1 FROM scam_reports
            WHERE user_id = CAST(:uid AS uuid)
              AND reported_at >= date_trunc('month', now())
            LIMIT 1
        """),
        {"uid": str(current_user.id)},
    ).first()

    if already:
        raise HTTPException(
            status_code=400,
            detail="Scam already confirmed this month",
        )

    # 2️⃣ Insert scam report
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

    # 3️⃣ Audit log (CRITICAL)
    create_audit_log(
        db=db,
        user_id=current_user.id,
        event_type="SCAM_CONFIRMED",
        event_description="User confirmed scam incident",
        request=request,
    )

    # 4️⃣ Notify trusted + family (best-effort)
    try:
        from app.services.trusted_alerts import notify_trusted_contacts
        from app.services.family_alerts import notify_family_head

        notify_trusted_contacts(
            db=db,
            user_id=str(current_user.id),
            scan_id=None,
            alert_type="SCAM_CONFIRMED",
        )

        notify_family_head(
            db=db,
            member_user_id=str(current_user.id),
            scan_id=None,
        )
    except Exception:
        pass  # never block confirmation

    return {
        "status": "scam_confirmed",
        "penalty": "-300 (this month only)",
        "helpline": "1930",
        "portal": "https://cybercrime.gov.in",
        "next_steps": [
            "Call 1930 immediately if financial loss occurred",
            "File complaint on cybercrime.gov.in",
            "Change passwords and secure accounts",
        ],
    }

# =========================================================
# CYBER SOS — SCAM CONFIRMATION & COMPLAINT ASSIST
# =========================================================

@router.post("/cyber-sos/confirm")
def cyber_sos_confirm(
    payload: CyberSOSRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔒 One Cyber SOS per month (DB already enforces this)
    month_start = db.execute(
        text("SELECT date_trunc('month', now() AT TIME ZONE 'Asia/Kolkata')")
    ).scalar()

    existing = db.execute(
        text("""
            SELECT id
            FROM scam_reports
            WHERE user_id = CAST(:uid AS uuid)
              AND reported_at >= :start
        """),
        {"uid": str(current_user.id), "start": month_start},
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "CYBER_SOS_ALREADY_USED",
                "message": "Cyber SOS can be used only once per month"
            }
        )

    # 🧾 Insert confirmed scam
    report = ScamReport(
        user_id=current_user.id,
        scam_type=payload.scam_type,
        title="Cyber SOS – Confirmed Scam",
        description=payload.description,
        source=payload.source,
        scam_value=payload.loss_amount,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    # 🧮 Cyber Card penalty handled automatically by monthly job

    # 📝 Generate complaint text (copy-ready)
    complaint_text = generate_cyber_complaint_text(
        user=current_user,
        scam_type=payload.scam_type,
        incident_date=payload.incident_date,
        description=payload.description,
        loss_amount=payload.loss_amount,
        source=payload.source,
    )

    # 🧾 Audit
    create_audit_log(
        db=db,
        user_id=current_user.id,
        event_type="CYBER_SOS_CONFIRMED",
        event_description="User confirmed scam via Cyber SOS",
        request=request,
    )

    return {
        "status": "CYBER_SOS_CONFIRMED",
        "emergency_contact": {
            "india_helpline": "1930",
            "portal": "https://cybercrime.gov.in"
        },
        "complaint_copy": complaint_text,
        "next_steps": [
            "Call 1930 immediately if financial fraud occurred",
            "Paste the complaint text on cybercrime.gov.in",
            "Upload screenshots, transaction proof, messages",
            "Change passwords & secure affected accounts"
        ]
    }
