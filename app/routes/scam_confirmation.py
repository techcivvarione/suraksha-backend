from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User
from app.models.scam_report import ScamReport
from app.services.audit_logger import create_audit_log

router = APIRouter(prefix="/scam", tags=["Scam Confirmation"])

@router.post("/confirm")
def confirm_scam(
    request: Request,
    scam_type: str,
    title: str,
    description: str,
    loss_amount: str | None = None,
    source: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔒 one confirmation per month
    exists = db.execute(
        text("""
            SELECT 1 FROM scam_reports
            WHERE user_id = CAST(:uid AS uuid)
              AND reported_at >= date_trunc('month', now())
        """),
        {"uid": str(current_user.id)},
    ).first()

    if exists:
        raise HTTPException(
            status_code=400,
            detail="Scam already confirmed for this month",
        )

    report = ScamReport(
        user_id=current_user.id,
        scam_type=scam_type,
        title=title,
        description=description,
        source=source,
        scam_value=loss_amount,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    # 🔐 audit
    create_audit_log(
        db=db,
        user_id=current_user.id,
        event_type="SCAM_CONFIRMED",
        event_description="User confirmed scam incident",
        request=request,
    )

    return {
        "status": "confirmed",
        "report_id": str(report.id),
        "penalty": -300,
        "message": "Cyber Score penalized for this month",
        "next_steps": {
            "india_helpline": "1930",
            "cybercrime_portal": "https://www.cybercrime.gov.in",
        },
    }
