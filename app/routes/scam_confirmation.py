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


def _compose_scam_description(*, title: str, description: str, source: str | None = None, loss_amount: str | None = None) -> str:
    parts = [f"Title: {title}", description]
    if source:
        parts.append(f"Source: {source}")
    if loss_amount:
        parts.append(f"Loss amount: {loss_amount}")
    return "\n".join(parts)

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
              AND created_at >= date_trunc('month', now())
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
        report_type="payment" if loss_amount else "call",
        category=scam_type,
        phishing_url=source if source and source.lower().startswith(("http://", "https://")) else None,
        normalized_url=source if source and source.lower().startswith(("http://", "https://")) else None,
        scam_description=_compose_scam_description(
            title=title,
            description=description,
            source=source,
            loss_amount=loss_amount,
        ),
        status="REPORTED",
        visibility_status="SUSPICIOUS",
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
