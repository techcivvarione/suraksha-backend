from datetime import datetime
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.scam_report import ScamReport


def _dt(value):
    """Convert datetime to ISO string safely."""
    if value is None:
        return None
    return value.isoformat()


def generate_evidence_bundle(db: Session, user: User):
    audit_logs = (
        db.query(AuditLog)
        .filter(AuditLog.user_id == user.id)
        .order_by(AuditLog.created_at.desc())
        .all()
    )

    scam_reports = (
        db.query(ScamReport)
        .filter(ScamReport.user_id == user.id)
        .order_by(ScamReport.reported_at.desc())
        .all()
    )

    return {
        "generated_at": _dt(datetime.utcnow()),
        "user": {
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "account_created_at": _dt(user.created_at),
            "password_changed_at": _dt(user.password_changed_at),
        },
        "audit_logs": [
            {
                "event_type": log.event_type,
                "description": log.event_description,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "created_at": _dt(log.created_at),
            }
            for log in audit_logs
        ],
        "scam_reports": [
            {
                "id": str(r.id),
                "scam_type": r.scam_type,
                "title": r.title,
                "description": r.description,
                "source": r.source,
                "scam_value": r.scam_value,
                "reported_at": _dt(r.reported_at),
            }
            for r in scam_reports
        ],
    }
