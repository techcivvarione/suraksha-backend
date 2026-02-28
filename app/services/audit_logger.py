from fastapi import Request
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def create_audit_log(
    db: Session,
    event_type: str,
    event_description: str,
    request: Request | None = None,
    user_id=None,
    auto_commit: bool = True,
):
    ip_address = None
    user_agent = None

    if request is not None:
        if request.client:
            ip_address = request.client.host
        user_agent = request.headers.get("user-agent")

    log = AuditLog(
        user_id=user_id,
        event_type=event_type,
        event_description=event_description,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(log)
    if auto_commit:
        db.commit()
