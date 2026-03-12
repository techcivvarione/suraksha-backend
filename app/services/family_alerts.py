import uuid
import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.alert_logging import log_alert_event
from app.services.notification_service import NotificationService

logger = logging.getLogger(__name__)
notifier = NotificationService()


def notify_family_head(
    db: Session,
    member_user_id: str,
    scan_id: str,
    alert_type: str = "HIGH_RISK_FAMILY_ALERT",
    alert_event_id=None,
):
    family_head = db.execute(
        text(
            """
            SELECT owner_user_id
            FROM trusted_contacts
            WHERE contact_user_id = CAST(:member_id AS uuid)
              AND status = 'ACTIVE'
            LIMIT 1
        """
        ),
        {"member_id": member_user_id},
    ).scalar()

    if not family_head:
        return {"stored": 0}

    db.execute(
        text(
            """
            INSERT INTO family_alerts (
                id,
                family_head_user_id,
                member_user_id,
                scan_id,
                alert_type
            )
            VALUES (
                :id,
                :family_head,
                :member,
                :scan,
                :alert_type
            )
        """
        ),
        {
            "id": str(uuid.uuid4()),
            "family_head": family_head,
            "member": member_user_id,
            "scan": scan_id,
            "alert_type": alert_type,
        },
    )

    db.commit()
    log_alert_event(
        alert_event_id=alert_event_id,
        user_id=str(member_user_id),
        trigger_type=alert_type,
        delivery_method="family_dashboard",
        status="STORED",
    )
    notifier.send_push_notification(
        db=db,
        contact_user_id=family_head,
        title=alert_type,
        body="A family member triggered a security alert.",
        alert_event_id=alert_event_id,
        user_id=str(member_user_id),
    )
    return {"stored": 1}
