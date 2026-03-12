import logging
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.email_service import send_email as send_email_message
from app.services.alert_logging import log_alert_event
from app.services.firebase_service import send_push_notification as send_firebase_push

logger = logging.getLogger(__name__)


class NotificationError(Exception):
    pass


class NotificationService:
    def __init__(self):
        pass

    def _get_primary_contact(self, db: Session, user_id: str) -> Optional[dict]:
        row = db.execute(
            text(
                """
                SELECT id, contact_email, contact_phone, contact_user_id
                FROM trusted_contacts
                WHERE owner_user_id = CAST(:uid AS uuid)
                  AND is_primary = true
                  AND status = 'ACTIVE'
                LIMIT 1
                """
            ),
            {"uid": user_id},
        ).mappings().first()
        return row

    def _get_user_device_tokens(self, db: Session, user_id: str) -> list[str]:
        rows = db.execute(
            text(
                """
                SELECT device_token
                FROM user_devices
                WHERE user_id = CAST(:uid AS uuid)
                ORDER BY updated_at DESC
                """
            ),
            {"uid": user_id},
        ).mappings().all()
        return [row["device_token"] for row in rows if row.get("device_token")]

    def send_email(self, *, to_email: str, subject: str, html_body: str, alert_event_id=None, user_id: str | None = None):
        send_email_message(to_email=to_email, subject=subject, html_body=html_body)
        log_alert_event(
            alert_event_id=alert_event_id,
            user_id=user_id or "unknown",
            trigger_type="EMAIL_ALERT",
            delivery_method="email",
            status="SENT",
        )
        return {"delivery_method": "email", "status": "SENT"}

    def send_push_notification(self, *, db: Session | None = None, contact_user_id=None, device_token: str | None = None, title: str, body: str, alert_event_id=None, user_id: str | None = None):
        if device_token:
            message_id = send_firebase_push(
                token=device_token,
                title=title,
                body=body,
                data={"type": "security_alert", "user_id": user_id or ""},
            )
            log_alert_event(
                alert_event_id=alert_event_id,
                user_id=user_id or "unknown",
                trigger_type=title,
                delivery_method="push",
                status="SENT",
            )
            return {"delivery_method": "push", "status": "SENT", "message_id": message_id}

        if db is not None and contact_user_id:
            deliveries = []
            for token in self._get_user_device_tokens(db, str(contact_user_id)):
                deliveries.append(
                    self.send_push_notification(
                        device_token=token,
                        title=title,
                        body=body,
                        alert_event_id=alert_event_id,
                        user_id=user_id,
                    )
                )
            if deliveries:
                return {
                    "delivery_method": "push",
                    "status": "SENT",
                    "deliveries": deliveries,
                }

        # TODO: wire stored FCM tokens once device token persistence is added.
        log_alert_event(
            alert_event_id=alert_event_id,
            user_id=user_id or "unknown",
            trigger_type=title,
            delivery_method="push",
            status="PENDING_PROVIDER",
        )
        logger.info(
            "push_delivery_pending",
            extra={"contact_user_id": str(contact_user_id) if contact_user_id else None},
        )
        return {"delivery_method": "push", "status": "PENDING_PROVIDER"}

    def send_alert(
        self,
        db: Session,
        user_id: str,
        media_hash: str,
        analysis_type: str,
        risk_score: int,
        *,
        alert_event_id=None,
        title: str | None = None,
        body: str | None = None,
    ):
        """
        Best-effort alert delivery to the user's registered devices.
        """
        deliveries = []
        for token in self._get_user_device_tokens(db, user_id):
            deliveries.append(
                self.send_push_notification(
                    device_token=token,
                    title=title or "GO Suraksha Alert",
                    body=body or f"High risk {analysis_type.lower()} detected on your device",
                    alert_event_id=alert_event_id,
                    user_id=user_id,
                )
            )

        if not deliveries:
            raise NotificationError("No registered device tokens")

        logger.info(
            "notify_user_devices",
            extra={
                "user_id": user_id,
                "media_hash_prefix": media_hash[:8],
                "analysis_type": analysis_type,
                "risk_score": risk_score,
                "delivery_count": len(deliveries),
            },
        )
        return deliveries
