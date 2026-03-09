import logging
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

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
                SELECT id
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

    def send_alert(self, db: Session, user_id: str, media_hash: str, analysis_type: str, risk_score: int):
        """
        Placeholder for push/email dispatch.
        Must not log PII. Only logs IDs at caller.
        """
        contact = self._get_primary_contact(db, user_id)
        if not contact:
            raise NotificationError("No primary trusted contact")
        # Future: send push/email to contact.id
        logger.info(
            "notify_primary_contact",
            extra={
                "user_id": user_id,
                "contact_id": contact["id"],
                "media_hash_prefix": media_hash[:8],
                "analysis_type": analysis_type,
                "risk_score": risk_score,
            },
        )
        return True
