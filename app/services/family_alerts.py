import uuid
import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature, has_feature

logger = logging.getLogger(__name__)


def notify_family_head(
    db: Session,
    member_user_id: str,
    scan_id: str,
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
        return

    plan = db.execute(
        text(
            """
            SELECT plan FROM users
            WHERE id = CAST(:uid AS uuid)
        """
        ),
        {"uid": family_head},
    ).scalar()

    family_ctx = type("FamilyCtx", (), {"plan": plan})()
    if not has_feature(family_ctx, Feature.FAMILY_ALERTS):
        logger.info(
            "feature_access_denied user_id=%s plan=%s feature=%s context=family_alert_insert",
            family_head,
            plan,
            Feature.FAMILY_ALERTS.value,
        )
        return

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
                'HIGH_RISK_FAMILY_ALERT'
            )
        """
        ),
        {
            "id": str(uuid.uuid4()),
            "family_head": family_head,
            "member": member_user_id,
            "scan": scan_id,
        },
    )

    db.commit()
