import uuid
from sqlalchemy.orm import Session
from sqlalchemy import text


def notify_family_head(
    db: Session,
    member_user_id: str,
    scan_id: str,
):
    """
    Notify family head when a member has HIGH risk activity.
    """

    # ---------- FIND FAMILY HEAD ----------
    family_head = db.execute(
        text("""
            SELECT owner_user_id
            FROM trusted_contacts
            WHERE contact_user_id = CAST(:member_id AS uuid)
              AND status = 'ACTIVE'
            LIMIT 1
        """),
        {"member_id": member_user_id},
    ).scalar()

    if not family_head:
        return

    # ---------- CHECK FAMILY PLAN ----------
    plan = db.execute(
        text("""
            SELECT plan FROM users
            WHERE id = CAST(:uid AS uuid)
        """),
        {"uid": family_head},
    ).scalar()

    if plan not in ("FAMILY_BASIC", "FAMILY_PRO"):
        return

    # ---------- INSERT ALERT ----------
    db.execute(
        text("""
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
        """),
        {
            "id": str(uuid.uuid4()),
            "family_head": family_head,
            "member": member_user_id,
            "scan": scan_id,
        },
    )

    db.commit()
