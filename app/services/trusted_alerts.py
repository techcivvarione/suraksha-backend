import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import text

# -------------------------------------------------
# CONFIG
# -------------------------------------------------

ALERT_COOLDOWN_MINUTES = 30   # prevent spam alerts


# -------------------------------------------------
# CORE FUNCTION
# -------------------------------------------------

def notify_trusted_contacts(
    db: Session,
    user_id: str,
    scan_id: str,
    alert_type: str = "HIGH_RISK_SCAN",
):
    """
    Notify trusted contacts when a HIGH risk scan is detected.

    Rules:
    - Only VERIFIED contacts
    - One alert per scan
    - Cooldown enforced per user
    - No scan content or PII shared
    """

    # ---------- THROTTLE CHECK ----------
    last_alert = db.execute(
        text("""
            SELECT created_at
            FROM trusted_alerts
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY created_at DESC
            LIMIT 1
        """),
        {"uid": user_id},
    ).scalar()

    if last_alert:
        delta = datetime.utcnow() - last_alert
        if delta < timedelta(minutes=ALERT_COOLDOWN_MINUTES):
            return  # silently skip (no error, no spam)

    # ---------- FETCH TRUSTED CONTACTS ----------
    contacts = db.execute(
        text("""
            SELECT id, name, contact, contact_type
            FROM trusted_contacts
            WHERE user_id = CAST(:uid AS uuid)
              AND verified = true
        """),
        {"uid": user_id},
    ).mappings().all()

    if not contacts:
        return

    # ---------- INSERT ALERT EVENTS ----------
    for contact in contacts:
        db.execute(
            text("""
                INSERT INTO trusted_alerts (
                    id,
                    user_id,
                    contact_id,
                    scan_id,
                    alert_type,
                    created_at
                )
                VALUES (
                    :id,
                    :user_id,
                    :contact_id,
                    :scan_id,
                    :alert_type,
                    now()
                )
            """),
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "contact_id": contact["id"],
                "scan_id": scan_id,
                "alert_type": alert_type,
            },
        )

        # 🔔 DELIVERY PLACEHOLDER
        # if contact["contact_type"] == "email":
        #     send_email_alert(contact["contact"])
        # elif contact["contact_type"] == "phone":
        #     send_sms_alert(contact["contact"])

    db.commit()
