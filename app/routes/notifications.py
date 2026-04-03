from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/notifications", tags=["Notifications"])


def _normalize_phone(value: str | None) -> str | None:
    if not value:
        return None
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) >= 10:
        return digits[-10:]
    return digits or None


@router.get("")
def list_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    receiver_phone = _normalize_phone(getattr(current_user, "phone", None) or getattr(current_user, "phone_number", None))

    invites = []
    if receiver_phone:
        invites = list(
            db.execute(
                text(
                    """
                    SELECT
                        CAST(i.id AS text) AS id,
                        i.status,
                        i.created_at,
                        i.contact_name,
                        i.relationship,
                        u.name AS sender_name,
                        u.phone AS sender_phone
                    FROM trusted_contact_invites i
                    JOIN users u
                      ON u.id = i.sender_user_id
                    WHERE i.receiver_phone = :receiver_phone
                      AND i.status = 'PENDING'
                    ORDER BY i.created_at DESC
                    LIMIT 20
                    """
                ),
                {"receiver_phone": receiver_phone},
            ).mappings().all()
        )

    alerts = list(
        db.execute(
            text(
                """
                SELECT *
                FROM (
                    SELECT
                        CAST(ae.id AS text) AS id,
                        'SELF' AS source,
                        UPPER(COALESCE(ae.scan_type, ae.analysis_type, 'SCAN')) AS alert_type,
                        COALESCE(ae.risk_level, CASE WHEN ae.risk_score >= 70 THEN 'high' ELSE 'medium' END) AS risk_level,
                        ae.risk_score,
                        ae.created_at,
                        NULL AS member_name,
                        NULL AS message
                    FROM alert_events ae
                    WHERE ae.user_id = CAST(:uid AS uuid)
                      AND (
                          ae.risk_score >= 70
                          OR UPPER(COALESCE(ae.scan_type, ae.analysis_type, '')) = 'SOS'
                      )

                    UNION ALL

                    SELECT
                        CAST(fa.member_user_id AS text) || ':' || CAST(fa.created_at AS text) AS id,
                        'FAMILY' AS source,
                        UPPER(fa.alert_type) AS alert_type,
                        CASE
                            WHEN UPPER(fa.alert_type) LIKE '%SOS%' THEN 'high'
                            ELSE 'high'
                        END AS risk_level,
                        90 AS risk_score,
                        fa.created_at,
                        u.name AS member_name,
                        NULL AS message
                    FROM family_alerts fa
                    JOIN users u
                      ON u.id = fa.member_user_id
                    WHERE fa.family_head_user_id = CAST(:uid AS uuid)
                      AND (
                          UPPER(fa.alert_type) LIKE '%HIGH%'
                          OR UPPER(fa.alert_type) LIKE '%SOS%'
                      )
                ) AS notification_alerts
                ORDER BY created_at DESC
                LIMIT 30
                """
            ),
            {"uid": str(current_user.id)},
        ).mappings().all()
    )

    system_events = list(
        db.execute(
            text(
                """
                SELECT
                    CAST(s.id AS text) AS id,
                    s.type,
                    s.title,
                    s.description,
                    s.status,
                    s.risk_level,
                    s.created_at
                FROM secure_now_items s
                WHERE s.user_id = CAST(:uid AS uuid)
                ORDER BY
                    CASE WHEN s.status = 'PENDING' THEN 0 ELSE 1 END,
                    s.created_at DESC
                LIMIT 20
                """
            ),
            {"uid": str(current_user.id)},
        ).mappings().all()
    )

    return {
        "invites": invites,
        "alerts": alerts,
        "system_events": system_events,
        "unread_count": len(invites) + sum(1 for event in system_events if event["status"] == "PENDING"),
    }
