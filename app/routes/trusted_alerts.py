from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(
    prefix="/trusted/alerts",
    tags=["Trusted Alerts"]
)


@router.get("")
def get_trusted_alerts(
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Fetch alerts where the logged-in user is a TRUSTED CONTACT.
    """

    rows = db.execute(
        text("""
            SELECT
                ta.id,
                ta.alert_type,
                ta.read,
                ta.created_at,

                tc.contact_name,

                u.id AS owner_user_id,
                u.name AS owner_name,
                u.email AS owner_email,

                sh.id AS scan_id,
                sh.risk,
                sh.score,
                sh.input_text,
                sh.created_at AS scan_created_at
            FROM trusted_alerts ta
            JOIN trusted_contacts tc
              ON ta.contact_id = tc.id
            JOIN users u
              ON tc.owner_user_id = u.id
            JOIN scan_history sh
              ON ta.scan_id = sh.id
            WHERE
                tc.contact_user_id = CAST(:uid AS uuid)
                AND tc.status = 'ACTIVE'
            ORDER BY
                ta.read ASC,
                ta.created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {
            "uid": str(current_user.id),
            "limit": limit,
            "offset": offset,
        },
    ).mappings().all()

    return {
        "count": len(rows),
        "alerts": rows,
    }


@router.patch("/{alert_id}/read")
def mark_trusted_alert_read(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Mark a trusted alert as read.
    Only the intended trusted user can do this.
    """

    updated = db.execute(
        text("""
            UPDATE trusted_alerts ta
            SET read = true
            FROM trusted_contacts tc
            WHERE
                ta.id = CAST(:aid AS uuid)
                AND ta.contact_id = tc.id
                AND tc.contact_user_id = CAST(:uid AS uuid)
            RETURNING ta.id
        """),
        {
            "aid": alert_id,
            "uid": str(current_user.id),
        },
    ).first()

    if not updated:
        raise HTTPException(status_code=404, detail="Trusted alert not found")

    db.commit()

    return {
        "status": "read",
        "alert_id": alert_id,
    }
