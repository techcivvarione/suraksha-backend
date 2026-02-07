from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(
    prefix="/trusted",
    tags=["Trusted Alerts"],
)


@router.get("/alerts")
def get_trusted_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text("""
            SELECT
                ta.id,
                ta.alert_type,
                ta.created_at,
                tc.contact_name,
                tc.contact_email,
                tc.contact_phone
            FROM trusted_alerts ta
            JOIN trusted_contacts tc
              ON tc.id = ta.contact_id
            WHERE tc.owner_user_id = CAST(:uid AS uuid)
            ORDER BY ta.created_at DESC
        """),
        {"uid": str(current_user.id)},
    ).mappings().all()

    return {
        "count": len(rows),
        "alerts": rows,
    }
