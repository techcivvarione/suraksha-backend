from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature
from app.db import get_db
from app.dependencies.access import require_feature
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/family", tags=["Family Dashboard"])


@router.get("/dashboard")
def family_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text(
            """
            SELECT
                u.id AS user_id,
                u.name,
                u.email,
                u.phone,
                COUNT(sh.id) AS total_scans,
                COUNT(*) FILTER (WHERE sh.risk = 'high') AS high_risk,
                COUNT(*) FILTER (WHERE sh.risk = 'medium') AS medium_risk,
                COUNT(*) FILTER (WHERE sh.risk = 'low') AS low_risk,
                MAX(sh.created_at) AS last_scan_at
            FROM trusted_contacts tc
            JOIN users u
              ON u.id = tc.contact_user_id
            LEFT JOIN scan_history sh
              ON sh.user_id = u.id
            WHERE tc.owner_user_id = CAST(:uid AS uuid)
              AND tc.status = 'ACTIVE'
            GROUP BY u.id, u.name, u.email, u.phone
            ORDER BY last_scan_at DESC NULLS LAST
        """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    members = []

    for row in rows:
        score = 100
        score -= row["high_risk"] * 15
        score -= row["medium_risk"] * 8
        score = max(0, min(100, score))

        members.append(
            {
                "user_id": row["user_id"],
                "name": row["name"],
                "email": row["email"],
                "phone": row["phone"],
                "security_score": score,
                "risk_summary": {
                    "high": row["high_risk"],
                    "medium": row["medium_risk"],
                    "low": row["low_risk"],
                },
                "total_scans": row["total_scans"],
                "last_scan_at": row["last_scan_at"],
            }
        )

    return {
        "family_head": {
            "user_id": str(current_user.id),
            "name": current_user.name,
        },
        "members_count": len(members),
        "members": members,
        "mode": "READ_ONLY",
    }


@router.get("/alerts")
def family_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_feature(Feature.FAMILY_ALERTS)
    ),
):
    rows = db.execute(
        text(
            """
            SELECT
                fa.created_at,
                u.name AS member_name,
                u.email AS member_email,
                fa.alert_type
            FROM family_alerts fa
            JOIN users u
              ON u.id = fa.member_user_id
            WHERE fa.family_head_user_id = CAST(:uid AS uuid)
            ORDER BY fa.created_at DESC
        """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    return {
        "count": len(rows),
        "alerts": rows,
    }
