from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.services.family_protection_access import FEATURE_FAMILY_DASHBOARD, check_feature_access, get_family_protection_capabilities
from app.services.security_plan_limits import allows_basic_family_dashboard, allows_family_alerts

router = APIRouter(prefix="/family", tags=["Family Dashboard"])


@router.get("/dashboard")
def family_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    capabilities = check_feature_access(current_user, FEATURE_FAMILY_DASHBOARD)

    rows = db.execute(
        text(
            """
            SELECT
                u.id AS user_id,
                u.name,
                u.email,
                u.phone_number,
                COUNT(sh.id) AS total_scans,
                COUNT(*) FILTER (WHERE sh.risk = 'high') AS high_risk,
                COUNT(*) FILTER (WHERE sh.risk = 'medium') AS medium_risk,
                COUNT(*) FILTER (WHERE sh.risk = 'low') AS low_risk,
                MAX(sh.created_at) AS last_scan_at,
                COUNT(sni.id) FILTER (WHERE sni.status = 'PENDING') AS pending_secure_now
            FROM trusted_contacts tc
            JOIN users u
              ON u.id = tc.contact_user_id
            LEFT JOIN scan_history sh
              ON sh.user_id = u.id
            LEFT JOIN secure_now_items sni
              ON sni.user_id = u.id
            WHERE tc.owner_user_id = CAST(:uid AS uuid)
              AND tc.status = 'ACTIVE'
              AND COALESCE(tc.family_link_enabled, true) = true
            GROUP BY u.id, u.name, u.email, u.phone_number
            ORDER BY last_scan_at DESC NULLS LAST
        """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    alert_rows = db.execute(
        text(
            """
            SELECT
                fa.member_user_id,
                fa.alert_type,
                fa.created_at
            FROM family_alerts fa
            WHERE fa.family_head_user_id = CAST(:uid AS uuid)
            ORDER BY fa.created_at DESC
            LIMIT 50
            """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()
    alerts_by_member: dict[str, list[dict]] = {}
    for alert in alert_rows:
        member_key = str(alert["member_user_id"])
        alerts_by_member.setdefault(member_key, []).append(
            {
                "alert_type": alert["alert_type"],
                "created_at": alert["created_at"],
            }
        )

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
                "phone_number": row["phone_number"],
                "security_score": score,
                "risk_summary": {
                    "high": row["high_risk"],
                    "medium": row["medium_risk"],
                    "low": row["low_risk"],
                },
                "total_scans": row["total_scans"],
                "pending_secure_now": row["pending_secure_now"],
                "last_scan_at": row["last_scan_at"],
                "recent_alerts": alerts_by_member.get(str(row["user_id"]), [])[:5],
            }
        )

    pending_invites = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM trusted_contact_invites
            WHERE sender_user_id = CAST(:uid AS uuid)
              AND status = 'PENDING'
            """
        ),
        {"uid": str(current_user.id)},
    ).scalar()

    return {
        "capabilities": capabilities,
        "family_head": {
            "user_id": str(current_user.id),
            "name": current_user.name,
        },
        "members_count": len(members),
        "members": members,
        "pending_invites_count": int(pending_invites or 0),
        "mode": "FULL" if allows_family_alerts(current_user.plan) else "BASIC",
    }


@router.get("/alerts")
def family_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not allows_basic_family_dashboard(current_user.plan):
        raise HTTPException(status_code=403, detail="Family alerts are available on GO_PRO and GO_ULTRA")
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
