from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.services.family_protection_access import FEATURE_SECURE_NOW, check_feature_access, get_family_protection_capabilities

router = APIRouter(prefix="/secure-now", tags=["Secure Now"])


@router.get("")
def get_secure_now(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    check_feature_access(current_user, FEATURE_SECURE_NOW)
    capabilities = get_family_protection_capabilities(current_user)

    own_items = db.execute(
        text(
            """
            SELECT
                s.id,
                s.type,
                s.title,
                s.description,
                s.status,
                s.risk_level,
                s.created_at,
                s.completed_at,
                false AS read_only,
                NULL AS owner_name,
                NULL AS owner_user_id
            FROM secure_now_items s
            WHERE s.user_id = CAST(:uid AS uuid)
            ORDER BY
                CASE WHEN s.status = 'PENDING' THEN 0 ELSE 1 END,
                s.created_at DESC
            """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    family_items = db.execute(
        text(
            """
            SELECT
                s.id,
                s.type,
                s.title,
                s.description,
                s.status,
                s.risk_level,
                s.created_at,
                s.completed_at,
                true AS read_only,
                u.name AS owner_name,
                CAST(u.id AS text) AS owner_user_id
            FROM secure_now_items s
            JOIN trusted_contacts tc
              ON tc.contact_user_id = s.user_id
            JOIN users u
              ON u.id = s.user_id
            WHERE tc.owner_user_id = CAST(:uid AS uuid)
              AND tc.status = 'ACTIVE'
              AND tc.is_primary = true
              AND COALESCE(tc.family_link_enabled, true) = true
            ORDER BY
                CASE WHEN s.status = 'PENDING' THEN 0 ELSE 1 END,
                s.created_at DESC
            """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    return {
        "capabilities": capabilities,
        "own_items": list(own_items),
        "family_items": list(family_items),
        "counts": {
            "own_pending": sum(1 for item in own_items if item["status"] == "PENDING"),
            "family_pending": sum(1 for item in family_items if item["status"] == "PENDING"),
        },
    }


@router.post("/{item_id}/complete")
def complete_secure_now(
    item_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    check_feature_access(current_user, FEATURE_SECURE_NOW)
    result = db.execute(
        text(
            """
            UPDATE secure_now_items
            SET status = 'DONE',
                completed_at = now()
            WHERE id = CAST(:item_id AS uuid)
              AND user_id = CAST(:uid AS uuid)
              AND status = 'PENDING'
            """
        ),
        {"item_id": item_id, "uid": str(current_user.id)},
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Secure Now item not found")
    db.commit()
    return {"status": "completed", "item_id": item_id}
