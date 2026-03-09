import uuid
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature, get_feature_limit
from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(
    prefix="/contacts/trusted",
    tags=["Trusted Contacts"],
)


class TrustedContactCreate(BaseModel):
    name: str
    email: EmailStr | None = None
    phone: str | None = None
    relationship: str | None = None


@router.post("/")
def add_trusted_contact(
    payload: TrustedContactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.email and not payload.phone:
        raise HTTPException(
            status_code=400,
            detail="At least email or phone is required",
        )

    current_count = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM trusted_contacts
            WHERE owner_user_id = CAST(:uid AS uuid)
              AND status = 'ACTIVE'
        """
        ),
        {"uid": str(current_user.id)},
    ).scalar()

    max_allowed = get_feature_limit(current_user, Feature.TRUSTED_CONTACT_LIMIT) or 1

    if current_count >= max_allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PLAN_LIMIT_REACHED",
                "message": f"Your plan allows only {max_allowed} trusted contact(s)",
                "plan": current_user.plan,
                "upgrade_required": max_allowed == 1,
            },
        )

    db.execute(
        text(
            """
            INSERT INTO trusted_contacts (
                id,
                owner_user_id,
                contact_name,
                contact_email,
                contact_phone,
                name,
                email,
                phone,
                relationship,
                is_primary,
                status,
                created_at,
                updated_at
            )
            VALUES (
                :id,
                CAST(:uid AS uuid),
                :name,
                :email,
                :phone,
                :name,
                :email,
                :phone,
                :relationship,
                :is_primary,
                'ACTIVE',
                now(),
                now()
            )
        """
        ),
        {
            "id": str(uuid.uuid4()),
            "uid": str(current_user.id),
            "name": payload.name,
            "email": payload.email,
            "phone": payload.phone,
            "relationship": payload.relationship,
            "is_primary": current_count == 0,
        },
    )

    db.commit()
    return {"status": "trusted_contact_added"}


@router.get("/")
def list_trusted_contacts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text(
            """
            SELECT
                id,
                name,
                email,
                phone,
                relationship,
                is_primary,
                status,
                created_at,
                updated_at
            FROM trusted_contacts
            WHERE owner_user_id = CAST(:uid AS uuid)
            ORDER BY created_at DESC
        """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    return {"count": len(rows), "data": rows}


@router.delete("/{contact_id}")
def deactivate_trusted_contact(
    contact_id: UUID = Path(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # prevent deleting sole primary without replacement
    contact = db.execute(
        text(
            """
            SELECT is_primary
            FROM trusted_contacts
            WHERE id = CAST(:cid AS uuid)
              AND owner_user_id = CAST(:uid AS uuid)
            LIMIT 1
            """
        ),
        {"cid": str(contact_id), "uid": str(current_user.id)},
    ).mappings().first()

    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    if contact["is_primary"]:
        other_active = db.execute(
            text(
                """
                SELECT 1 FROM trusted_contacts
                WHERE owner_user_id = CAST(:uid AS uuid)
                  AND id != CAST(:cid AS uuid)
                  AND status = 'ACTIVE'
                LIMIT 1
                """
            ),
            {"uid": str(current_user.id), "cid": str(contact_id)},
        ).scalar()
        if not other_active:
            raise HTTPException(status_code=400, detail="Set another primary before deleting this contact")

    result = db.execute(
        text(
            """
            UPDATE trusted_contacts
            SET status = 'DISABLED',
                is_primary = false,
                updated_at = now()
            WHERE id = CAST(:cid AS uuid)
              AND owner_user_id = CAST(:uid AS uuid)
        """
        ),
        {
            "cid": str(contact_id),
            "uid": str(current_user.id),
        },
    )

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Contact not found")

    db.commit()
    return {"status": "trusted_contact_deactivated"}


@router.patch("/{contact_id}/set-primary")
def set_primary_contact(
    contact_id: UUID = Path(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    contact = db.execute(
        text(
            """
            SELECT status
            FROM trusted_contacts
            WHERE id = CAST(:cid AS uuid)
              AND owner_user_id = CAST(:uid AS uuid)
            LIMIT 1
            """
        ),
        {"cid": str(contact_id), "uid": str(current_user.id)},
    ).mappings().first()

    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    if contact["status"] != "ACTIVE":
        raise HTTPException(status_code=400, detail="Contact must be ACTIVE to be primary")

    try:
        with db.begin():
            db.execute(
                text(
                    """
                    UPDATE trusted_contacts
                    SET is_primary = false, updated_at = now()
                    WHERE owner_user_id = CAST(:uid AS uuid)
                      AND is_primary = true
                    """
                ),
                {"uid": str(current_user.id)},
            )
            db.execute(
                text(
                    """
                    UPDATE trusted_contacts
                    SET is_primary = true, updated_at = now()
                    WHERE id = CAST(:cid AS uuid)
                      AND owner_user_id = CAST(:uid AS uuid)
                    """
                ),
                {"cid": str(contact_id), "uid": str(current_user.id)},
            )
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to update primary contact")

    return {"status": "PRIMARY_UPDATED"}
