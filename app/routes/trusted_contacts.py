import uuid
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.services.security_plan_limits import get_contact_limit

router = APIRouter(
    prefix="/contacts/trusted",
    tags=["Trusted Contacts"],
)
legacy_router = APIRouter(
    prefix="/trusted-contacts",
    tags=["Trusted Contacts"],
)


class TrustedContactCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, min_length=5, max_length=32)
    relationship: str | None = Field(default=None, max_length=100)


@router.post("/")
def add_trusted_contact(
    payload: TrustedContactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.email and not payload.phone:
        raise HTTPException(
            status_code=400,
            detail={"error": "VALIDATION_ERROR", "message": "At least email or phone is required"},
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

    max_allowed = get_contact_limit(current_user.plan)

    if current_count >= max_allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PLAN_LIMIT_REACHED",
                "message": "Trusted contact limit reached for your plan",
                "plan": current_user.plan,
                "upgrade_required": True,
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
            "name": payload.name.strip(),
            "email": payload.email,
            "phone": payload.phone.strip() if payload.phone else None,
            "relationship": payload.relationship.strip() if payload.relationship else None,
            "is_primary": current_count == 0,
        },
    )

    db.commit()
    return {"status": "trusted_contact_added", "data": {"status": "trusted_contact_added"}}


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

    payload = {"count": len(rows), "data": rows}
    return payload


@legacy_router.get("/")
def list_trusted_contacts_legacy(
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
                is_primary
            FROM trusted_contacts
            WHERE owner_user_id = CAST(:uid AS uuid)
              AND status = 'ACTIVE'
            ORDER BY is_primary DESC, created_at DESC
            """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()
    return list(rows)


@router.delete("/{contact_id}")
def deactivate_trusted_contact(
    contact_id: UUID = Path(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
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
    return {"status": "trusted_contact_deactivated", "data": {"status": "trusted_contact_deactivated"}}


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

    return {"status": "PRIMARY_UPDATED", "data": {"status": "PRIMARY_UPDATED"}}
