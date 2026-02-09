from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import text
from uuid import UUID
import uuid

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(
    prefix="/trusted-contacts",
    tags=["Trusted Contacts"],
)

# ---------------- MODELS ----------------

class TrustedContactCreate(BaseModel):
    contact_name: str
    contact_email: EmailStr | None = None
    contact_phone: str | None = None


# ---------------- HELPERS ----------------

PLAN_LIMITS = {
    "FREE": 1,
    "FAMILY_BASIC": 3,
    "FAMILY_PRO": 6,
}


def get_contact_limit(plan: str) -> int:
    return PLAN_LIMITS.get(plan.upper(), 1)


# ---------------- ROUTES ----------------

@router.post("/")
def add_trusted_contact(
    payload: TrustedContactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.contact_email and not payload.contact_phone:
        raise HTTPException(
            status_code=400,
            detail="At least email or phone is required",
        )

    # ---- ENFORCE PLAN LIMIT ----
    current_count = db.execute(
        text("""
            SELECT COUNT(*)
            FROM trusted_contacts
            WHERE owner_user_id = CAST(:uid AS uuid)
              AND status = 'ACTIVE'
        """),
        {"uid": str(current_user.id)},
    ).scalar()

    max_allowed = get_contact_limit(current_user.plan)

    if current_count >= max_allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PLAN_LIMIT_REACHED",
                "message": f"Your plan allows only {max_allowed} trusted contact(s)",
                "plan": current_user.plan,
                "upgrade_required": current_user.plan == "FREE",
            },
        )

    db.execute(
        text("""
            INSERT INTO trusted_contacts (
                id,
                owner_user_id,
                contact_name,
                contact_email,
                contact_phone,
                status,
                created_at
            )
            VALUES (
                :id,
                CAST(:uid AS uuid),
                :name,
                :email,
                :phone,
                'ACTIVE',
                now()
            )
        """),
        {
            "id": str(uuid.uuid4()),
            "uid": str(current_user.id),
            "name": payload.contact_name,
            "email": payload.contact_email,
            "phone": payload.contact_phone,
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
        text("""
            SELECT
                id,
                contact_name,
                contact_email,
                contact_phone,
                status,
                created_at
            FROM trusted_contacts
            WHERE owner_user_id = CAST(:uid AS uuid)
            ORDER BY created_at DESC
        """),
        {"uid": str(current_user.id)},
    ).mappings().all()

    return {"count": len(rows), "data": rows}


@router.delete("/{contact_id}")
def deactivate_trusted_contact(
    contact_id: UUID = Path(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = db.execute(
        text("""
            UPDATE trusted_contacts
            SET status = 'INACTIVE'
            WHERE id = CAST(:cid AS uuid)
              AND owner_user_id = CAST(:uid AS uuid)
        """),
        {
            "cid": str(contact_id),
            "uid": str(current_user.id),
        },
    )

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Contact not found")

    db.commit()
    return {"status": "trusted_contact_deactivated"}
