import uuid
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.services.family_protection_access import FEATURE_TRUSTED_CONTACTS, check_feature_access
from app.services.notification_service import NotificationService
from app.services.security_plan_limits import get_contact_limit

router = APIRouter(
    prefix="/contacts/trusted",
    tags=["Trusted Contacts"],
)
legacy_router = APIRouter(
    prefix="/trusted-contacts",
    tags=["Trusted Contacts"],
)
notifier = NotificationService()


class TrustedContactCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, min_length=5, max_length=32)
    relationship: str | None = Field(default=None, max_length=100)


class TrustedContactInviteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    phone: str = Field(min_length=10, max_length=20)
    relationship: str | None = Field(default=None, max_length=100)
    add_to_family: bool = True


class TrustedContactInviteAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invite_id: UUID
    action: str = Field(pattern="^(ACCEPT|REJECT)$")
    add_to_family: bool | None = None


def _normalize_phone(value: str | None) -> str | None:
    if not value:
        return None
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) >= 10:
        return digits[-10:]
    return digits or None


@router.post("/")
def add_trusted_contact(
    payload: TrustedContactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    check_feature_access(current_user, FEATURE_TRUSTED_CONTACTS)
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
    check_feature_access(current_user, FEATURE_TRUSTED_CONTACTS)
    rows = db.execute(
        text(
            """
            SELECT
                id,
                name,
                email,
                phone,
                relationship,
                COALESCE(family_link_enabled, true) AS family_link_enabled,
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


@router.post("/invite")
def invite_trusted_contact(
    payload: TrustedContactInviteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    check_feature_access(current_user, FEATURE_TRUSTED_CONTACTS)
    receiver_phone = _normalize_phone(payload.phone)
    if not receiver_phone:
        raise HTTPException(status_code=400, detail="Valid phone required")

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
        raise HTTPException(status_code=403, detail="Trusted contact limit reached for your plan")

    receiver = db.execute(
        text(
            """
            SELECT id, phone, name
            FROM users
            WHERE REPLACE(REPLACE(REPLACE(COALESCE(phone, ''), '+', ''), '-', ''), ' ', '') LIKE :phone_suffix
            LIMIT 1
            """
        ),
        {"phone_suffix": f"%{receiver_phone}"},
    ).mappings().first()

    existing_pending = db.execute(
        text(
            """
            SELECT id
            FROM trusted_contact_invites
            WHERE sender_user_id = CAST(:uid AS uuid)
              AND receiver_phone = :receiver_phone
              AND status = 'PENDING'
            LIMIT 1
            """
        ),
        {"uid": str(current_user.id), "receiver_phone": receiver_phone},
    ).scalar()
    if existing_pending:
        raise HTTPException(status_code=409, detail="A pending invite already exists for this phone number")

    invite_id = str(uuid.uuid4())
    db.execute(
        text(
            """
            INSERT INTO trusted_contact_invites (
                id,
                sender_user_id,
                receiver_user_id,
                receiver_phone,
                contact_name,
                relationship,
                add_to_family,
                status,
                created_at,
                updated_at
            )
            VALUES (
                CAST(:id AS uuid),
                CAST(:sender_user_id AS uuid),
                CAST(NULLIF(:receiver_user_id, '') AS uuid),
                :receiver_phone,
                :contact_name,
                :relationship,
                :add_to_family,
                'PENDING',
                now(),
                now()
            )
            """
        ),
        {
            "id": invite_id,
            "sender_user_id": str(current_user.id),
            "receiver_user_id": str(receiver["id"]) if receiver else "",
            "receiver_phone": receiver_phone,
            "contact_name": payload.name.strip(),
            "relationship": payload.relationship.strip() if payload.relationship else None,
            "add_to_family": payload.add_to_family,
        },
    )
    db.commit()

    if receiver:
        notifier.send_push_notification(
            db=db,
            contact_user_id=str(receiver["id"]),
            title="Trusted contact invite",
            body=f"You have been added as a trusted contact by {getattr(current_user, 'phone', None) or getattr(current_user, 'email', '')}",
            user_id=str(current_user.id),
        )

    return {
        "status": "invite_sent",
        "invite_id": invite_id,
        "receiver_phone": receiver_phone,
    }


@router.get("/pending")
def list_pending_invites(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    receiver_phone = _normalize_phone(getattr(current_user, "phone", None) or getattr(current_user, "phone_number", None))
    if not receiver_phone:
        return {"count": 0, "invites": []}

    rows = db.execute(
        text(
            """
            SELECT
                i.id,
                i.status,
                i.created_at,
                i.contact_name,
                i.relationship,
                i.add_to_family,
                CAST(u.id AS text) AS sender_user_id,
                u.name AS sender_name,
                u.phone AS sender_phone
            FROM trusted_contact_invites i
            JOIN users u
              ON u.id = i.sender_user_id
            WHERE i.receiver_phone = :receiver_phone
              AND i.status = 'PENDING'
            ORDER BY i.created_at DESC
            """
        ),
        {"receiver_phone": receiver_phone},
    ).mappings().all()
    return {"count": len(rows), "invites": list(rows)}


@router.post("/accept")
def respond_to_invite(
    payload: TrustedContactInviteAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    invite = db.execute(
        text(
            """
            SELECT *
            FROM trusted_contact_invites
            WHERE id = CAST(:invite_id AS uuid)
            LIMIT 1
            """
        ),
        {"invite_id": str(payload.invite_id)},
    ).mappings().first()
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found")

    receiver_phone = _normalize_phone(getattr(current_user, "phone", None) or getattr(current_user, "phone_number", None))
    if invite["receiver_user_id"] and str(invite["receiver_user_id"]) != str(current_user.id):
        raise HTTPException(status_code=403, detail="Invite does not belong to this user")
    if not invite["receiver_user_id"] and invite["receiver_phone"] != receiver_phone:
        raise HTTPException(status_code=403, detail="Invite does not belong to this phone number")
    if invite["status"] != "PENDING":
        raise HTTPException(status_code=400, detail="Invite has already been processed")

    action = payload.action.upper()
    family_link_enabled = invite["add_to_family"] if payload.add_to_family is None else payload.add_to_family

    if action == "REJECT":
        db.execute(
            text(
                """
                UPDATE trusted_contact_invites
                SET status = 'REJECTED',
                    receiver_user_id = CAST(:receiver_user_id AS uuid),
                    updated_at = now()
                WHERE id = CAST(:invite_id AS uuid)
                """
            ),
            {"invite_id": str(payload.invite_id), "receiver_user_id": str(current_user.id)},
        )
        db.commit()
        return {"status": "rejected", "invite_id": str(payload.invite_id)}

    existing_active = db.execute(
        text(
            """
            SELECT id
            FROM trusted_contacts
            WHERE owner_user_id = CAST(:owner_user_id AS uuid)
              AND contact_user_id = CAST(:contact_user_id AS uuid)
              AND status = 'ACTIVE'
            LIMIT 1
            """
        ),
        {"owner_user_id": str(invite["sender_user_id"]), "contact_user_id": str(current_user.id)},
    ).scalar()

    if not existing_active:
        active_count = db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM trusted_contacts
                WHERE owner_user_id = CAST(:owner_user_id AS uuid)
                  AND status = 'ACTIVE'
                """
            ),
            {"owner_user_id": str(invite["sender_user_id"])},
        ).scalar()
        db.execute(
            text(
                """
                INSERT INTO trusted_contacts (
                    id,
                    owner_user_id,
                    contact_user_id,
                    contact_name,
                    contact_email,
                    contact_phone,
                    name,
                    email,
                    phone,
                    relationship,
                    family_link_enabled,
                    is_primary,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (
                    :id,
                    CAST(:owner_user_id AS uuid),
                    CAST(:contact_user_id AS uuid),
                    :contact_name,
                    :contact_email,
                    :contact_phone,
                    :name,
                    :email,
                    :phone,
                    :relationship,
                    :family_link_enabled,
                    :is_primary,
                    'ACTIVE',
                    now(),
                    now()
                )
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "owner_user_id": str(invite["sender_user_id"]),
                "contact_user_id": str(current_user.id),
                "contact_name": getattr(current_user, "name", None) or invite["contact_name"],
                "contact_email": getattr(current_user, "email", None),
                "contact_phone": getattr(current_user, "phone", None) or getattr(current_user, "phone_number", None),
                "name": getattr(current_user, "name", None) or invite["contact_name"],
                "email": getattr(current_user, "email", None),
                "phone": getattr(current_user, "phone", None) or getattr(current_user, "phone_number", None),
                "relationship": invite["relationship"],
                "family_link_enabled": family_link_enabled,
                "is_primary": active_count == 0,
            },
        )

    db.execute(
        text(
            """
            UPDATE trusted_contact_invites
            SET status = 'ACCEPTED',
                receiver_user_id = CAST(:receiver_user_id AS uuid),
                add_to_family = :add_to_family,
                updated_at = now()
            WHERE id = CAST(:invite_id AS uuid)
            """
        ),
        {
            "invite_id": str(payload.invite_id),
            "receiver_user_id": str(current_user.id),
            "add_to_family": family_link_enabled,
        },
    )
    db.commit()

    notifier.send_push_notification(
        db=db,
        contact_user_id=str(invite["sender_user_id"]),
        title="Trusted contact accepted",
        body=f"{getattr(current_user, 'name', 'Your contact')} accepted your trusted contact invite.",
        user_id=str(current_user.id),
    )
    return {"status": "accepted", "invite_id": str(payload.invite_id), "family_link_enabled": family_link_enabled}


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
