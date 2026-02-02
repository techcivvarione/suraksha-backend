from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user, hash_password, verify_password

router = APIRouter(prefix="/profile", tags=["Profile"])


# ---------- models ----------
class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    phone: Optional[str] = None


class PasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_new_password: str


# ---------- routes ----------
@router.get("/")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "name": current_user.name,
        "email": current_user.email,
        "phone": current_user.phone,
        "role": current_user.role,
        "created_at": current_user.created_at,
        "updated_at": current_user.updated_at,
    }


@router.put("/")
def update_profile(
    payload: ProfileUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.name is not None:
        current_user.name = payload.name

    if payload.role is not None:
        current_user.role = payload.role

    if payload.phone is not None:
        current_user.phone = payload.phone

    current_user.updated_at = datetime.utcnow()

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return {"status": "profile_updated"}


@router.put("/password")
def change_password(
    payload: PasswordUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if payload.new_password != payload.confirm_new_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    current_user.password_hash = hash_password(payload.new_password)
    current_user.updated_at = datetime.utcnow()

    db.add(current_user)
    db.commit()

    return {"status": "password_updated"}
