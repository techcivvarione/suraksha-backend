from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import (
    get_current_user,
    hash_password,
    invalidate_user_sessions,
    validate_password_strength,
    verify_password,
)
from app.services.language import ALLOWED_LANGUAGES, normalize_language

router = APIRouter(prefix="/profile", tags=["Profile"])


class ProfileUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    phone_number: Optional[str] = None
    preferred_language: Optional[str] = None


class PasswordUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str
    new_password: str
    confirm_new_password: str


@router.get("/")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "name": current_user.name,
        "email": current_user.email,
        "phone_number": current_user.phone_number,
        "plan": current_user.plan,
        "preferred_language": current_user.preferred_language,
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
    if payload.phone_number is not None:
        current_user.phone_number = payload.phone_number
    if payload.preferred_language is not None:
        normalized = normalize_language(payload.preferred_language, supported=ALLOWED_LANGUAGES)
        if not normalized:
            raise HTTPException(status_code=400, detail="preferred_language must be one of: en, hi, te")
        current_user.preferred_language = normalized

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

    validate_password_strength(payload.new_password)
    current_user.password_hash = hash_password(payload.new_password)
    current_user.password_changed_at = datetime.utcnow()
    invalidate_user_sessions(current_user)
    db.add(current_user)
    db.commit()
    return {"status": "password_updated"}
