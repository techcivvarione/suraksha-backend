import io
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
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
from app.services.supabase_client import get_supabase

router = APIRouter(prefix="/profile", tags=["Profile"])

ALLOWED_PROFILE_IMAGE_TYPES = {"image/jpeg", "image/png"}
MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024
PROFILE_BUCKET = "profile-pictures"
PROFILE_PATH_PREFIX = "profiles"


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


class ProfilePhotoUploadResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_image_url: str


@router.get("/")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "name": current_user.name,
        "email": current_user.email,
        "phone_number": current_user.phone_number,
        "plan": current_user.plan,
        "preferred_language": current_user.preferred_language,
        "profile_image_url": getattr(current_user, "profile_image_url", None),
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


@router.post("/upload-photo", response_model=ProfilePhotoUploadResponse)
async def upload_profile_photo(
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    content_type = (image.content_type or "").lower()
    if content_type not in ALLOWED_PROFILE_IMAGE_TYPES:
        raise HTTPException(status_code=400, detail="Invalid file type")

    file_bytes = await image.read(MAX_PROFILE_IMAGE_SIZE + 1)
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(file_bytes) > MAX_PROFILE_IMAGE_SIZE:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")

    try:
        with Image.open(io.BytesIO(file_bytes)) as uploaded_image:
            converted = uploaded_image.convert("RGB")
            output = io.BytesIO()
            converted.save(output, format="JPEG", quality=90)
            jpeg_bytes = output.getvalue()
    except (UnidentifiedImageError, OSError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid image file")

    filename = f"profile_{current_user.id}.jpg"
    storage_path = f"{PROFILE_PATH_PREFIX}/{filename}"

    try:
        storage = get_supabase().storage.from_(PROFILE_BUCKET)
        storage.upload(
            path=storage_path,
            file=jpeg_bytes,
            file_options={"content-type": "image/jpeg", "upsert": "true"},
        )
        public_url = storage.get_public_url(storage_path)
    except Exception:
        raise HTTPException(status_code=500, detail="Profile photo upload failed")

    if isinstance(public_url, dict):
        public_url = public_url.get("publicURL") or public_url.get("publicUrl") or public_url.get("data", {}).get("publicUrl")
    if not public_url:
        raise HTTPException(status_code=500, detail="Profile photo upload failed")

    db.execute(
        text(
            """
            UPDATE users
            SET profile_image_url = :url,
                updated_at = now()
            WHERE id = :user_id
            """
        ),
        {"url": public_url, "user_id": str(current_user.id)},
    )
    db.commit()
    current_user.profile_image_url = public_url

    return {"profile_image_url": public_url}
