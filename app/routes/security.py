from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime

from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user, verify_password, hash_password

router = APIRouter(prefix="/security", tags=["Account Security"])


# ---------- models ----------
class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


# ---------- routes ----------
@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")

    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    current_user.password_hash = hash_password(payload.new_password)
    current_user.updated_at = datetime.utcnow()

    db.add(current_user)
    db.commit()

    return {"status": "password_changed"}


@router.post("/logout-all")
def logout_all_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # invalidate all existing JWTs by moving updated_at forward
    current_user.updated_at = datetime.utcnow()
    db.add(current_user)
    db.commit()

    return {"status": "all_sessions_logged_out"}


@router.get("/status")
def security_status(
    current_user: User = Depends(get_current_user),
):
    return {
        "password_last_changed": current_user.updated_at,
        "session_model": "stateless JWT",
        "note": "All tokens issued before password change are invalid"
    }
