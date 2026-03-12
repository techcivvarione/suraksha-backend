from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.services.device_service import register_device

router = APIRouter(prefix="/devices", tags=["Devices"])


class DeviceRegisterRequest(BaseModel):
    device_token: str
    device_type: str = "android"


@router.post("/register")
def register_user_device(
    payload: DeviceRegisterRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    register_device(
        user_id=str(current_user.id),
        device_token=payload.device_token,
        device_type=payload.device_type,
        db=db,
    )
    return {"status": "device_registered"}
