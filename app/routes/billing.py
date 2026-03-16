from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.enums.user_plan import UserPlan
from app.routes.auth import get_current_user
from app.schemas.common import ErrorResponse

router = APIRouter(prefix="/billing", tags=["Billing"])


class UpgradeRequest(BaseModel):
    plan: UserPlan = Field(..., description="Target plan")


@router.post("/upgrade", responses={403: {"model": ErrorResponse}})
def upgrade_plan(
    payload: UpgradeRequest,
    current_user=Depends(get_current_user),
):
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "status": "error",
            "error_code": "DIRECT_UPGRADE_DISABLED",
            "message": "Direct plan upgrades are disabled. Subscription changes are applied only from verified RevenueCat webhooks.",
        },
    )
