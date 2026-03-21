import logging
import os
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.enums.user_plan import UserPlan
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])


def _verify_admin(x_admin_secret: str = Header(..., alias="X-Admin-Secret")) -> None:
    """Dependency that validates the X-Admin-Secret header against the env var."""
    admin_secret = os.getenv("ADMIN_SECRET", "").strip()
    if not admin_secret:
        logger.error("admin_secret_not_configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error_code": "ADMIN_NOT_CONFIGURED",
                "message": "Admin access is not configured on this server.",
            },
        )
    if x_admin_secret != admin_secret:
        logger.warning("admin_auth_failed")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": "FORBIDDEN",
                "message": "Invalid admin secret.",
            },
        )


class UpdateUserPlanRequest(BaseModel):
    user_id: UUID = Field(..., description="UUID of the user whose plan should be updated")
    plan: UserPlan = Field(..., description="New plan: FREE, GO_PRO, or GO_ULTRA")


class UserPlanResponse(BaseModel):
    id: str
    email: str | None
    name: str
    plan: str
    subscription_status: str


@router.post(
    "/user/plan",
    response_model=UserPlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a user's plan (admin only)",
)
def update_user_plan(
    body: UpdateUserPlanRequest,
    db: Session = Depends(get_db),
    _: None = Depends(_verify_admin),
) -> UserPlanResponse:
    user: User | None = db.query(User).filter(User.id == body.user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "USER_NOT_FOUND",
                "message": f"No user found with id {body.user_id}.",
            },
        )

    old_plan = user.plan
    user.plan = body.plan.value
    db.commit()
    db.refresh(user)

    logger.info(
        "admin_plan_updated",
        extra={
            "user_id": str(user.id),
            "old_plan": old_plan,
            "new_plan": user.plan,
        },
    )

    return UserPlanResponse(
        id=str(user.id),
        email=user.email,
        name=user.name,
        plan=user.plan,
        subscription_status=user.subscription_status,
    )
