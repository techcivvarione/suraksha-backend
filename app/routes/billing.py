import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.enums.user_plan import UserPlan
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/billing", tags=["Billing"])
logger = logging.getLogger(__name__)


class UpgradeRequest(BaseModel):
    plan: UserPlan = Field(..., description="Target plan")


@router.post("/upgrade")
def upgrade_plan(
    payload: UpgradeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = payload.plan.value

    # TODO integrate Razorpay / Stripe webhook
    # upgrade plan after payment verification

    current_user.plan = target
    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    logger.info("plan_upgrade", extra={"user_id": str(current_user.id), "plan": target})

    return {"status": "success", "plan": target}
