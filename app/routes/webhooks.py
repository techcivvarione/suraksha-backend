from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.subscription_event import SubscriptionEvent
from app.models.user import User
from app.services.subscription import (
    apply_subscription_update,
    is_out_of_order_event,
    log_subscription_webhook,
    parse_revenuecat_payload,
    verify_revenuecat_signature,
)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@router.post("/revenuecat")
async def revenuecat_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    raw_body = await request.body()
    verify_revenuecat_signature(request, raw_body)

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    try:
        parsed = parse_revenuecat_payload(payload)
    except HTTPException:
        log_subscription_webhook(
            db=db,
            user_id=None,
            event_type="UNKNOWN_PARSE_ERROR",
            payload=payload,
            request=request,
        )
        raise
    user_ref = parsed.get("app_user_id")
    if not user_ref:
        log_subscription_webhook(
            db=db,
            user_id=None,
            event_type=str(parsed.get("event_type", "UNKNOWN")),
            payload=payload,
            request=request,
        )
        raise HTTPException(status_code=400, detail="app_user_id is required")

    try:
        with db.begin():
            locked_user = (
                db.query(User)
                .filter(User.id == user_ref)
                .with_for_update()
                .first()
            )
            if not locked_user:
                raise HTTPException(status_code=404, detail="User not found")

            event_row = SubscriptionEvent(
                event_id=parsed["event_id"],
                user_id=locked_user.id,
                event_type=parsed["event_type"],
                event_at=parsed["event_at"],
                processing_status="RECEIVED",
                payload=json.dumps(payload, default=str),
            )
            db.add(event_row)
            db.flush()

            log_subscription_webhook(
                db=db,
                user_id=locked_user.id,
                event_type=str(parsed["event_type"]),
                payload=payload,
                request=request,
                auto_commit=False,
            )

            if is_out_of_order_event(locked_user, parsed["event_at"]):
                event_row.processing_status = "IGNORED_OUT_OF_ORDER"
            else:
                apply_subscription_update(
                    db=db,
                    user=locked_user,
                    plan=parsed["plan"],
                    subscription_status=parsed["subscription_status"],
                    subscription_expires_at=parsed["subscription_expires_at"],
                    event_type=parsed["event_type"],
                    event_at=parsed["event_at"],
                    request=request,
                    auto_commit=False,
                )
                event_row.processing_status = "APPLIED"

            db.add(event_row)

    except HTTPException:
        log_subscription_webhook(
            db=db,
            user_id=None,
            event_type=str(parsed.get("event_type", "UNKNOWN")),
            payload=payload,
            request=request,
        )
        raise
    except IntegrityError:
        db.rollback()
        log_subscription_webhook(
            db=db,
            user_id=None,
            event_type=f"{parsed['event_type']}_DUPLICATE",
            payload=payload,
            request=request,
        )
        return {
            "status": "ok",
            "idempotent": True,
            "event_id": parsed["event_id"],
        }

    user = db.query(User).filter(User.id == user_ref).first()
    return {
        "status": "ok",
        "idempotent": False,
        "event_id": parsed["event_id"],
        "user_id": str(user.id) if user else str(user_ref),
        "plan": user.plan if user else None,
        "subscription_status": user.subscription_status if user else None,
        "subscription_expires_at": user.subscription_expires_at if user else None,
    }
