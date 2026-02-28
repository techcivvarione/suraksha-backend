from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.features import TIER_FREE, TIER_PRO, TIER_ULTRA, normalize_plan
from app.models.user import User
from app.services.audit_logger import create_audit_log

logger = logging.getLogger(__name__)

STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_CANCELED = "CANCELED"
STATUS_GRACE = "GRACE"


def verify_revenuecat_signature(request: Request, raw_body: bytes) -> None:
    secret = os.getenv("REVENUECAT_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="RevenueCat webhook secret not configured")

    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        supplied = auth.split(" ", 1)[1].strip()
        if hmac.compare_digest(supplied, secret):
            return

    signature = request.headers.get("x-revenuecat-signature") or request.headers.get("x-signature")
    if signature:
        digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature.strip(), digest):
            return

    raise HTTPException(status_code=401, detail="Invalid webhook signature")


def parse_revenuecat_payload(payload: dict[str, Any]) -> dict[str, Any]:
    event = payload.get("event", payload)
    event_type = str(event.get("type", "UNKNOWN")).upper()
    event_id = str(event.get("id") or event.get("event_id") or "").strip()
    app_user_id = event.get("app_user_id") or event.get("original_app_user_id") or event.get("user_id")

    if not event_id:
        raise HTTPException(status_code=400, detail="event_id is required")

    entitlement_ids = event.get("entitlement_ids") or []
    product_id = str(event.get("product_id") or "")
    store_product_id = str(event.get("store_product_id") or "")
    candidate = " ".join([product_id, store_product_id, " ".join(entitlement_ids)]).upper()

    if any(token in candidate for token in ("ULTRA", "ENTERPRISE")):
        next_plan = TIER_ULTRA
    elif any(token in candidate for token in ("PRO", "PAID", "PREMIUM")):
        next_plan = TIER_PRO
    else:
        next_plan = TIER_FREE

    expires_at = _parse_datetime(
        event.get("expiration_at_ms")
        or event.get("expires_date_ms")
        or event.get("expiration_at")
        or event.get("expires_date")
    )

    event_at = _parse_datetime(
        event.get("event_timestamp_ms")
        or event.get("event_timestamp")
        or event.get("purchased_at_ms")
        or event.get("purchased_at")
        or event.get("event_created_at_ms")
        or event.get("event_created_at")
    ) or datetime.now(timezone.utc)

    now = datetime.now(timezone.utc)
    if event_type in {"CANCELLATION", "SUBSCRIPTION_CANCELED", "REFUND", "UNCANCELLATION_REVERSED"}:
        status = STATUS_CANCELED
    elif event_type in {"BILLING_ISSUE", "SUBSCRIPTION_EXTENDED", "TEMPORARY_ENTITLEMENT_GRANT"}:
        status = STATUS_GRACE
    elif expires_at and expires_at < now:
        status = STATUS_EXPIRED
    else:
        status = STATUS_ACTIVE

    # Integrity rule: ACTIVE status must include an explicit expiry timestamp.
    if status == STATUS_ACTIVE and normalize_plan(next_plan) != TIER_FREE and expires_at is None:
        raise HTTPException(status_code=400, detail="ACTIVE subscriptions require expiration timestamp")

    return {
        "event_id": event_id,
        "event_type": event_type,
        "raw_event": event,
        "app_user_id": app_user_id,
        "plan": normalize_plan(next_plan),
        "subscription_status": status,
        "subscription_expires_at": expires_at,
        "event_at": event_at,
    }


def resolve_effective_plan(user: Any) -> str:
    """
    Pure plan resolver for testability.
    Returns GO_FREE when a paid plan is expired; otherwise returns normalized stored plan.
    """
    current_plan = normalize_plan(getattr(user, "plan", None))
    if current_plan == TIER_FREE:
        return TIER_FREE

    expires_at = getattr(user, "subscription_expires_at", None)
    if not expires_at:
        return current_plan

    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if isinstance(expires_at, datetime) and expires_at < datetime.now(timezone.utc):
        return TIER_FREE

    return current_plan


def is_out_of_order_event(user: User, incoming_event_at: datetime | None) -> bool:
    if incoming_event_at is None:
        return False

    last_seen = getattr(user, "last_subscription_event_at", None)
    if not last_seen:
        return False

    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)

    event_at = incoming_event_at
    if event_at.tzinfo is None:
        event_at = event_at.replace(tzinfo=timezone.utc)

    return event_at < last_seen


def apply_subscription_update(
    db: Session,
    user: User,
    plan: str,
    subscription_status: str,
    subscription_expires_at: datetime | None,
    event_type: str,
    event_at: datetime | None,
    request: Request | None = None,
    auto_commit: bool = True,
) -> None:
    if subscription_status == STATUS_ACTIVE and normalize_plan(plan) != TIER_FREE and subscription_expires_at is None:
        raise HTTPException(status_code=400, detail="ACTIVE subscriptions require expiration timestamp")

    old_plan = user.plan
    old_plan_normalized = normalize_plan(old_plan)
    new_plan_normalized = normalize_plan(plan)
    old_status = getattr(user, "subscription_status", None)
    old_expires = getattr(user, "subscription_expires_at", None)

    user.plan = plan
    user.subscription_status = subscription_status
    user.subscription_expires_at = subscription_expires_at
    if (
        old_plan_normalized == TIER_FREE
        and new_plan_normalized in {TIER_PRO, TIER_ULTRA}
        and not bool(getattr(user, "first_upgrade_used", False))
    ):
        user.first_upgrade_used = True

    if event_at:
        if event_at.tzinfo is None:
            event_at = event_at.replace(tzinfo=timezone.utc)
        user.last_subscription_event_at = event_at

    user.updated_at = datetime.utcnow()

    db.add(user)

    description = (
        f"event={event_type} plan:{old_plan}->{user.plan} "
        f"status:{old_status}->{user.subscription_status} "
        f"expires:{old_expires}->{user.subscription_expires_at} "
        f"event_at:{event_at}"
    )
    create_audit_log(
        db=db,
        user_id=user.id,
        event_type="SUBSCRIPTION_UPDATED",
        event_description=description,
        request=request,
        auto_commit=False,
    )
    logger.info("subscription_event user_id=%s %s", user.id, description)

    if auto_commit:
        db.commit()
        db.refresh(user)


def maybe_auto_downgrade_expired_subscription(
    db: Session,
    user: User,
    request: Request | None = None,
) -> User:
    effective_plan = resolve_effective_plan(user)
    normalized_plan = normalize_plan(user.plan)

    if effective_plan == normalized_plan:
        return user

    if normalized_plan == TIER_FREE:
        return user

    expires_at = getattr(user, "subscription_expires_at", None)
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    old_plan = user.plan
    user.plan = TIER_FREE
    user.subscription_status = STATUS_EXPIRED
    user.updated_at = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)

    description = f"auto_downgrade plan:{old_plan}->{TIER_FREE} expired_at:{expires_at.isoformat() if expires_at else None}"
    create_audit_log(
        db=db,
        user_id=user.id,
        event_type="SUBSCRIPTION_AUTO_DOWNGRADE",
        event_description=description,
        request=request,
    )
    logger.info("subscription_event user_id=%s %s", user.id, description)
    return user


def log_subscription_webhook(
    db: Session,
    user_id: Any,
    event_type: str,
    payload: dict[str, Any],
    request: Request | None = None,
    auto_commit: bool = True,
) -> None:
    compact = json.dumps(payload, default=str)[:2000]
    create_audit_log(
        db=db,
        user_id=user_id,
        event_type="SUBSCRIPTION_WEBHOOK_EVENT",
        event_description=f"event={event_type} payload={compact}",
        request=request,
        auto_commit=auto_commit,
    )
    logger.info("subscription_webhook_event user_id=%s event=%s", user_id, event_type)


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        epoch = float(value)
        if epoch > 10_000_000_000:
            epoch = epoch / 1000.0
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
