"""GET /user/quota — Return the current user's plan limits and remaining usage.

Response schema:
  {
    "plan":               str,          # "FREE" | "GO_PRO" | "GO_ULTRA"
    "image_remaining":    int | null,   # null = unlimited
    "image_limit":        int | null,
    "email_limit":        int | null,   # null = unlimited; window = weekly
    "email_window":       str,          # "week" | "unlimited"
    "password_limit":     int | null,
    "password_window":    str,
    "threat_limit":       int | null,
    "threat_window":      str,          # "day" | "unlimited"
    "qr_limit":           int | null,
    "qr_window":          str,          # "week" | "unlimited"
    "ai_explain_limit":   int | null,   # null = unlimited; 0 = not available
    "ai_explain_window":  str,          # "day" | "unlimited" | "unavailable"
    "contacts_limit":     int,
  }

Note: "remaining" values (other than image) are not tracked here because Redis
      counters only increment on consume.  The frontend should use limit + window
      to display correct messaging.  image_remaining is derived from the DB column
      ai_image_lifetime_used.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import (
    TIER_FREE,
    TIER_PRO,
    TIER_ULTRA,
    Limit,
    get_plan_limit,
    normalize_plan,
)
from app.db import get_db
from app.routes.scan_base import require_user

router = APIRouter(prefix="/user", tags=["User"])
logger = logging.getLogger(__name__)

_UNLIMITED = None


def _window_label(limit_value: int | None, default_window: str) -> str:
    return "unlimited" if limit_value is None else default_window


@router.get("/quota")
def get_user_quota(
    current_user=Depends(require_user),
    db: Session = Depends(get_db),
):
    plan = normalize_plan(getattr(current_user, "plan", None))

    # ── Per-plan limit values ─────────────────────────────────────────────
    image_limit    = get_plan_limit(plan, Limit.AI_IMAGE_LIFETIME)
    email_limit    = get_plan_limit(plan, Limit.EMAIL_MONTHLY)
    password_limit = get_plan_limit(plan, Limit.PASSWORD_MONTHLY)
    threat_limit   = get_plan_limit(plan, Limit.THREAT_DAILY)
    qr_limit       = get_plan_limit(plan, Limit.QR_WEEKLY)
    ai_limit       = get_plan_limit(plan, Limit.AI_EXPLAIN_DAILY)

    # ── Image remaining (DB-backed for FREE) ─────────────────────────────
    image_remaining: int | None = None
    if image_limit is not None:
        row = db.execute(
            text("SELECT COALESCE(ai_image_lifetime_used, 0) FROM users WHERE id = CAST(:uid AS uuid)"),
            {"uid": str(current_user.id)},
        ).fetchone()
        used = int(row[0]) if row else 0
        image_remaining = max(0, image_limit - used)
    # PRO/ULTRA: unlimited → image_remaining stays None

    # ── AI explain availability ───────────────────────────────────────────
    if ai_limit == 0:
        ai_explain_window = "unavailable"
    elif ai_limit is None:
        ai_explain_window = "unlimited"
    else:
        ai_explain_window = "day"

    logger.info(
        "user_quota_requested",
        extra={
            "user_id": str(current_user.id),
            "plan": plan,
        },
    )

    return {
        "plan": plan,
        "image_remaining":   image_remaining,
        "image_limit":       image_limit,
        "email_limit":       email_limit,
        "email_window":      _window_label(email_limit, "week"),
        "password_limit":    password_limit,
        "password_window":   _window_label(password_limit, "week"),
        "threat_limit":      threat_limit,
        "threat_window":     _window_label(threat_limit, "day"),
        "qr_limit":          qr_limit,
        "qr_window":         _window_label(qr_limit, "week"),
        "ai_explain_limit":  ai_limit,
        "ai_explain_window": ai_explain_window,
        "contacts_limit":    int(get_plan_limit(plan, Limit.TRUSTED_CONTACT_MAX) or 0),
    }
