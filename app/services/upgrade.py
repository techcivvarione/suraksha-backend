from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.features import Feature, TIER_FREE, TIER_PRO, TIER_ULTRA, normalize_plan
from app.services.audit_logger import create_audit_log


_FEATURE_UPGRADE_MAP: dict[str, dict[str, Any]] = {
    "THREAT_SCAN": {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "Higher threat scan limits",
            "Priority protection features",
        ],
    },
    "PASSWORD_SCAN": {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "Higher password scan limits",
            "Expanded security diagnostics",
        ],
    },
    "AI_IMAGE_SCAN": {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "More AI image scans",
            "Extended deepfake protection",
        ],
    },
    Feature.EMAIL_BREACH_COUNT.value: {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "Higher email breach scan limits",
            "Extended breach visibility",
        ],
    },
    Feature.QR_UNLIMITED.value: {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "Unlimited QR scans",
            "Unlimited QR scam reports",
        ],
    },
    Feature.OCR_SCAN.value: {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "OCR scam detection",
            "Screenshot analysis",
            "Higher scan limits",
        ],
    },
    Feature.AI_EXPLAIN.value: {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "Human-readable security explanations",
            "Attack intent analysis",
            "Clear next steps",
        ],
    },
    Feature.RISK_INSIGHTS.value: {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "Behavioral scam patterns",
            "Risk timeline analysis",
            "Personalized security recommendations",
        ],
    },
    Feature.CYBER_CARD_ACCESS.value: {
        "recommended_plan": TIER_PRO,
        "benefits": [
            "Monthly Cyber Card score",
            "Historical cyber score tracking",
        ],
    },
    Feature.FAMILY_ALERTS.value: {
        "recommended_plan": "FAMILY_PRO",
        "benefits": [
            "Family security alerts",
            "Family-level risk visibility",
        ],
    },
    Feature.ULTRA_PRIORITY_PIPELINE.value: {
        "recommended_plan": TIER_ULTRA,
        "benefits": [
            "Priority protection pipeline",
            "Fastest incident handling",
        ],
    },
}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _discount_meta(user: Any) -> dict[str, Any]:
    if bool(getattr(user, "first_upgrade_used", False)):
        return {
            "eligible": False,
            "window_days": 30,
            "reason": "first_upgrade_already_used",
        }

    created_at = getattr(user, "created_at", None)
    if not isinstance(created_at, datetime):
        return {
            "eligible": False,
            "window_days": 30,
            "reason": "created_at_unavailable",
        }

    now = datetime.now(timezone.utc)
    created_utc = _as_utc(created_at)
    discount_until = created_utc + timedelta(days=30)
    eligible = now < discount_until
    days_remaining = max(0, (discount_until - now).days)
    return {
        "eligible": eligible,
        "window_days": 30,
        "expires_at": discount_until.isoformat(),
        "days_remaining": days_remaining,
    }


def _log_upgrade_required(
    db: Session | None,
    user: Any,
    plan: str,
    feature_name: str | None,
    endpoint: str,
    reason: str,
) -> None:
    if db is None:
        return
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        auto_commit = not bool(db.in_transaction())
        create_audit_log(
            db=db,
            user_id=getattr(user, "id", None),
            event_type="UPGRADE_REQUIRED",
            event_description=(
                f"user_id={getattr(user, 'id', None)} "
                f"plan={plan} "
                f"feature={feature_name or 'UNKNOWN'} "
                f"endpoint={endpoint} "
                f"reason={reason} "
                f"timestamp={timestamp}"
            ),
            auto_commit=auto_commit,
        )
    except Exception:
        # Logging must never block request handling.
        pass


def build_upgrade_response(
    user: Any,
    reason: str,
    feature: Feature | str | None = None,
    db: Session | None = None,
    endpoint: str | None = None,
) -> dict[str, Any]:
    plan = normalize_plan(getattr(user, "plan", None))
    feature_name = feature.value if isinstance(feature, Feature) else (str(feature) if feature else None)
    recommendation = _FEATURE_UPGRADE_MAP.get(feature_name or "", {})
    recommended_plan = recommendation.get("recommended_plan", TIER_PRO if plan == TIER_FREE else TIER_ULTRA)
    benefits = recommendation.get("benefits", ["Higher limits and premium security features"])
    resolved_endpoint = endpoint or "unknown"

    _log_upgrade_required(
        db=db,
        user=user,
        plan=plan,
        feature_name=feature_name,
        endpoint=resolved_endpoint,
        reason=reason,
    )

    return {
        "error": {
            "code": "UPGRADE_REQUIRED",
            "message": "Upgrade required",
            "reason": reason,
            "feature": feature_name,
            "current_plan": plan,
            "endpoint": resolved_endpoint,
            "recommended_plan": recommended_plan,
            "benefits": benefits,
            "discount": _discount_meta(user),
        }
    }
