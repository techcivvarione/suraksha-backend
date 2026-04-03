from __future__ import annotations

from fastapi import HTTPException, status

from app.core.features import normalize_plan
from app.services.security_plan_limits import get_contact_limit

FEATURE_TRUSTED_CONTACTS = "trusted_contacts"
FEATURE_ALERTS = "alerts"
FEATURE_MANUAL_ALERTS = "manual_alerts"
FEATURE_AUTO_ALERTS = "auto_alerts"
FEATURE_FAMILY_DASHBOARD = "family_dashboard"
FEATURE_SECURE_NOW = "secure_now"
FEATURE_CYBER_SOS = "cyber_sos"


def get_family_protection_capabilities(user) -> dict[str, object]:
    plan = normalize_plan(getattr(user, "plan", None))
    is_free = plan == "FREE"
    is_pro = plan == "GO_PRO"
    is_ultra = plan == "GO_ULTRA"
    return {
        "plan": plan,
        "trusted_contacts_enabled": not is_free,
        "trusted_contacts_limit": get_contact_limit(plan),
        "alerts_enabled": not is_free,
        "manual_alerts_enabled": is_pro or is_ultra,
        "auto_alerts_enabled": is_ultra,
        "family_dashboard_enabled": is_pro or is_ultra,
        "secure_now_enabled": True,
        "cyber_sos_enabled": is_ultra,
        "family_mode": "FULL" if is_ultra else ("BASIC" if is_pro else "LOCKED"),
    }


def check_feature_access(user, feature: str) -> dict[str, object]:
    capabilities = get_family_protection_capabilities(user)
    allowed = {
        FEATURE_TRUSTED_CONTACTS: capabilities["trusted_contacts_enabled"],
        FEATURE_ALERTS: capabilities["alerts_enabled"],
        FEATURE_MANUAL_ALERTS: capabilities["manual_alerts_enabled"],
        FEATURE_AUTO_ALERTS: capabilities["auto_alerts_enabled"],
        FEATURE_FAMILY_DASHBOARD: capabilities["family_dashboard_enabled"],
        FEATURE_SECURE_NOW: capabilities["secure_now_enabled"],
        FEATURE_CYBER_SOS: capabilities["cyber_sos_enabled"],
    }.get(feature, False)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "FEATURE_NOT_AVAILABLE",
                "message": f"{feature.replace('_', ' ').title()} is not available on your current plan",
                "plan": capabilities["plan"],
                "upgrade_required": True,
            },
        )
    return capabilities
