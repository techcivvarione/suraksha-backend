from __future__ import annotations

from app.core.features import Limit, get_plan_limit, normalize_plan


def normalized_plan(plan: str | None) -> str:
    return normalize_plan(plan)


def get_contact_limit(plan: str | None) -> int:
    """Returns trusted-contact limit from the single source of truth (features.py).
    FREE=0, GO_PRO=3, GO_ULTRA=6.
    """
    result = get_plan_limit(normalized_plan(plan), Limit.TRUSTED_CONTACT_MAX)
    return int(result) if result is not None else 0


def allows_automatic_trusted_alerts(plan: str | None) -> bool:
    return normalized_plan(plan) == "GO_ULTRA"


def allows_manual_trusted_alerts(plan: str | None) -> bool:
    return normalized_plan(plan) in {"GO_PRO", "GO_ULTRA"}


def allows_family_alerts(plan: str | None) -> bool:
    return normalized_plan(plan) == "GO_ULTRA"


def allows_basic_family_dashboard(plan: str | None) -> bool:
    return normalized_plan(plan) in {"GO_PRO", "GO_ULTRA"}


def allows_realtime_alerts(plan: str | None) -> bool:
    return normalized_plan(plan) == "GO_ULTRA"
