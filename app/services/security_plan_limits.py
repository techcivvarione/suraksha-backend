from __future__ import annotations

from app.core.features import normalize_plan

PLAN_CONTACT_LIMITS = {
    "FREE": 0,
    "GO_PRO": 3,
    "GO_ULTRA": 5,
}


def normalized_plan(plan: str | None) -> str:
    return normalize_plan(plan)


def get_contact_limit(plan: str | None) -> int:
    return PLAN_CONTACT_LIMITS.get(normalized_plan(plan), 0)


def allows_automatic_trusted_alerts(plan: str | None) -> bool:
    return normalized_plan(plan) in {"GO_PRO", "GO_ULTRA"}


def allows_family_alerts(plan: str | None) -> bool:
    return normalized_plan(plan) == "GO_ULTRA"


def allows_realtime_alerts(plan: str | None) -> bool:
    return normalized_plan(plan) == "GO_ULTRA"
