from __future__ import annotations

# =============================================================================
# features.py — SINGLE SOURCE OF TRUTH for all plan features and limits
#
# Plan matrix:
#   FREE:      email 1/week, threat 1/day, password 1/week, QR 1/week,
#              image 1/lifetime, AI ❌, contacts 0
#   GO_PRO:    everything unlimited, AI explain 20/day, contacts 3,
#              automatic alerts, priority SOS
#   GO_ULTRA:  everything unlimited, AI explain unlimited, contacts 6,
#              real-time alerts, family dashboard
# =============================================================================

from enum import Enum
from typing import Any


class Feature(str, Enum):
    EMAIL_BREACH_COUNT = "EMAIL_BREACH_COUNT"
    EMAIL_BREACH_DETAILS = "EMAIL_BREACH_DETAILS"
    OCR_SCAN = "OCR_SCAN"
    AI_EXPLAIN = "AI_EXPLAIN"
    RISK_INSIGHTS = "RISK_INSIGHTS"
    CYBER_CARD_ACCESS = "CYBER_CARD_ACCESS"
    QR_UNLIMITED = "QR_UNLIMITED"
    TRUSTED_CONTACT_LIMIT = "TRUSTED_CONTACT_LIMIT"
    FAMILY_ALERTS = "FAMILY_ALERTS"
    PRIORITY_SOS = "PRIORITY_SOS"
    ULTRA_PRIORITY_PIPELINE = "ULTRA_PRIORITY_PIPELINE"


class Limit(str, Enum):
    TRUSTED_CONTACT_MAX = "TRUSTED_CONTACT_MAX"
    # FREE: 1/day;  PRO/ULTRA: None (unlimited)
    THREAT_DAILY = "THREAT_DAILY"
    # FREE: 1/week; PRO/ULTRA: None — window enforced in plan_limits.py
    EMAIL_MONTHLY = "EMAIL_MONTHLY"
    # FREE: 1/week; PRO/ULTRA: None — window enforced in plan_limits.py
    PASSWORD_MONTHLY = "PASSWORD_MONTHLY"
    # FREE: 1/week; PRO/ULTRA: None
    QR_WEEKLY = "QR_WEEKLY"
    # FREE: 1 lifetime; PRO/ULTRA: None
    AI_IMAGE_LIFETIME = "AI_IMAGE_LIFETIME"
    # PRO: 20/day;  ULTRA: None (unlimited); FREE: 0 (blocked at feature layer)
    AI_EXPLAIN_DAILY = "AI_EXPLAIN_DAILY"
    # --- global (not plan-scoped) ---
    EMAIL_MAX_LENGTH = "EMAIL_MAX_LENGTH"
    EMAIL_GLOBAL_COOLDOWN_SECONDS = "EMAIL_GLOBAL_COOLDOWN_SECONDS"
    EMAIL_DUPLICATE_SCAN_BLOCK_SECONDS = "EMAIL_DUPLICATE_SCAN_BLOCK_SECONDS"
    EMAIL_RATE_WINDOW_SECONDS = "EMAIL_RATE_WINDOW_SECONDS"
    EMAIL_RATE_LIMIT_USER = "EMAIL_RATE_LIMIT_USER"
    EMAIL_RATE_LIMIT_IP = "EMAIL_RATE_LIMIT_IP"
    AI_INSIGHT_RATE_WINDOW_SECONDS = "AI_INSIGHT_RATE_WINDOW_SECONDS"
    AI_INSIGHT_RATE_LIMIT_IP = "AI_INSIGHT_RATE_LIMIT_IP"
    BREACH_EMAIL_CACHE_TTL_SECONDS = "BREACH_EMAIL_CACHE_TTL_SECONDS"


TIER_FREE = "FREE"
TIER_PRO = "GO_PRO"
TIER_ULTRA = "GO_ULTRA"

PLAN_ALIASES = {
    "FREE": TIER_FREE,
    "GO FREE": TIER_FREE,
    "GO_FREE": TIER_FREE,
    "GOFREE": TIER_FREE,
    "PAID": TIER_PRO,
    "PRO": TIER_PRO,
    "GO PRO": TIER_PRO,
    "GO_PRO": TIER_PRO,
    "GOPRO": TIER_PRO,
    "PREMIUM": TIER_PRO,
    "ULTRA": TIER_ULTRA,
    "GO ULTRA": TIER_ULTRA,
    "GO_ULTRA": TIER_ULTRA,
    "GOULTRA": TIER_ULTRA,
    "ENTERPRISE": TIER_ULTRA,
}

# ── Per-plan feature gates ─────────────────────────────────────────────────

GO_PRO_FEATURES: set[Feature] = {
    Feature.EMAIL_BREACH_COUNT,
    Feature.EMAIL_BREACH_DETAILS,
    Feature.OCR_SCAN,
    Feature.AI_EXPLAIN,
    Feature.RISK_INSIGHTS,
    Feature.CYBER_CARD_ACCESS,
    Feature.QR_UNLIMITED,
    Feature.TRUSTED_CONTACT_LIMIT,
    Feature.PRIORITY_SOS,
}

GO_ULTRA_FEATURES: set[Feature] = GO_PRO_FEATURES | {
    Feature.FAMILY_ALERTS,
    Feature.ULTRA_PRIORITY_PIPELINE,
}

PLAN_FEATURES: dict[str, set[Feature]] = {
    TIER_FREE: {
        Feature.EMAIL_BREACH_COUNT,
        # FREE has 0 contacts; TRUSTED_CONTACT_LIMIT feature not granted
    },
    TIER_PRO: GO_PRO_FEATURES,
    TIER_ULTRA: GO_ULTRA_FEATURES,
}

# ── Per-plan limits ────────────────────────────────────────────────────────
# None = unlimited; 0 = explicitly blocked (enforced at feature layer)

PLAN_LIMITS: dict[str, dict[Limit, int | None]] = {
    TIER_FREE: {
        Limit.TRUSTED_CONTACT_MAX: 0,
        Limit.THREAT_DAILY: 1,
        Limit.EMAIL_MONTHLY: 1,        # window: weekly (see plan_limits.py)
        Limit.PASSWORD_MONTHLY: 1,     # window: weekly (see plan_limits.py)
        Limit.QR_WEEKLY: 1,
        Limit.AI_IMAGE_LIFETIME: 1,
        Limit.AI_EXPLAIN_DAILY: 0,     # blocked at Feature.AI_EXPLAIN gate
    },
    TIER_PRO: {
        Limit.TRUSTED_CONTACT_MAX: 3,
        Limit.THREAT_DAILY: None,
        Limit.EMAIL_MONTHLY: None,
        Limit.PASSWORD_MONTHLY: None,
        Limit.QR_WEEKLY: None,
        Limit.AI_IMAGE_LIFETIME: None,
        Limit.AI_EXPLAIN_DAILY: 20,
    },
    TIER_ULTRA: {
        Limit.TRUSTED_CONTACT_MAX: 6,
        Limit.THREAT_DAILY: None,
        Limit.EMAIL_MONTHLY: None,
        Limit.PASSWORD_MONTHLY: None,
        Limit.QR_WEEKLY: None,
        Limit.AI_IMAGE_LIFETIME: None,
        Limit.AI_EXPLAIN_DAILY: None,
    },
}

# ── Global (non-plan-scoped) limits ────────────────────────────────────────

GLOBAL_LIMITS: dict[Limit, int] = {
    Limit.EMAIL_MAX_LENGTH: 254,
    Limit.EMAIL_GLOBAL_COOLDOWN_SECONDS: 60,
    Limit.EMAIL_DUPLICATE_SCAN_BLOCK_SECONDS: 120,
    Limit.EMAIL_RATE_WINDOW_SECONDS: 60,
    Limit.EMAIL_RATE_LIMIT_USER: 8,
    Limit.EMAIL_RATE_LIMIT_IP: 20,
    Limit.AI_INSIGHT_RATE_WINDOW_SECONDS: 60,
    Limit.AI_INSIGHT_RATE_LIMIT_IP: 20,
    Limit.BREACH_EMAIL_CACHE_TTL_SECONDS: 300,
}


# ── Helper functions ────────────────────────────────────────────────────────

def normalize_plan(raw_plan: str | None) -> str:
    if not raw_plan:
        return TIER_FREE
    normalized = str(raw_plan).strip().upper()
    return PLAN_ALIASES.get(normalized, TIER_FREE)


def _feature_value(feature: Feature | str) -> Feature:
    if isinstance(feature, Feature):
        return feature
    return Feature(feature)


def has_feature(user: Any, feature: Feature | str) -> bool:
    plan = normalize_plan(getattr(user, "plan", None))
    required = _feature_value(feature)
    return required in PLAN_FEATURES.get(plan, set())


def get_plan_limit(user_or_plan: Any, limit: Limit | str) -> int | None:
    if isinstance(user_or_plan, str):
        plan = normalize_plan(user_or_plan)
    else:
        plan = normalize_plan(getattr(user_or_plan, "plan", None))
    resolved = Limit(limit) if isinstance(limit, str) else limit
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS[TIER_FREE])
    return limits.get(resolved)


def get_global_limit(limit: Limit | str) -> int:
    resolved = Limit(limit) if isinstance(limit, str) else limit
    return GLOBAL_LIMITS[resolved]


def get_feature_limit(user: Any, feature: Feature | str) -> int | None:
    resolved = _feature_value(feature)
    if resolved == Feature.TRUSTED_CONTACT_LIMIT:
        return get_plan_limit(user, Limit.TRUSTED_CONTACT_MAX)
    return None
