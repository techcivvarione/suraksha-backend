from __future__ import annotations

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
    THREAT_DAILY = "THREAT_DAILY"
    EMAIL_MONTHLY = "EMAIL_MONTHLY"
    PASSWORD_MONTHLY = "PASSWORD_MONTHLY"
    QR_WEEKLY = "QR_WEEKLY"
    AI_IMAGE_LIFETIME = "AI_IMAGE_LIFETIME"
    ANALYZE_DAILY_THREAT = "ANALYZE_DAILY_THREAT"
    ANALYZE_DAILY_EMAIL = "ANALYZE_DAILY_EMAIL"
    ANALYZE_DAILY_PASSWORD = "ANALYZE_DAILY_PASSWORD"
    QR_WEEKLY_SCAN = "QR_WEEKLY_SCAN"
    QR_WEEKLY_REPORT = "QR_WEEKLY_REPORT"
    EMAIL_MAX_LENGTH = "EMAIL_MAX_LENGTH"
    EMAIL_GLOBAL_COOLDOWN_SECONDS = "EMAIL_GLOBAL_COOLDOWN_SECONDS"
    EMAIL_DUPLICATE_SCAN_BLOCK_SECONDS = "EMAIL_DUPLICATE_SCAN_BLOCK_SECONDS"
    EMAIL_RATE_WINDOW_SECONDS = "EMAIL_RATE_WINDOW_SECONDS"
    EMAIL_RATE_LIMIT_USER = "EMAIL_RATE_LIMIT_USER"
    EMAIL_RATE_LIMIT_IP = "EMAIL_RATE_LIMIT_IP"
    AI_INSIGHT_RATE_WINDOW_SECONDS = "AI_INSIGHT_RATE_WINDOW_SECONDS"
    AI_INSIGHT_RATE_LIMIT_IP = "AI_INSIGHT_RATE_LIMIT_IP"
    BREACH_EMAIL_CACHE_TTL_SECONDS = "BREACH_EMAIL_CACHE_TTL_SECONDS"


TIER_FREE = "GO_FREE"
TIER_PRO = "GO_PRO"
TIER_ULTRA = "GO_ULTRA"
PLAN_FAMILY_BASIC = "FAMILY_BASIC"
PLAN_FAMILY_PRO = "FAMILY_PRO"


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
    PLAN_FAMILY_BASIC: PLAN_FAMILY_BASIC,
    PLAN_FAMILY_PRO: PLAN_FAMILY_PRO,
}


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
    Feature.ULTRA_PRIORITY_PIPELINE,
}


PLAN_FEATURES: dict[str, set[Feature]] = {
    TIER_FREE: {
        Feature.EMAIL_BREACH_COUNT,
        Feature.TRUSTED_CONTACT_LIMIT,
    },
    TIER_PRO: GO_PRO_FEATURES,
    TIER_ULTRA: GO_ULTRA_FEATURES,
    PLAN_FAMILY_BASIC: {
        Feature.EMAIL_BREACH_COUNT,
        Feature.TRUSTED_CONTACT_LIMIT,
        Feature.FAMILY_ALERTS,
    },
    PLAN_FAMILY_PRO: {
        Feature.EMAIL_BREACH_COUNT,
        Feature.TRUSTED_CONTACT_LIMIT,
        Feature.FAMILY_ALERTS,
    },
}


PLAN_LIMITS: dict[str, dict[Limit, int | None]] = {
    TIER_FREE: {
        Limit.TRUSTED_CONTACT_MAX: 1,
        Limit.THREAT_DAILY: 3,
        Limit.EMAIL_MONTHLY: 3,
        Limit.PASSWORD_MONTHLY: 3,
        Limit.QR_WEEKLY: 3,
        Limit.AI_IMAGE_LIFETIME: 1,
        Limit.ANALYZE_DAILY_THREAT: 3,
        Limit.ANALYZE_DAILY_EMAIL: 3,
        Limit.ANALYZE_DAILY_PASSWORD: 3,
        Limit.QR_WEEKLY_SCAN: 3,
        Limit.QR_WEEKLY_REPORT: 3,
    },
    TIER_PRO: {
        Limit.TRUSTED_CONTACT_MAX: 1,
        Limit.THREAT_DAILY: None,
        Limit.EMAIL_MONTHLY: None,
        Limit.PASSWORD_MONTHLY: None,
        Limit.QR_WEEKLY: None,
        Limit.AI_IMAGE_LIFETIME: None,
        Limit.ANALYZE_DAILY_THREAT: 100,
        Limit.ANALYZE_DAILY_EMAIL: 20,
        Limit.ANALYZE_DAILY_PASSWORD: 20,
        Limit.QR_WEEKLY_SCAN: None,
        Limit.QR_WEEKLY_REPORT: None,
    },
    TIER_ULTRA: {
        Limit.TRUSTED_CONTACT_MAX: 1,
        Limit.THREAT_DAILY: None,
        Limit.EMAIL_MONTHLY: None,
        Limit.PASSWORD_MONTHLY: None,
        Limit.QR_WEEKLY: None,
        Limit.AI_IMAGE_LIFETIME: None,
        Limit.ANALYZE_DAILY_THREAT: 100,
        Limit.ANALYZE_DAILY_EMAIL: 20,
        Limit.ANALYZE_DAILY_PASSWORD: 20,
        Limit.QR_WEEKLY_SCAN: None,
        Limit.QR_WEEKLY_REPORT: None,
    },
    PLAN_FAMILY_BASIC: {
        Limit.TRUSTED_CONTACT_MAX: 3,
        Limit.THREAT_DAILY: 3,
        Limit.EMAIL_MONTHLY: 3,
        Limit.PASSWORD_MONTHLY: 3,
        Limit.QR_WEEKLY: 3,
        Limit.AI_IMAGE_LIFETIME: 1,
        Limit.ANALYZE_DAILY_THREAT: 10,
        Limit.ANALYZE_DAILY_EMAIL: 3,
        Limit.ANALYZE_DAILY_PASSWORD: 3,
        Limit.QR_WEEKLY_SCAN: 3,
        Limit.QR_WEEKLY_REPORT: 3,
    },
    PLAN_FAMILY_PRO: {
        Limit.TRUSTED_CONTACT_MAX: 6,
        Limit.THREAT_DAILY: 3,
        Limit.EMAIL_MONTHLY: 3,
        Limit.PASSWORD_MONTHLY: 3,
        Limit.QR_WEEKLY: 3,
        Limit.AI_IMAGE_LIFETIME: 1,
        Limit.ANALYZE_DAILY_THREAT: 10,
        Limit.ANALYZE_DAILY_EMAIL: 3,
        Limit.ANALYZE_DAILY_PASSWORD: 3,
        Limit.QR_WEEKLY_SCAN: 3,
        Limit.QR_WEEKLY_REPORT: 3,
    },
}


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


def get_analyze_daily_limit(user: Any, scan_type: str) -> int | None:
    scan = scan_type.upper()
    mapping = {
        "THREAT": Limit.ANALYZE_DAILY_THREAT,
        "EMAIL": Limit.ANALYZE_DAILY_EMAIL,
        "PASSWORD": Limit.ANALYZE_DAILY_PASSWORD,
    }
    selected = mapping.get(scan)
    if not selected:
        return None
    return get_plan_limit(user, selected)
