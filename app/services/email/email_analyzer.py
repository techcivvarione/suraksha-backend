import hashlib
import unicodedata
from typing import Optional

from redis.exceptions import RedisError

from app.enums.scan_type import ScanType
from app.services.risk_mapper import map_breach_count_to_risk
from app.services.redis_store import get_json, set_json, build_hashed_key
from app.services.email.providers.hibp_provider import HIBPProvider

CACHE_TTL = 24 * 3600  # seconds


def _normalize_email(email: str) -> str:
    return unicodedata.normalize("NFKC", email.strip().lower())


def _cache_key(email: str) -> str:
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return build_hashed_key("email_breach", digest)


def analyze_email(email: str, user_plan: str = "GO_FREE") -> dict:
    normalized = _normalize_email(email)
    cache_key = _cache_key(normalized)

    cached = get_json("email_breach", cache_key)
    if cached:
        breach_count = cached.get("breach_count", 0)
        latest_year = cached.get("latest_year")
    else:
        provider = HIBPProvider(user_plan=user_plan)
        res = provider.lookup(normalized)
        breach_count = res.get("breach_count", 0)
        latest_year = res.get("latest_year")
        try:
            set_json("email_breach", {"breach_count": breach_count, "latest_year": latest_year}, CACHE_TTL, cache_key)
        except RedisError:
            pass

    risk = map_breach_count_to_risk(breach_count)
    reasons = (
        [f"Email exposed in {breach_count} known data breaches"]
        if breach_count > 0
        else ["No known data breaches for this email"]
    )
    if latest_year:
        reasons.append(f"Latest exposure detected in {latest_year}")

    recommendation = (
        "Reset passwords and enable MFA on all accounts using this email."
        if risk["risk_level"] == "HIGH"
        else "Consider rotating passwords and reviewing account security."
        if risk["risk_level"] == "MEDIUM"
        else "No breaches detected; continue safe practices."
    )

    return {
        "analysis_type": ScanType.EMAIL.value,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "confidence": None,
        "reasons": reasons,
        "recommendation": recommendation,
    }
