# ── Legacy thresholds (300–999 range — used by old monthly batch job) ─────────
ELITE_SCORE       = 850
SAFE_SCORE        = 750
MEDIUM_RISK_SCORE = 650
HIGH_RISK_SCORE   = 500

# ── V2 thresholds (0–1000 real-time scoring) ──────────────────────────────────
V2_EXCELLENT      = 850
V2_MOSTLY_SAFE    = 700
V2_MODERATE_RISK  = 550
V2_HIGH_RISK      = 400


def get_risk_level(score: int) -> str:
    """Legacy human-readable label (used by monthly job and old client code)."""
    if score >= ELITE_SCORE:       return "Elite"
    if score >= SAFE_SCORE:        return "Safe"
    if score >= MEDIUM_RISK_SCORE: return "Medium Risk"
    if score >= HIGH_RISK_SCORE:   return "High Risk"
    return "Critical"


def get_risk_level_v2(score: int) -> str:
    """V2 machine-readable level (0–1000 real-time scoring)."""
    if score >= V2_EXCELLENT:     return "EXCELLENT"
    if score >= V2_MOSTLY_SAFE:   return "MOSTLY_SAFE"
    if score >= V2_MODERATE_RISK: return "MODERATE_RISK"
    if score >= V2_HIGH_RISK:     return "HIGH_RISK"
    return "CRITICAL"
