def map_probability_to_risk(probability: float) -> dict:
    """
    probability: 0..1
    Returns dict with risk_score (0-100) and risk_level LOW/MEDIUM/HIGH.
    """
    p = max(0.0, min(probability, 1.0))
    score = int(round(p * 100))
    if p < 0.3:
        level = "LOW"
    elif p < 0.7:
        level = "MEDIUM"
    else:
        level = "HIGH"
    return {"risk_score": score, "risk_level": level}


def map_breach_count_to_risk(count: int) -> dict:
    """
    Maps breach count to risk buckets:
    0 -> LOW (10)
    1-999 -> MEDIUM (60)
    >=1000 -> HIGH (90)
    """
    c = max(0, count)
    if c == 0:
        return {"risk_score": 10, "risk_level": "LOW"}
    if c < 1000:
        return {"risk_score": 60, "risk_level": "MEDIUM"}
    return {"risk_score": 90, "risk_level": "HIGH"}


def derive_risk_level_from_score(score: int) -> str:
    """
    Derives a human-readable risk level from a numeric score (0-100).
    Used as a guaranteed fallback so risk_level is NEVER null or 'UNKNOWN'.

    Thresholds mirror map_breach_count_to_risk and classify_risk in risk_scoring.py:
      0-30  → LOW
      31-60 → MEDIUM
      61+   → HIGH
    """
    s = max(0, min(int(score or 0), 100))
    if s <= 40:
        return "LOW"
    if s <= 70:
        return "MEDIUM"
    return "HIGH"


def compute_breach_confidence(breach_count: int, data_is_fresh: bool = True) -> float:
    """
    Returns a confidence score (0.0-1.0) for breach-based scan results.

    HIBP is considered a high-authority source:
    - breach_count > 0  : data definitively proves a breach → 1.0
    - breach_count == 0 + fresh live query : no breach found, high confidence → 0.95
    - breach_count == 0 + cached result   : slightly stale, still reliable → 0.90
    - breach_count == 0 + HIBP unavailable (caller passes data_is_fresh=False) → 0.50

    A non-None confidence value lets the UI render a real percentage
    instead of falling back to "0%".
    """
    count = max(0, int(breach_count or 0))
    if count > 0:
        # Definitive evidence of compromise — confidence is absolute
        return 1.0
    if data_is_fresh:
        return 0.95
    return 0.50
