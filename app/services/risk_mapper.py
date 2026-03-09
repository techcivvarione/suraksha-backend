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
