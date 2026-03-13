ELITE_SCORE = 850
SAFE_SCORE = 750
MEDIUM_RISK_SCORE = 650
HIGH_RISK_SCORE = 500


def get_risk_level(score: int) -> str:
    if score >= ELITE_SCORE:
        return "Elite"
    if score >= SAFE_SCORE:
        return "Safe"
    if score >= MEDIUM_RISK_SCORE:
        return "Medium Risk"
    if score >= HIGH_RISK_SCORE:
        return "High Risk"
    return "Critical"
