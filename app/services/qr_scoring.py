from typing import List, Tuple


# SECURE QR START
def score_risk(
    reported_count: int,
    homograph: bool,
    suspicious_keyword: bool,
    shortener: bool,
    domain_age_risk: bool,
    upi_impersonation: bool,
    blacklist_hit: bool,
) -> Tuple[int, str]:
    """
    Deterministic weighted scoring.
    """
    score = 0
    score += min(reported_count * 10, 40)
    if homograph:
        score += 20
    if suspicious_keyword:
        score += 10
    if shortener:
        score += 10
    if domain_age_risk:
        score += 10
    if upi_impersonation:
        score += 15
    if blacklist_hit:
        score += 25

    score = max(0, min(score, 100))

    if score >= 70:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level
# SECURE QR END
