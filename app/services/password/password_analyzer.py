from app.enums.scan_type import ScanType
from app.services.password import hibp_checker
from app.services.risk_mapper import map_breach_count_to_risk


def analyze_password(password: str) -> dict:
    count = hibp_checker.check_password_pwned(password)
    risk = map_breach_count_to_risk(count)
    reasons = (
        ["Password found in breach database {} times".format(count)]
        if count > 0
        else ["Password not found in known breach databases"]
    )
    recommendation = (
        "Change this password immediately."
        if risk["risk_level"] == "HIGH"
        else "Consider changing this password."
        if risk["risk_level"] == "MEDIUM"
        else "No breach found; keep following good hygiene."
    )

    return {
        "analysis_type": ScanType.PASSWORD.value,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "confidence": None,
        "reasons": reasons,
        "recommendation": recommendation,
    }
