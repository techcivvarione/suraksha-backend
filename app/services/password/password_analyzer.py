from app.enums.scan_type import ScanType
from app.services.password import hibp_checker
from app.services.risk_mapper import map_breach_count_to_risk, compute_breach_confidence


def analyze_password(password: str) -> dict:
    # hibp_checker returns 0 on both "not found" and network errors.
    # It logs and swallows exceptions internally, so any return value
    # means the function completed — treat it as a responded data source.
    count = max(0, hibp_checker.check_password_pwned(password))
    risk = map_breach_count_to_risk(count)

    # Confidence reflects the quality and authority of the HIBP data source.
    # breach_count > 0 → definitive evidence → 1.0
    # breach_count == 0 → no match found in HIBP (high coverage db) → 0.95
    confidence = compute_breach_confidence(count, data_is_fresh=True)

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
        "confidence": confidence,
        "reasons": reasons,
        "recommendation": recommendation,
    }
