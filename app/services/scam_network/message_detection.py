from __future__ import annotations

from app.services.threat.threat_analyzer import analyze_threat


def analyze_message_text(message_text: str) -> dict:
    result = analyze_threat(message_text)
    score = int(result["risk_score"])
    risk_level = str(result.get("risk_level") or "").upper()

    if risk_level == "HIGH" or score >= 70:
        classification = "phishing_suspected"
    elif score >= 40:
        classification = "suspicious"
    else:
        classification = "unlikely_phishing"

    explanation = result.get("explanation") or result.get("summary") or "No strong phishing pattern detected"
    signals = result.get("signals") or result.get("reasons") or []

    return {
        "risk_score": score,
        "classification": classification,
        "reason": explanation,
        "matched_keywords": signals,
        "detected_type": result.get("detected_type"),
    }
