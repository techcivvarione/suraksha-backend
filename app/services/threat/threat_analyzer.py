import re
import unicodedata
from urllib.parse import urlparse

from app.enums.scan_type import ScanType
from app.services.risk_mapper import map_probability_to_risk

SUSPICIOUS_KEYWORDS = [
    "otp",
    "bank",
    "refund",
    "verify account",
    "payment required",
    "kyc",
    "block your account",
    "click link",
]

SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "cutt.ly", "ow.ly"}


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = " ".join(text.split())
    return text


URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def analyze_threat(text: str) -> dict:
    normalized = _normalize(text)

    urls = URL_REGEX.findall(normalized)
    keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in normalized.lower()]

    probability = 0.1
    reasons = []

    if keywords:
        probability = max(probability, 0.5)
        reasons.append(f"Suspicious keywords detected: {', '.join(keywords[:3])}")

    for url in urls:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host.lower() in SHORTENERS:
            probability = max(probability, 0.6)
            reasons.append("Shortened link detected")
        if any(part in parsed.path.lower() for part in ["pay", "login", "verify", "bank"]):
            probability = max(probability, 0.6)
            reasons.append("Payment or credential path detected")

    if "payment" in normalized.lower():
        probability = max(probability, 0.6)
        reasons.append("Payment request detected")

    risk = map_probability_to_risk(probability)

    if not reasons:
        reasons = ["No strong threat indicators detected"]

    recommendation = (
        "Do not engage; likely phishing."
        if risk["risk_level"] == "HIGH"
        else "Verify sender independently before acting."
        if risk["risk_level"] == "MEDIUM"
        else "No major threats detected; stay cautious."
    )

    return {
        "analysis_type": ScanType.THREAT.value,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "confidence": round(probability, 2),
        "reasons": reasons,
        "recommendation": recommendation,
    }
