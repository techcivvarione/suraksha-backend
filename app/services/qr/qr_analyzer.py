import re
import unicodedata
from typing import List

from app.enums.scan_type import ScanType
from app.services.qr_classifier import classify_payload, QrType
from app.services.qr_validators import (
    validate_upi,
    validate_url,
    contains_zero_width,
    is_mixed_script,
)
from app.services.risk_mapper import map_probability_to_risk


def _normalize_payload(payload: str) -> str:
    normalized = unicodedata.normalize("NFKC", payload).strip()
    # strip control characters
    normalized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", normalized)
    return normalized


def analyze_qr(raw_payload: str) -> dict:
    payload = _normalize_payload(raw_payload)

    detected_type, meta = classify_payload(payload)
    reasons: List[str] = []
    probability = 0.1  # baseline low risk

    if detected_type == QrType.UPI:
        ok, upi_reasons = validate_upi(meta["uri"])
        reasons.extend(upi_reasons)
        probability = 0.3 if ok else 0.6
    elif detected_type == QrType.URL:
        ok, url_reasons, url_meta = validate_url(meta["url"])
        reasons.extend(url_reasons)
        if url_meta.get("is_shortener"):
            probability = max(probability, 0.5)
        if url_meta.get("homograph"):
            probability = max(probability, 0.7)
        if url_meta.get("domain_age_risk"):
            probability = max(probability, 0.6)
        if not ok:
            probability = max(probability, 0.6)
    else:
        txt = payload.lower()
        if contains_zero_width(payload) or is_mixed_script(payload):
            reasons.append("Obfuscated text detected")
            probability = max(probability, 0.5)
        if any(word in txt for word in ["refund", "support", "kyc", "bonus"]):
            probability = max(probability, 0.5)

    risk = map_probability_to_risk(probability)

    if not reasons:
        reasons = ["No strong risk indicators detected"]

    recommendation = (
        "Do not proceed; treat as malicious."
        if risk["risk_level"] == "HIGH"
        else "Verify sender before proceeding."
        if risk["risk_level"] == "MEDIUM"
        else "Proceed with caution."
    )

    return {
        "analysis_type": ScanType.QR.value,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "confidence": None,
        "reasons": reasons,
        "recommendation": recommendation,
        "detected_type": detected_type.value if hasattr(detected_type, "value") else str(detected_type),
        "original_payload": raw_payload,
    }
