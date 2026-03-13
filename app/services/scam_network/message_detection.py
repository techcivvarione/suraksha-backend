from __future__ import annotations

KEYWORD_WEIGHTS = {
    'otp': 20,
    'kyc': 18,
    'account blocked': 18,
    'verify immediately': 16,
    'bank update': 14,
    'click link': 14,
    'urgent': 8,
    'suspend': 10,
}


def analyze_message_text(message_text: str) -> dict:
    text = (message_text or '').strip().lower()
    score = 0
    matched: list[str] = []
    for keyword, weight in KEYWORD_WEIGHTS.items():
        if keyword in text:
            score += weight
            matched.append(keyword)
    if 'http://' in text or 'https://' in text or 'www.' in text:
        score += 12
        matched.append('suspicious_link')
    score = max(0, min(100, score))
    if score >= 70:
        classification = 'phishing_suspected'
        reason = 'Bank impersonation pattern detected' if any(k in matched for k in ('otp', 'kyc', 'bank update')) else 'Suspicious urgency and link pattern detected'
    elif score >= 40:
        classification = 'suspicious'
        reason = 'Suspicious message patterns detected'
    else:
        classification = 'unlikely_phishing'
        reason = 'No strong phishing pattern detected'
    return {
        'risk_score': score,
        'classification': classification,
        'reason': reason,
        'matched_keywords': matched,
    }
