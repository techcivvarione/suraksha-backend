from urllib.parse import urlparse
from datetime import datetime, timezone
import whois
import requests
import re

NEW_DOMAIN_DAYS_THRESHOLD = 90

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "buff.ly", "ow.ly", "cutt.ly"
}

BRAND_DOMAINS = {
    "sbi": ["sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "google": ["google.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["google.com"]
}

SCAM_KEYWORDS = {
    "urgency": [
        "urgent", "immediately", "act now", "within 24 hours",
        "final warning", "account will be blocked"
    ],
    "authority": [
        "rbi", "income tax", "bank team", "kyc update",
        "customs", "police", "legal action"
    ],
    "reward": [
        "refund", "cashback", "won", "prize", "lottery",
        "gift", "free"
    ],
    "threat": [
        "blocked", "suspended", "terminated",
        "penalty", "fine", "arrest"
    ]
}


def get_domain_age_days(domain: str):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        return (datetime.now(timezone.utc) - creation_date).days

    except Exception:
        return None


def analyze_redirects(url: str):
    reasons = []
    score = 0

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        redirect_count = len(response.history)

        if redirect_count >= 3:
            reasons.append(f"URL redirects {redirect_count} times")
            score += 20

        parsed = urlparse(url)
        if parsed.netloc.lower() in SHORTENER_DOMAINS:
            reasons.append("URL uses a known shortener service")
            score += 30

    except Exception:
        reasons.append("Could not safely resolve redirects")
        score += 10

    return score, reasons


def analyze_text_message(text: str):
    reasons = []
    score = 0
    text_lower = text.lower()

    for category, keywords in SCAM_KEYWORDS.items():
        for word in keywords:
            if re.search(rf"\b{re.escape(word)}\b", text_lower):
                reasons.append(f"Scam keyword detected: '{word}'")
                score += 15

    return {"score": score, "reasons": reasons}


def analyze_brand_spoofing(text: str, domain: str | None):
    reasons = []
    score = 0
    text_lower = text.lower()

    for brand, valid_domains in BRAND_DOMAINS.items():
        if brand in text_lower:
            if domain:
                if not any(domain.endswith(d) for d in valid_domains):
                    reasons.append(f"Brand impersonation detected: {brand}")
                    score += 40
            else:
                reasons.append(f"Brand mentioned without official link: {brand}")
                score += 20

    return score, reasons


def analyze_url(url: str):
    reasons = []
    score = 0

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return {
            "score": 50,
            "reasons": ["Invalid or malformed URL"]
        }

    domain = parsed.netloc.lower()

    if parsed.scheme != "https":
        reasons.append("URL is not using HTTPS")
        score += 20

    age_days = get_domain_age_days(domain)
    if age_days is not None and age_days < NEW_DOMAIN_DAYS_THRESHOLD:
        reasons.append(f"Domain registered {age_days} days ago (very new domain)")
        score += 30

    # Redirect & short URL check
    redirect_score, redirect_reasons = analyze_redirects(url)
    score += redirect_score
    reasons.extend(redirect_reasons)

    return {"score": score, "reasons": reasons}
