from urllib.parse import urlparse
from datetime import datetime, timezone
import whois
import requests

NEW_DOMAIN_DAYS_THRESHOLD = 90

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "buff.ly", "ow.ly", "cutt.ly"
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

        age_days = (datetime.now(timezone.utc) - creation_date).days
        return age_days

    except Exception:
        return None


def analyze_redirects(url: str):
    reasons = []
    score = 0

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

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


def analyze_url(url: str):
    reasons = []
    score = 0

    parsed = urlparse(url)

    # Invalid URL
    if not parsed.scheme or not parsed.netloc:
        reasons.append("Invalid or malformed URL")
        score += 50
        return {
            "score": score,
            "reasons": reasons
        }

    domain = parsed.netloc.lower()

    # HTTPS check
    if parsed.scheme != "https":
        reasons.append("URL is not using HTTPS")
        score += 20

    # Domain age check
    age_days = get_domain_age_days(domain)
    if age_days is not None and age_days < NEW_DOMAIN_DAYS_THRESHOLD:
        reasons.append(f"Domain registered {age_days} days ago (very new domain)")
        score += 30

    # Redirect & short URL check
    redirect_score, redirect_reasons = analyze_redirects(url)
    score += redirect_score
    reasons.extend(redirect_reasons)

    return {
        "score": score,
        "reasons": reasons
    }
