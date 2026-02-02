from urllib.parse import urlparse
from datetime import datetime, timezone
import whois

NEW_DOMAIN_DAYS_THRESHOLD = 90

def get_domain_age_days(domain: str):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # creation_date can be list or single value
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

    return {
        "score": score,
        "reasons": reasons
    }
